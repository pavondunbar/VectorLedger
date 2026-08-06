"""
VectorLedger Python client.

Connects to a running ``vledger start`` server over TLS 1.3 and speaks the
newline-delimited JSON wire protocol.

Usage
-----
>>> from vledger_client import VledgerClient
>>> with VledgerClient.connect("127.0.0.1", 5433) as db:
...     result = db.query("SELECT * FROM accounts")
...     for row in result.rows:
...         print(row)
...     db.execute("INSERT INTO accounts (code, name, account_type, currency, domain) "
...                "VALUES ('CASH', 'Cash', 'asset', 'USD', 'prod')")
"""

from __future__ import annotations

import json
import socket
import ssl
import threading
from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class Row:
    """A single result row returned by a query."""
    columns: list[str]
    values: list[Any]

    def __getitem__(self, column: str) -> Any:
        idx = self.columns.index(column)
        return self.values[idx]

    def get(self, column: str, default: Any = None) -> Any:
        try:
            return self[column]
        except (ValueError, IndexError):
            return default

    def as_dict(self) -> dict[str, Any]:
        return dict(zip(self.columns, self.values))

    def __repr__(self) -> str:
        return f"Row({self.as_dict()})"


@dataclass
class MerkleProof:
    """Cryptographic Merkle proof attached to a SELECT result."""
    root_hex: str
    leaf_count: int
    verified: bool


@dataclass
class QueryResult:
    """The complete result of a SQL query."""
    columns: list[str]
    rows: list[Row]
    rows_affected: int
    message: str
    proof: Optional[MerkleProof] = None

    @classmethod
    def _from_response(cls, resp: dict) -> "QueryResult":
        columns: list[str] = resp.get("columns", [])
        raw_rows: list[list[Any]] = resp.get("rows", [])
        rows = [Row(columns=columns, values=r) for r in raw_rows]

        proof = None
        if p := resp.get("proof"):
            proof = MerkleProof(
                root_hex=p.get("root_hex", ""),
                leaf_count=p.get("leaf_count", 0),
                verified=p.get("verified", False),
            )

        return cls(
            columns=columns,
            rows=rows,
            rows_affected=resp.get("rows_affected", len(rows)),
            message=resp.get("message", ""),
            proof=proof,
        )


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class VledgerError(Exception):
    """Raised when the server returns an error response."""

    def __init__(self, message: str, sql: str = ""):
        super().__init__(message)
        self.sql = sql


class VledgerConnectionError(VledgerError):
    """Raised when the client cannot connect to the server."""


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class VledgerClient:
    """
    Thread-safe VectorGuard DB client.

    Parameters
    ----------
    host : str
        Hostname or IP address of the vledger server.
    port : int
        TCP port (default 5433 for the native JSON protocol).
    with_proofs : bool
        When ``True``, every SELECT response includes a Merkle proof.
    tls : bool
        When ``True`` (default), connect with TLS 1.3.
    tls_ca_cert : str | None
        Path to a PEM CA certificate to verify the server certificate.
        ``None`` disables certificate verification (development only).
    timeout : float
        Socket timeout in seconds (default 30).
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 5433,
        *,
        with_proofs: bool = False,
        tls: bool = True,
        tls_ca_cert: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self._host = host
        self._port = port
        self._with_proofs = with_proofs
        self._tls = tls
        self._tls_ca_cert = tls_ca_cert
        self._timeout = timeout
        self._lock = threading.Lock()
        self._sock: Optional[ssl.SSLSocket | socket.socket] = None
        self._buf = b""

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "VledgerClient":
        self.connect()
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    @classmethod
    def connect(
        cls,
        host: str = "127.0.0.1",
        port: int = 5433,
        **kwargs: Any,
    ) -> "VledgerClient":
        """Create a client and open the connection."""
        c = cls(host, port, **kwargs)
        c._connect()
        return c

    def _connect(self) -> None:
        raw = socket.create_connection((self._host, self._port), timeout=self._timeout)
        if self._tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            if self._tls_ca_cert:
                ctx.load_verify_locations(self._tls_ca_cert)
            else:
                # Development: accept self-signed certs from vgdb.
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            self._sock = ctx.wrap_socket(raw, server_hostname=self._host)
        else:
            self._sock = raw
        self._buf = b""

    def close(self) -> None:
        """Close the connection."""
        with self._lock:
            if self._sock:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None

    def reconnect(self) -> None:
        """Close and re-open the connection."""
        self.close()
        self._connect()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def query(self, sql: str, *, with_proof: Optional[bool] = None) -> QueryResult:
        """
        Execute *sql* and return all rows.

        Parameters
        ----------
        sql : str
            Any SQL statement supported by vgdb.
        with_proof : bool | None
            Override the client-level ``with_proofs`` setting for this call.
        """
        return self._send(sql, with_proof=with_proof if with_proof is not None else self._with_proofs)

    def execute(self, sql: str) -> int:
        """
        Execute *sql* and return the number of rows affected.

        Convenience wrapper for INSERT / UPDATE statements.
        """
        result = self._send(sql, with_proof=False)
        return result.rows_affected

    def balance(self, account: str) -> int:
        """Return the current balance for *account* (code or UUID)."""
        result = self.query(f"SELECT BALANCE('{account}')")
        if not result.rows:
            raise VledgerError(f"No balance returned for account '{account}'")
        val = result.rows[0].get("balance")
        return int(val) if val is not None else 0

    def verify_chain(self) -> bool:
        """
        Verify the database hash-chain integrity.

        Returns ``True`` if the chain is intact, raises ``VledgerError`` otherwise.
        """
        result = self.query("SELECT VERIFY_CHAIN()")
        if not result.rows:
            raise VledgerError("No response from VERIFY_CHAIN()")
        status = result.rows[0].get("status", "")
        if status != "OK":
            raise VledgerError(f"Chain integrity failure: {status}")
        return True

    # ------------------------------------------------------------------
    # Internal send/receive
    # ------------------------------------------------------------------

    def _send(self, sql: str, *, with_proof: bool) -> QueryResult:
        request = json.dumps({"sql": sql, "with_proof": with_proof}) + "\n"
        with self._lock:
            if self._sock is None:
                raise VledgerConnectionError("Not connected — call connect() first")
            try:
                self._sock.sendall(request.encode("utf-8"))
                response_line = self._read_line()
            except (OSError, ssl.SSLError) as exc:
                self._sock = None
                raise VledgerConnectionError(f"Connection lost: {exc}") from exc

        resp = json.loads(response_line)
        if not resp.get("ok", False):
            raise VledgerError(resp.get("error", "unknown error"), sql=sql)
        return QueryResult._from_response(resp)

    def _read_line(self) -> str:
        """Read bytes until a newline, handling partial reads."""
        assert self._sock is not None
        while b"\n" not in self._buf:
            chunk = self._sock.recv(65536)
            if not chunk:
                raise VledgerConnectionError("Server closed the connection")
            self._buf += chunk
        line, self._buf = self._buf.split(b"\n", 1)
        return line.decode("utf-8")
