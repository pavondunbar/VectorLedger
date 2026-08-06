"""
Unit tests for the VectorLedger Python client.

These tests mock the socket layer so no running server is required.
"""

import json
import socket
import threading
import unittest
from unittest.mock import MagicMock

from vledger_client import VledgerClient, VledgerError, QueryResult, Row


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ok_response(**kwargs) -> bytes:
    """Build a minimal OK response line."""
    base = {"ok": True, "columns": [], "rows": [], "rows_affected": 0, "message": "OK"}
    base.update(kwargs)
    return (json.dumps(base) + "\n").encode()


def _err_response(msg: str) -> bytes:
    return (json.dumps({"ok": False, "error": msg}) + "\n").encode()


def _mock_client(recv_data: bytes) -> VledgerClient:
    """Return a VledgerClient with a mocked socket."""
    client = VledgerClient(tls=False)
    mock_sock = MagicMock(spec=socket.socket)
    mock_sock.recv.side_effect = [recv_data, b""]
    client._sock = mock_sock
    client._buf = b""
    return client


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestQueryResult(unittest.TestCase):
    def test_from_response_basic(self):
        resp = {
            "ok": True,
            "columns": ["id", "balance"],
            "rows": [["abc123", 50000]],
            "rows_affected": 1,
            "message": "1 rows",
        }
        qr = QueryResult._from_response(resp)
        self.assertEqual(len(qr.rows), 1)
        self.assertEqual(qr.rows[0]["balance"], 50000)
        self.assertIsNone(qr.proof)

    def test_from_response_with_proof(self):
        resp = {
            "ok": True,
            "columns": ["sequence"],
            "rows": [[1]],
            "rows_affected": 1,
            "message": "ok",
            "proof": {"root_hex": "deadbeef", "leaf_count": 1, "verified": True},
        }
        qr = QueryResult._from_response(resp)
        self.assertIsNotNone(qr.proof)
        self.assertEqual(qr.proof.root_hex, "deadbeef")
        self.assertTrue(qr.proof.verified)


class TestRow(unittest.TestCase):
    def test_getitem(self):
        row = Row(columns=["a", "b"], values=[1, 2])
        self.assertEqual(row["a"], 1)
        self.assertEqual(row["b"], 2)

    def test_as_dict(self):
        row = Row(columns=["x"], values=["hello"])
        self.assertEqual(row.as_dict(), {"x": "hello"})

    def test_get_missing(self):
        row = Row(columns=[], values=[])
        self.assertIsNone(row.get("missing"))
        self.assertEqual(row.get("missing", 42), 42)


class TestVledgerClient(unittest.TestCase):
    def test_query_ok(self):
        data = _ok_response(
            columns=["balance"],
            rows=[[99000]],
            rows_affected=1,
            message="balance = 99000",
        )
        client = _mock_client(data)
        result = client.query("SELECT BALANCE('CASH')")
        self.assertEqual(len(result.rows), 1)
        self.assertEqual(result.rows[0]["balance"], 99000)

    def test_execute_returns_rows_affected(self):
        data = _ok_response(rows_affected=1, message="1 entry posted")
        client = _mock_client(data)
        n = client.execute("INSERT INTO ledger (...) VALUES (...)")
        self.assertEqual(n, 1)

    def test_error_response_raises(self):
        data = _err_response("account 'NOPE' not found")
        client = _mock_client(data)
        with self.assertRaises(VledgerError) as ctx:
            client.query("SELECT BALANCE('NOPE')")
        self.assertIn("not found", str(ctx.exception))

    def test_balance_helper(self):
        data = _ok_response(
            columns=["account", "balance"],
            rows=[["CASH", 12345]],
            rows_affected=1,
        )
        client = _mock_client(data)
        bal = client.balance("CASH")
        self.assertEqual(bal, 12345)

    def test_verify_chain_ok(self):
        data = _ok_response(
            columns=["status", "entries_verified", "chain_tip"],
            rows=[["OK", 10, "abcdef"]],
            rows_affected=1,
        )
        client = _mock_client(data)
        self.assertTrue(client.verify_chain())

    def test_verify_chain_failure(self):
        data = _ok_response(
            columns=["status"],
            rows=[["BROKEN: hash mismatch at sequence 3"]],
            rows_affected=1,
        )
        client = _mock_client(data)
        with self.assertRaises(VledgerError):
            client.verify_chain()


if __name__ == "__main__":
    unittest.main()
