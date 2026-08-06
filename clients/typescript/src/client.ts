/**
 * VectorLedger TypeScript/Node.js client.
 *
 * Connects to a running ``vledger start`` server over TLS 1.3 and speaks the
 * newline-delimited JSON wire protocol.
 *
 * @example
 * ```ts
 * import { VledgerClient } from "vledger-client";
 *
 * const db = await VledgerClient.connect({ host: "127.0.0.1", port: 5433 });
 * try {
 *   const result = await db.query("SELECT * FROM accounts");
 *   for (const row of result.rows) {
 *     console.log(row.toObject());
 *   }
 *   await db.execute(
 *     "INSERT INTO accounts (code, name, account_type, currency, domain) " +
 *     "VALUES ('CASH', 'Cash', 'asset', 'USD', 'prod')"
 *   );
 * } finally {
 *   db.close();
 * }
 * ```
 */

import * as net  from "net";
import * as tls  from "tls";
import {
  MerkleProof,
  QueryResult,
  Row,
  VledgerConnectionError,
  VledgerError,
  VledgerRawResponse,
  VledgerRequest,
} from "./types";

// ── Connection options ────────────────────────────────────────────────────────

export interface VledgerClientOptions {
  /** Hostname or IP address (default: "127.0.0.1"). */
  host?:        string;
  /** TCP port (default: 5433). */
  port?:        number;
  /** Attach Merkle proof to every SELECT (default: false). */
  withProofs?:  boolean;
  /** Use TLS (default: true). */
  tls?:         boolean;
  /** Path to a PEM CA certificate for server verification. */
  tlsCaCert?:   string;
  /**
   * When true, skip server certificate verification.
   * Use only in development/test environments.
   */
  rejectUnauthorized?: boolean;
  /** Socket timeout in milliseconds (default: 30_000). */
  timeout?:     number;
}

// ── VledgerClient ────────────────────────────────────────────────────────────────

export class VledgerClient {
  private socket:     tls.TLSSocket | net.Socket | null = null;
  private buf:        Buffer = Buffer.alloc(0);
  private readonly pending: Array<{
    resolve: (line: string) => void;
    reject:  (err: Error)   => void;
  }> = [];

  private constructor(private readonly opts: Required<VledgerClientOptions>) {}

  // ── Factory ────────────────────────────────────────────────────────────────

  /** Open a connection and return a ready client. */
  static connect(opts: VledgerClientOptions = {}): Promise<VledgerClient> {
    const resolved: Required<VledgerClientOptions> = {
      host:               opts.host               ?? "127.0.0.1",
      port:               opts.port               ?? 5433,
      withProofs:         opts.withProofs          ?? false,
      tls:                opts.tls                 ?? true,
      tlsCaCert:          opts.tlsCaCert           ?? "",
      rejectUnauthorized: opts.rejectUnauthorized  ?? false,
      timeout:            opts.timeout             ?? 30_000,
    };
    const client = new VledgerClient(resolved);
    return client._connect();
  }

  // ── Lifecycle ──────────────────────────────────────────────────────────────

  private _connect(): Promise<VledgerClient> {
    return new Promise((resolve, reject) => {
      const onError = (err: Error): void => {
        reject(new VledgerConnectionError(`Connection failed: ${err.message}`));
      };

      const onConnect = (): void => {
        this.socket!.removeListener("error", onError);
        this._setupDataHandler();
        resolve(this);
      };

      if (this.opts.tls) {
        const tlsOpts: tls.ConnectionOptions = {
          host:               this.opts.host,
          port:               this.opts.port,
          rejectUnauthorized: this.opts.rejectUnauthorized,
        };
        if (this.opts.tlsCaCert) {
          // eslint-disable-next-line @typescript-eslint/no-require-imports
          const fs = require("fs") as typeof import("fs");
          tlsOpts.ca = fs.readFileSync(this.opts.tlsCaCert);
        }
        const sock = tls.connect(tlsOpts, onConnect);
        sock.setTimeout(this.opts.timeout);
        sock.once("error", onError);
        this.socket = sock;
      } else {
        const sock = net.createConnection(
          { host: this.opts.host, port: this.opts.port },
          onConnect,
        );
        sock.setTimeout(this.opts.timeout);
        sock.once("error", onError);
        this.socket = sock;
      }
    });
  }

  private _setupDataHandler(): void {
    this.socket!.on("data", (chunk: Buffer) => {
      this.buf = Buffer.concat([this.buf, chunk]);
      this._drainLines();
    });

    this.socket!.on("error", (err: Error) => {
      const p = this.pending.shift();
      p?.reject(new VledgerConnectionError(err.message));
    });

    this.socket!.on("close", () => {
      while (this.pending.length) {
        this.pending.shift()!.reject(
          new VledgerConnectionError("Connection closed by server"),
        );
      }
    });
  }

  private _drainLines(): void {
    const newline = this.buf.indexOf(0x0a); // '\n'
    if (newline === -1) return;
    const line = this.buf.slice(0, newline).toString("utf8");
    this.buf   = this.buf.slice(newline + 1);
    const p    = this.pending.shift();
    if (p) p.resolve(line);
    // Keep draining if more complete lines are buffered
    if (this.buf.indexOf(0x0a) !== -1) this._drainLines();
  }

  /** Close the connection. */
  close(): void {
    this.socket?.destroy();
    this.socket = null;
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * Execute *sql* and return the full result set.
   */
  async query(sql: string, opts: { withProof?: boolean } = {}): Promise<QueryResult> {
    const withProof = opts.withProof ?? this.opts.withProofs;
    return this._send(sql, withProof);
  }

  /**
   * Execute *sql* and return the number of rows affected.
   * Convenience wrapper for INSERT / UPDATE statements.
   */
  async execute(sql: string): Promise<number> {
    const result = await this._send(sql, false);
    return result.rowsAffected;
  }

  /** Return the current balance for *account* (code or UUID). */
  async balance(account: string): Promise<number> {
    const result = await this.query(`SELECT BALANCE('${account}')`);
    if (!result.rows.length) {
      throw new VledgerError(`No balance returned for account '${account}'`);
    }
    return Number(result.rows[0].get("balance"));
  }

  /**
   * Verify the database hash-chain integrity.
   * Resolves `true` on success, throws `VledgerError` on failure.
   */
  async verifyChain(): Promise<boolean> {
    const result = await this.query("SELECT VERIFY_CHAIN()");
    if (!result.rows.length) throw new VledgerError("No response from VERIFY_CHAIN()");
    const status = result.rows[0].getOrDefault("status", "") as string;
    if (status !== "OK") throw new VledgerError(`Chain integrity failure: ${status}`);
    return true;
  }

  // ── Internal ───────────────────────────────────────────────────────────────

  private _send(sql: string, withProof: boolean): Promise<QueryResult> {
    return new Promise((resolve, reject) => {
      if (!this.socket) {
        reject(new VledgerConnectionError("Not connected"));
        return;
      }

      // Register the response handler BEFORE sending so we don't miss it.
      this.pending.push({
        resolve: (line) => {
          try {
            const raw = JSON.parse(line) as VledgerRawResponse;
            if (!raw.ok) {
              reject(new VledgerError(raw.error ?? "unknown error", sql));
            } else {
              resolve(VledgerClient._parseResult(raw));
            }
          } catch (e) {
            reject(new VledgerError(`Failed to parse server response: ${e}`));
          }
        },
        reject,
      });

      const req: VledgerRequest = { sql, with_proof: withProof };
      const wire = JSON.stringify(req) + "\n";
      this.socket.write(wire, "utf8", (err) => {
        if (err) {
          this.pending.pop();
          reject(new VledgerConnectionError(`Send failed: ${err.message}`));
        }
      });
    });
  }

  private static _parseResult(raw: VledgerRawResponse): QueryResult {
    const columns = raw.columns ?? [];
    const rows    = (raw.rows ?? []).map((r) => new Row(columns, r));

    let proof: MerkleProof | null = null;
    if (raw.proof) {
      proof = {
        rootHex:   raw.proof.root_hex,
        leafCount: raw.proof.leaf_count,
        verified:  raw.proof.verified,
      };
    }

    return {
      columns,
      rows,
      rowsAffected: raw.rows_affected ?? rows.length,
      message:      raw.message ?? "",
      proof,
    };
  }
}
