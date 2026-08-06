/**
 * VectorLedger wire-protocol types.
 *
 * The server speaks newline-delimited JSON over TLS 1.3.
 * Every request is a single JSON line; every response is a single JSON line.
 */

// ── Request ──────────────────────────────────────────────────────────────────

/** JSON request sent to the VectorLedger server. */
export interface VledgerRequest {
  sql:        string;
  with_proof: boolean;
}

// ── Response ─────────────────────────────────────────────────────────────────

/** Raw JSON response from the VectorLedger server. */
export interface VledgerRawResponse {
  ok:            boolean;
  error?:        string;
  columns?:      string[];
  rows?:         unknown[][];
  rows_affected?: number;
  message?:      string;
  proof?:        RawProof;
}

export interface RawProof {
  root_hex:   string;
  leaf_count: number;
  verified:   boolean;
}

// ── Result types ──────────────────────────────────────────────────────────────

/** A cryptographic Merkle proof attached to a SELECT result. */
export interface MerkleProof {
  rootHex:   string;
  leafCount: number;
  verified:  boolean;
}

/** A single result row with named-column access. */
export class Row {
  constructor(
    public readonly columns: string[],
    public readonly values:  unknown[],
  ) {}

  /** Get the value of column *name*. Throws if the column does not exist. */
  get(name: string): unknown {
    const idx = this.columns.indexOf(name);
    if (idx === -1) throw new Error(`Column '${name}' not found`);
    return this.values[idx];
  }

  /** Get the value of column *name*, or *defaultValue* if absent. */
  getOrDefault(name: string, defaultValue: unknown = null): unknown {
    const idx = this.columns.indexOf(name);
    return idx === -1 ? defaultValue : this.values[idx];
  }

  /** Return this row as a plain object. */
  toObject(): Record<string, unknown> {
    return Object.fromEntries(this.columns.map((c, i) => [c, this.values[i]]));
  }

  toString(): string {
    return JSON.stringify(this.toObject());
  }
}

/** The complete result of a SQL query. */
export interface QueryResult {
  columns:      string[];
  rows:         Row[];
  rowsAffected: number;
  message:      string;
  proof:        MerkleProof | null;
}

// ── Errors ───────────────────────────────────────────────────────────────────

/** Thrown when the server returns an error response. */
export class VledgerError extends Error {
  constructor(
    message:   string,
    public readonly sql: string = "",
  ) {
    super(message);
    this.name = "VledgerError";
  }
}

/** Thrown when the connection to the server fails or drops. */
export class VledgerConnectionError extends VledgerError {
  constructor(message: string) {
    super(message);
    this.name = "VledgerConnectionError";
  }
}
