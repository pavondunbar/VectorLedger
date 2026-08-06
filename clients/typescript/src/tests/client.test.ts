/**
 * Unit tests for the VectorLedger TypeScript client.
 * Uses Node.js built-in test runner (no external test framework needed).
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Row, VledgerError } from "../types";
import type { VledgerRawResponse } from "../types";

// ── Row tests ────────────────────────────────────────────────────────────────

describe("Row", () => {
  it("get() returns the correct value", () => {
    const row = new Row(["a", "b"], [1, 2]);
    assert.equal(row.get("a"), 1);
    assert.equal(row.get("b"), 2);
  });

  it("get() throws for unknown column", () => {
    const row = new Row(["x"], ["hello"]);
    assert.throws(() => row.get("z"), /Column 'z' not found/);
  });

  it("getOrDefault() returns default for unknown column", () => {
    const row = new Row([], []);
    assert.equal(row.getOrDefault("missing", 99), 99);
    assert.equal(row.getOrDefault("missing"), null);
  });

  it("toObject() converts to plain object", () => {
    const row = new Row(["id", "name"], [42, "Cash"]);
    assert.deepEqual(row.toObject(), { id: 42, name: "Cash" });
  });
});

// ── VledgerError tests ────────────────────────────────────────────────────────

describe("VledgerError", () => {
  it("carries the sql field", () => {
    const err = new VledgerError("account not found", "SELECT BALANCE('X')");
    assert.equal(err.sql, "SELECT BALANCE('X')");
    assert.match(err.message, /account not found/);
    assert.equal(err.name, "VledgerError");
  });
});

// ── QueryResult parsing ───────────────────────────────────────────────────────

import { VledgerClient } from "../client";

// @ts-expect-error — testing private static
const parseResult = (raw: VledgerRawResponse) => VledgerClient._parseResult(raw);

describe("VledgerClient._parseResult", () => {
  it("parses a basic SELECT response", () => {
    const raw: VledgerRawResponse = {
      ok:            true,
      columns:       ["balance"],
      rows:          [[99000]],
      rows_affected: 1,
      message:       "balance = 99000",
    };
    const result = parseResult(raw);
    assert.equal(result.rows.length, 1);
    assert.equal(result.rows[0].get("balance"), 99000);
    assert.equal(result.rowsAffected, 1);
    assert.equal(result.proof, null);
  });

  it("parses proof when present", () => {
    const raw: VledgerRawResponse = {
      ok:       true,
      columns:  ["sequence"],
      rows:     [[1]],
      rows_affected: 1,
      message:  "ok",
      proof:    { root_hex: "deadbeef", leaf_count: 1, verified: true },
    };
    const result = parseResult(raw);
    assert.notEqual(result.proof, null);
    assert.equal(result.proof!.rootHex, "deadbeef");
    assert.equal(result.proof!.verified, true);
  });

  it("handles empty result set", () => {
    const raw: VledgerRawResponse = { ok: true };
    const result = parseResult(raw);
    assert.equal(result.rows.length, 0);
    assert.equal(result.rowsAffected, 0);
  });
});
