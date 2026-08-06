package vledger

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

// startMockServer creates a local TCP server that replies with resp for every
// request.  Returns the address and a stop function.
func startMockServer(t *testing.T, replies []string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		idx := 0
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go func(c net.Conn) {
				defer c.Close()
				scanner := bufio.NewScanner(c)
				for scanner.Scan() {
					if idx >= len(replies) {
						idx = len(replies) - 1
					}
					fmt.Fprintln(c, replies[idx])
					idx++
				}
			}(conn)
		}
	}()

	return ln.Addr().String()
}

func okReply(columns []string, rows [][]any, msg string) string {
	resp := rawResponse{
		OK:           true,
		Columns:      columns,
		Rows:         rows,
		RowsAffected: len(rows),
		Message:      msg,
	}
	b, _ := json.Marshal(resp)
	return string(b)
}

func errReply(msg string) string {
	resp := rawResponse{OK: false, Error: msg}
	b, _ := json.Marshal(resp)
	return string(b)
}

func connectMock(t *testing.T, addr string) *Client {
	t.Helper()
	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	c := &Client{
		opts: Options{
			Host:    host,
			Port:    port,
			UseTLS:  false,
			Timeout: 5 * time.Second,
		},
	}
	if err := c.dial(); err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(c.Close)
	return c
}

// ── Row tests ─────────────────────────────────────────────────────────────────

func TestRow_Get(t *testing.T) {
	row := Row{Columns: []string{"a", "b"}, Values: []any{1.0, "hello"}}
	v, err := row.Get("a")
	if err != nil || v != 1.0 {
		t.Fatalf("expected 1.0, got %v (err %v)", v, err)
	}
}

func TestRow_GetMissing(t *testing.T) {
	row := Row{Columns: []string{"x"}, Values: []any{"foo"}}
	_, err := row.Get("z")
	if err == nil {
		t.Fatal("expected error for missing column")
	}
}

func TestRow_GetOrDefault(t *testing.T) {
	row := Row{Columns: []string{}, Values: []any{}}
	v := row.GetOrDefault("missing", 42)
	if v != 42 {
		t.Fatalf("expected 42, got %v", v)
	}
}

func TestRow_ToMap(t *testing.T) {
	row := Row{Columns: []string{"id", "name"}, Values: []any{1.0, "Cash"}}
	m := row.ToMap()
	if m["name"] != "Cash" {
		t.Fatalf("unexpected map: %v", m)
	}
}

// ── Client tests ──────────────────────────────────────────────────────────────

func TestClient_Query(t *testing.T) {
	reply := okReply([]string{"balance"}, [][]any{{99000.0}}, "balance = 99000")
	addr := startMockServer(t, []string{reply})
	c := connectMock(t, addr)

	result, err := c.Query("SELECT BALANCE('CASH')")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(result.Rows))
	}
	bal, _ := result.Rows[0].Get("balance")
	if bal != 99000.0 {
		t.Fatalf("expected 99000, got %v", bal)
	}
}

func TestClient_Execute(t *testing.T) {
	// RowsAffected is 0 when rows is empty, but we set it in the reply explicitly
	resp := rawResponse{OK: true, RowsAffected: 1, Message: "1 entry posted"}
	b, _ := json.Marshal(resp)

	addr := startMockServer(t, []string{string(b)})
	c := connectMock(t, addr)

	n, err := c.Execute("INSERT INTO ledger (...) VALUES (...)")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected rows_affected=1, got %d", n)
	}
}

func TestClient_ErrorResponse(t *testing.T) {
	addr := startMockServer(t, []string{errReply("account 'X' not found")})
	c := connectMock(t, addr)

	_, err := c.Query("SELECT BALANCE('X')")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	vErr, ok := err.(*VledgerError)
	if !ok {
		t.Fatalf("expected *VledgerError, got %T", err)
	}
	if vErr.Message != "account 'X' not found" {
		t.Fatalf("unexpected message: %q", vErr.Message)
	}
}

func TestClient_VerifyChain(t *testing.T) {
	reply := okReply(
		[]string{"status", "entries_verified", "chain_tip"},
		[][]any{{"OK", 5.0, "abcdef"}},
		"verified",
	)
	addr := startMockServer(t, []string{reply})
	c := connectMock(t, addr)

	ok, err := c.VerifyChain()
	if err != nil || !ok {
		t.Fatalf("VerifyChain failed: %v", err)
	}
}

func TestParseQueryResult_WithProof(t *testing.T) {
	raw := &rawResponse{
		OK:      true,
		Columns: []string{"seq"},
		Rows:    [][]any{{1.0}},
		Proof:   &rawProof{RootHex: "deadbeef", LeafCount: 1, Verified: true},
	}
	result := parseQueryResult(raw)
	if result.Proof == nil {
		t.Fatal("expected proof")
	}
	if result.Proof.RootHex != "deadbeef" {
		t.Fatalf("unexpected root hex: %q", result.Proof.RootHex)
	}
}
