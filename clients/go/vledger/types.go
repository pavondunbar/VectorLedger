// Package vledger provides a Go client for VectorLedger.
//
// The client connects to a running vledger server over TLS 1.3 and speaks the
// newline-delimited JSON wire protocol.
//
//	db, err := vledger.Connect(vledger.Options{Host: "127.0.0.1", Port: 5433})
//	if err != nil { log.Fatal(err) }
//	defer db.Close()
//
//	result, err := db.Query("SELECT * FROM accounts")
//	if err != nil { log.Fatal(err) }
//	for _, row := range result.Rows {
//	    fmt.Println(row.ToMap())
//	}
package vledger

import "fmt"

// ── Request / response wire types ────────────────────────────────────────────

// request is the JSON object sent to the server.
type request struct {
	SQL       string `json:"sql"`
	WithProof bool   `json:"with_proof"`
}

// rawResponse is the JSON object received from the server.
type rawResponse struct {
	OK           bool              `json:"ok"`
	Error        string            `json:"error,omitempty"`
	Columns      []string          `json:"columns,omitempty"`
	Rows         [][]any           `json:"rows,omitempty"`
	RowsAffected int               `json:"rows_affected,omitempty"`
	Message      string            `json:"message,omitempty"`
	Proof        *rawProof         `json:"proof,omitempty"`
}

type rawProof struct {
	RootHex   string `json:"root_hex"`
	LeafCount int    `json:"leaf_count"`
	Verified  bool   `json:"verified"`
}

// ── Result types ──────────────────────────────────────────────────────────────

// MerkleProof is a cryptographic proof attached to a SELECT result.
type MerkleProof struct {
	RootHex   string
	LeafCount int
	Verified  bool
}

// Row is a single result row with named-column access.
type Row struct {
	Columns []string
	Values  []any
}

// Get returns the value of column name.
// Returns an error if the column does not exist.
func (r Row) Get(name string) (any, error) {
	for i, c := range r.Columns {
		if c == name {
			return r.Values[i], nil
		}
	}
	return nil, fmt.Errorf("vledger: column %q not found", name)
}

// MustGet returns the value of column name, panicking if absent.
func (r Row) MustGet(name string) any {
	v, err := r.Get(name)
	if err != nil {
		panic(err)
	}
	return v
}

// GetOrDefault returns the value of column name, or defaultVal if absent.
func (r Row) GetOrDefault(name string, defaultVal any) any {
	v, err := r.Get(name)
	if err != nil {
		return defaultVal
	}
	return v
}

// ToMap converts the row to a map[string]any.
func (r Row) ToMap() map[string]any {
	m := make(map[string]any, len(r.Columns))
	for i, c := range r.Columns {
		m[c] = r.Values[i]
	}
	return m
}

// QueryResult is the complete result of a SQL query.
type QueryResult struct {
	Columns      []string
	Rows         []Row
	RowsAffected int
	Message      string
	Proof        *MerkleProof
}

// ── Errors ────────────────────────────────────────────────────────────────────

// VledgerError is returned when the server sends an error response.
type VledgerError struct {
	Message string
	SQL     string
}

func (e *VledgerError) Error() string {
	if e.SQL != "" {
		return fmt.Sprintf("vledger: %s (sql: %s)", e.Message, e.SQL)
	}
	return fmt.Sprintf("vledger: %s", e.Message)
}

// VledgerConnectionError is returned when the connection fails.
type VledgerConnectionError struct {
	Cause error
}

func (e *VledgerConnectionError) Error() string {
	return fmt.Sprintf("vledger: connection error: %v", e.Cause)
}

func (e *VledgerConnectionError) Unwrap() error { return e.Cause }
