package vledger

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
)

// Options controls how the client connects to VectorLedger.
type Options struct {
	// Host is the server hostname or IP address (default: "127.0.0.1").
	Host string
	// Port is the TCP port (default: 5433).
	Port int
	// WithProofs attaches a Merkle proof to every SELECT result (default: false).
	WithProofs bool
	// UseTLS enables TLS 1.3 (default: true).
	UseTLS bool
	// TLSCACert is the path to a PEM CA certificate for server verification.
	// Leave empty to skip verification (development only).
	TLSCACert string
	// InsecureSkipVerify disables TLS certificate verification.
	// Set to true only in development / test environments.
	InsecureSkipVerify bool
	// Timeout is the dial and read/write timeout (default: 30s).
	Timeout time.Duration
}

func (o *Options) applyDefaults() {
	if o.Host == "" {
		o.Host = "127.0.0.1"
	}
	if o.Port == 0 {
		o.Port = 5433
	}
	if o.Timeout == 0 {
		o.Timeout = 30 * time.Second
	}
	if !o.UseTLS {
		// Preserve zero-value: default is TLS on, so we only set it explicitly
		// when the caller sets UseTLS = false.
		o.UseTLS = true
	}
}

// Client is a thread-safe VectorLedger client.
// Create one with Connect and reuse it across goroutines.
type Client struct {
	opts   Options
	conn   net.Conn
	reader *bufio.Reader
	mu     sync.Mutex
}

// Connect opens a connection and returns a ready Client.
func Connect(opts Options) (*Client, error) {
	opts.applyDefaults()
	c := &Client{opts: opts}
	if err := c.dial(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) dial() error {
	addr := fmt.Sprintf("%s:%d", c.opts.Host, c.opts.Port)

	var conn net.Conn
	var err error

	if c.opts.UseTLS {
		tlsCfg := &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: c.opts.InsecureSkipVerify, //nolint:gosec
			ServerName:         c.opts.Host,
		}
		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: c.opts.Timeout},
			Config:    tlsCfg,
		}
		conn, err = dialer.Dial("tcp", addr)
	} else {
		conn, err = net.DialTimeout("tcp", addr, c.opts.Timeout)
	}

	if err != nil {
		return &VledgerConnectionError{Cause: err}
	}

	c.conn   = conn
	c.reader = bufio.NewReader(conn)
	return nil
}

// Close shuts down the connection.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
}

// Reconnect closes the current connection and opens a fresh one.
func (c *Client) Reconnect() error {
	c.Close()
	return c.dial()
}

// Query executes sql and returns the full result set.
func (c *Client) Query(sql string, opts ...QueryOption) (*QueryResult, error) {
	qo := queryOptions{withProof: c.opts.WithProofs}
	for _, o := range opts {
		o(&qo)
	}
	return c.send(sql, qo.withProof)
}

// Execute executes sql and returns the number of rows affected.
// Convenience wrapper for INSERT / UPDATE statements.
func (c *Client) Execute(sql string) (int, error) {
	result, err := c.send(sql, false)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected, nil
}

// Balance returns the current balance for account (code or UUID).
func (c *Client) Balance(account string) (int64, error) {
	result, err := c.Query(fmt.Sprintf("SELECT BALANCE('%s')", account))
	if err != nil {
		return 0, err
	}
	if len(result.Rows) == 0 {
		return 0, &VledgerError{Message: fmt.Sprintf("no balance returned for account %q", account)}
	}
	raw, err := result.Rows[0].Get("balance")
	if err != nil {
		return 0, err
	}
	switch v := raw.(type) {
	case float64:
		return int64(v), nil
	case int64:
		return v, nil
	case json.Number:
		n, e := v.Int64()
		return n, e
	default:
		return 0, fmt.Errorf("vledger: unexpected balance type %T", raw)
	}
}

// VerifyChain verifies the database hash-chain integrity.
// Returns true on success, or a VledgerError describing the failure.
func (c *Client) VerifyChain() (bool, error) {
	result, err := c.Query("SELECT VERIFY_CHAIN()")
	if err != nil {
		return false, err
	}
	if len(result.Rows) == 0 {
		return false, &VledgerError{Message: "no response from VERIFY_CHAIN()"}
	}
	status, _ := result.Rows[0].Get("status")
	if status != "OK" {
		return false, &VledgerError{Message: fmt.Sprintf("chain integrity failure: %v", status)}
	}
	return true, nil
}

// ── Query options ─────────────────────────────────────────────────────────────

type queryOptions struct {
	withProof bool
}

// QueryOption is a functional option for Query calls.
type QueryOption func(*queryOptions)

// WithProof attaches a Merkle proof to the response.
func WithProof() QueryOption {
	return func(o *queryOptions) { o.withProof = true }
}

// ── Internal send / receive ───────────────────────────────────────────────────

func (c *Client) send(sql string, withProof bool) (*QueryResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil, &VledgerConnectionError{Cause: fmt.Errorf("not connected")}
	}

	// Set deadline
	deadline := time.Now().Add(c.opts.Timeout)
	if err := c.conn.SetDeadline(deadline); err != nil {
		return nil, &VledgerConnectionError{Cause: err}
	}

	// Encode and send request
	req := request{SQL: sql, WithProof: withProof}
	line, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("vledger: marshal request: %w", err)
	}
	line = append(line, '\n')

	if _, err = c.conn.Write(line); err != nil {
		c.conn = nil
		return nil, &VledgerConnectionError{Cause: err}
	}

	// Read response line
	respLine, err := c.reader.ReadString('\n')
	if err != nil {
		c.conn = nil
		return nil, &VledgerConnectionError{Cause: err}
	}

	// Parse response
	var raw rawResponse
	if err = json.Unmarshal([]byte(respLine), &raw); err != nil {
		return nil, fmt.Errorf("vledger: parse response: %w", err)
	}

	if !raw.OK {
		return nil, &VledgerError{Message: raw.Error, SQL: sql}
	}

	return parseQueryResult(&raw), nil
}

func parseQueryResult(raw *rawResponse) *QueryResult {
	rows := make([]Row, len(raw.Rows))
	for i, r := range raw.Rows {
		rows[i] = Row{Columns: raw.Columns, Values: r}
	}

	var proof *MerkleProof
	if raw.Proof != nil {
		proof = &MerkleProof{
			RootHex:   raw.Proof.RootHex,
			LeafCount: raw.Proof.LeafCount,
			Verified:  raw.Proof.Verified,
		}
	}

	rowsAffected := raw.RowsAffected
	if rowsAffected == 0 {
		rowsAffected = len(rows)
	}

	return &QueryResult{
		Columns:      raw.Columns,
		Rows:         rows,
		RowsAffected: rowsAffected,
		Message:      raw.Message,
		Proof:        proof,
	}
}
