//! PostgreSQL wire-protocol v3 message types.
//!
//! References: https://www.postgresql.org/docs/current/protocol-message-formats.html
//!
//! Every message is serialised to / deserialised from the raw byte stream
//! described in the Postgres frontend/backend protocol spec.

use std::collections::HashMap;

// ── Startup message ───────────────────────────────────────────────────────────

/// Magic number in the first 4 bytes of a startup packet that signals a
/// TLS (SSL) upgrade request.  We decline gracefully.
pub const SSL_REQUEST_CODE: u32 = 80877103;
/// Magic number for a cancel-request packet.
pub const CANCEL_REQUEST_CODE: u32 = 80877102;
/// Protocol version 3.0 (major=3, minor=0).
pub const PROTOCOL_VERSION_3: u32 = 196608;

/// Decoded startup message sent by the client before authentication.
#[derive(Debug)]
pub struct StartupMessage {
    pub protocol_version: u32,
    /// Key-value parameters (user, database, application_name, …).
    pub params: HashMap<String, String>,
}

impl StartupMessage {
    /// Parse a startup message from a length-prefixed byte buffer.
    ///
    /// The buffer must NOT include the 4-byte length prefix — callers strip
    /// that before calling here.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 4 {
            return None;
        }
        let protocol_version = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let mut params = HashMap::new();

        if protocol_version == SSL_REQUEST_CODE || protocol_version == CANCEL_REQUEST_CODE {
            return Some(Self {
                protocol_version,
                params,
            });
        }

        // Parameters are NUL-terminated key\0value\0 pairs followed by a final \0
        let mut pos = 4;
        while pos < buf.len() {
            let key = read_cstr(buf, &mut pos)?;
            if key.is_empty() {
                break;
            }
            let val = read_cstr(buf, &mut pos)?;
            params.insert(key, val);
        }
        Some(Self {
            protocol_version,
            params,
        })
    }
}

fn read_cstr(buf: &[u8], pos: &mut usize) -> Option<String> {
    let start = *pos;
    let end = buf[start..].iter().position(|&b| b == 0)?;
    let s = String::from_utf8_lossy(&buf[start..start + end]).into_owned();
    *pos = start + end + 1;
    Some(s)
}

// ── Frontend (client → server) messages ──────────────────────────────────────

/// Messages sent by the frontend after the startup phase.
#[derive(Debug)]
pub enum FrontendMessage {
    /// Simple query: `Q` + query string.
    Query(String),
    /// Parse (extended query): `P` + statement name + query + param type count.
    Parse { name: String, query: String },
    /// Bind (extended query): `B`.
    Bind { portal: String, statement: String },
    /// Describe: `D`.
    Describe { kind: u8, name: String },
    /// Execute: `E` + portal name + max rows.
    Execute { portal: String },
    /// Sync: `S` — flush the pipeline.
    Sync,
    /// Flush: `H`.
    Flush,
    /// Terminate: `X`.
    Terminate,
    /// Unknown / unhandled message type.
    Unknown(u8),
}

impl FrontendMessage {
    /// Parse a single frontend message from `(type_byte, payload)`.
    pub fn parse(msg_type: u8, payload: &[u8]) -> Self {
        match msg_type {
            b'Q' => {
                // Query message: null-terminated query string
                let s = payload
                    .split(|&b| b == 0)
                    .next()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .unwrap_or_default();
                Self::Query(s)
            }
            b'P' => {
                let mut pos = 0usize;
                let name = read_cstr_pos(payload, &mut pos);
                let query = read_cstr_pos(payload, &mut pos);
                Self::Parse { name, query }
            }
            b'B' => {
                let mut pos = 0usize;
                let portal = read_cstr_pos(payload, &mut pos);
                let statement = read_cstr_pos(payload, &mut pos);
                Self::Bind { portal, statement }
            }
            b'D' => {
                let kind = *payload.first().unwrap_or(&b'S');
                let mut pos = 1usize;
                let name = read_cstr_pos(payload, &mut pos);
                Self::Describe { kind, name }
            }
            b'E' => {
                let mut pos = 0usize;
                let portal = read_cstr_pos(payload, &mut pos);
                Self::Execute { portal }
            }
            b'S' => Self::Sync,
            b'H' => Self::Flush,
            b'X' => Self::Terminate,
            other => Self::Unknown(other),
        }
    }
}

fn read_cstr_pos(buf: &[u8], pos: &mut usize) -> String {
    if *pos >= buf.len() {
        return String::new();
    }
    match buf[*pos..].iter().position(|&b| b == 0) {
        Some(end) => {
            let s = String::from_utf8_lossy(&buf[*pos..*pos + end]).into_owned();
            *pos += end + 1;
            s
        }
        None => {
            let s = String::from_utf8_lossy(&buf[*pos..]).into_owned();
            *pos = buf.len();
            s
        }
    }
}

// ── Backend (server → client) message builders ───────────────────────────────

/// Build an `AuthenticationOk` message (type `R`, int32 = 0).
pub fn auth_ok() -> Vec<u8> {
    let mut buf = Vec::with_capacity(9);
    buf.push(b'R');
    buf.extend_from_slice(&8u32.to_be_bytes()); // length = 4 (len field) + 4 (int)
    buf.extend_from_slice(&0u32.to_be_bytes()); // AuthenticationOk
    buf
}

/// Build an `AuthenticationCleartextPassword` request (type `R`, int32 = 3).
///
/// Sent by the server to request a cleartext password from the client.
/// Safe to use because we are always inside a TLS 1.3 channel.
pub fn auth_cleartext_password() -> Vec<u8> {
    let mut buf = Vec::with_capacity(9);
    buf.push(b'R');
    buf.extend_from_slice(&8u32.to_be_bytes()); // length = 4 + 4
    buf.extend_from_slice(&3u32.to_be_bytes()); // AuthenticationCleartextPassword
    buf
}

/// Build a `ParameterStatus` message (type `S`).
pub fn parameter_status(name: &str, value: &str) -> Vec<u8> {
    let payload_len = name.len() + 1 + value.len() + 1;
    let mut buf = Vec::with_capacity(1 + 4 + payload_len);
    buf.push(b'S');
    buf.extend_from_slice(&((4 + payload_len) as u32).to_be_bytes());
    buf.extend_from_slice(name.as_bytes());
    buf.push(0);
    buf.extend_from_slice(value.as_bytes());
    buf.push(0);
    buf
}

/// Build a `BackendKeyData` message (type `K`).
pub fn backend_key_data(pid: u32, secret: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(13);
    buf.push(b'K');
    buf.extend_from_slice(&12u32.to_be_bytes());
    buf.extend_from_slice(&pid.to_be_bytes());
    buf.extend_from_slice(&secret.to_be_bytes());
    buf
}

/// Build a `ReadyForQuery` message (type `Z`).
/// `tx_status`: `b'I'` = idle, `b'T'` = in transaction, `b'E'` = error.
pub fn ready_for_query(tx_status: u8) -> Vec<u8> {
    let mut buf = Vec::with_capacity(6);
    buf.push(b'Z');
    buf.extend_from_slice(&5u32.to_be_bytes());
    buf.push(tx_status);
    buf
}

/// A column description for `RowDescription`.
#[derive(Debug, Clone)]
pub struct FieldDesc {
    pub name: String,
    pub type_oid: u32,
    pub type_size: i16,
    pub type_mod: i32,
    pub format_code: i16, // 0 = text, 1 = binary
}

impl FieldDesc {
    pub fn text(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            type_oid: 25, // text OID
            type_size: -1,
            type_mod: -1,
            format_code: 0,
        }
    }
    pub fn bigint(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            type_oid: 20, // int8 OID
            type_size: 8,
            type_mod: -1,
            format_code: 0,
        }
    }
}

/// Build a `RowDescription` message (type `T`).
pub fn row_description(fields: &[FieldDesc]) -> Vec<u8> {
    let mut payload: Vec<u8> = Vec::new();
    payload.extend_from_slice(&(fields.len() as u16).to_be_bytes());
    for f in fields {
        payload.extend_from_slice(f.name.as_bytes());
        payload.push(0); // NUL terminator
        payload.extend_from_slice(&0u32.to_be_bytes()); // table OID (0 = no table)
        payload.extend_from_slice(&0u16.to_be_bytes()); // column attr number
        payload.extend_from_slice(&f.type_oid.to_be_bytes());
        payload.extend_from_slice(&f.type_size.to_be_bytes());
        payload.extend_from_slice(&f.type_mod.to_be_bytes());
        payload.extend_from_slice(&f.format_code.to_be_bytes());
    }
    let mut buf = Vec::with_capacity(1 + 4 + payload.len());
    buf.push(b'T');
    buf.extend_from_slice(&((4 + payload.len()) as u32).to_be_bytes());
    buf.extend_from_slice(&payload);
    buf
}

/// Build a single `DataRow` message (type `D`).
/// Each value is a `Option<String>`; `None` → SQL NULL.
pub fn data_row(values: &[Option<String>]) -> Vec<u8> {
    let mut payload: Vec<u8> = Vec::new();
    payload.extend_from_slice(&(values.len() as u16).to_be_bytes());
    for v in values {
        match v {
            None => payload.extend_from_slice(&(-1i32).to_be_bytes()),
            Some(s) => {
                let bytes = s.as_bytes();
                payload.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
                payload.extend_from_slice(bytes);
            }
        }
    }
    let mut buf = Vec::with_capacity(1 + 4 + payload.len());
    buf.push(b'D');
    buf.extend_from_slice(&((4 + payload.len()) as u32).to_be_bytes());
    buf.extend_from_slice(&payload);
    buf
}

/// Build a `CommandComplete` message (type `C`).
/// `tag` examples: `"SELECT 3"`, `"INSERT 0 1"`.
pub fn command_complete(tag: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 4 + tag.len() + 1);
    buf.push(b'C');
    buf.extend_from_slice(&((4 + tag.len() + 1) as u32).to_be_bytes());
    buf.extend_from_slice(tag.as_bytes());
    buf.push(0);
    buf
}

/// Build an `EmptyQueryResponse` message (type `I`).
pub fn empty_query_response() -> Vec<u8> {
    let mut buf = Vec::with_capacity(5);
    buf.push(b'I');
    buf.extend_from_slice(&4u32.to_be_bytes());
    buf
}

/// Build an `ErrorResponse` message (type `E`).
/// `severity`: `"ERROR"` | `"FATAL"` | `"PANIC"`.
/// `sqlstate`: 5-character SQLSTATE code (e.g. `"42601"` for syntax error).
pub fn error_response(severity: &str, sqlstate: &str, message: &str) -> Vec<u8> {
    let mut payload: Vec<u8> = Vec::new();
    let push_field = |p: &mut Vec<u8>, code: u8, val: &str| {
        p.push(code);
        p.extend_from_slice(val.as_bytes());
        p.push(0);
    };
    push_field(&mut payload, b'S', severity);
    push_field(&mut payload, b'V', severity);
    push_field(&mut payload, b'C', sqlstate);
    push_field(&mut payload, b'M', message);
    payload.push(0); // terminator
    let mut buf = Vec::with_capacity(1 + 4 + payload.len());
    buf.push(b'E');
    buf.extend_from_slice(&((4 + payload.len()) as u32).to_be_bytes());
    buf.extend_from_slice(&payload);
    buf
}

/// Build a `NoticeResponse` message (type `N`) — same format as ErrorResponse.
pub fn notice_response(message: &str) -> Vec<u8> {
    let mut payload: Vec<u8> = Vec::new();
    payload.push(b'S');
    payload.extend_from_slice(b"NOTICE");
    payload.push(0);
    payload.push(b'M');
    payload.extend_from_slice(message.as_bytes());
    payload.push(0);
    payload.push(0);
    let mut buf = Vec::with_capacity(1 + 4 + payload.len());
    buf.push(b'N');
    buf.extend_from_slice(&((4 + payload.len()) as u32).to_be_bytes());
    buf.extend_from_slice(&payload);
    buf
}

/// Build a `ParseComplete` message (type `1`).
pub fn parse_complete() -> Vec<u8> {
    let mut buf = Vec::with_capacity(5);
    buf.push(b'1');
    buf.extend_from_slice(&4u32.to_be_bytes());
    buf
}

/// Build a `BindComplete` message (type `2`).
pub fn bind_complete() -> Vec<u8> {
    let mut buf = Vec::with_capacity(5);
    buf.push(b'2');
    buf.extend_from_slice(&4u32.to_be_bytes());
    buf
}

/// Build a `NoData` message (type `n`).
pub fn no_data() -> Vec<u8> {
    let mut buf = Vec::with_capacity(5);
    buf.push(b'n');
    buf.extend_from_slice(&4u32.to_be_bytes());
    buf
}
