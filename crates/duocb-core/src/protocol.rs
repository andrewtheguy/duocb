//! Wire protocol: auth/PIN control messages, clipboard messages, and the
//! length-prefixed JSON framing shared by both.
//!
//! A connection uses a **single** bidirectional stream, opened by the client
//! (dialer):
//! 1. Auth runs first on it: mutual application-key authentication, or the PIN
//!    challenge-response used by quick mode (see `crate::pin_auth`).
//! 2. Once auth succeeds the same stream stays open and carries [`ClipMsg`]
//!    frames in both directions for the life of the connection. (A clipboard
//!    app has exactly one data stream, so no separate control channel is
//!    warranted — unlike the multiplexed tunnel this transport was ported from.)

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// v3 replaces configure-mode token auth with mutual application-key proofs.
pub const DUOCB_PROTO_VERSION: u16 = 3;

/// Cap for control frames (auth/pin). Small request/response messages only.
pub const MAX_CONTROL_MESSAGE_SIZE: usize = 16 * 1024;

/// Cap for clipboard frames (the encoded frame, not the raw text — JSON string
/// escaping can expand the payload). Oversize sends are rejected locally before
/// hitting the wire; an oversize length prefix on receive is a protocol error.
pub const MAX_CLIP_MESSAGE_SIZE: usize = 1024 * 1024;

/// Maximum length for rejection reason to prevent excessively large messages.
pub const MAX_REJECT_REASON_LENGTH: usize = 512;

/// Truncate a rejection reason to the maximum allowed length.
/// If truncation is needed, appends "..." suffix at a valid UTF-8 boundary.
fn truncate_reason(reason: String, max_len: usize) -> String {
    const TRUNCATION_SUFFIX: &str = "...";
    if reason.len() > max_len {
        let max_content_len = max_len.saturating_sub(TRUNCATION_SUFFIX.len());
        let truncated = &reason[..reason.floor_char_boundary(max_content_len)];
        format!("{}{}", truncated, TRUNCATION_SUFFIX)
    } else {
        reason
    }
}

/// Authentication request sent by the client immediately after the iroh connection,
/// on the first bidirectional stream it opens. The `method` tag selects the auth path
/// the server runs:
/// - `Key` — the persistent application identity (configure mode).
/// - `Pin` — PIN/session-secret challenge-response used by PIN quick pair and
///   manual mode: `nonce` is the dialer's random nonce and the exchange continues
///   with [`PinChallenge`] / [`PinResponse`] / [`PinConfirm`] on the same stream
///   (see `crate::pin_auth`). No token crosses the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method")]
pub enum AuthRequest {
    Key {
        version: u16,
        /// Hex-encoded Nostr/application public key.
        public_key: String,
        /// Base64url random client nonce.
        nonce: String,
    },
    Pin {
        version: u16,
        /// The dialer's random challenge nonce (base64url), bound into the proofs.
        nonce: String,
    },
}

impl AuthRequest {
    pub fn key(public_key: impl Into<String>, nonce: impl Into<String>) -> Self {
        Self::Key {
            version: DUOCB_PROTO_VERSION,
            public_key: public_key.into(),
            nonce: nonce.into(),
        }
    }

    /// PIN-method request carrying the dialer's challenge nonce.
    pub fn pin(nonce: impl Into<String>) -> Self {
        Self::Pin {
            version: DUOCB_PROTO_VERSION,
            nonce: nonce.into(),
        }
    }

    fn version(&self) -> u16 {
        match self {
            AuthRequest::Key { version, .. } | AuthRequest::Pin { version, .. } => *version,
        }
    }
}

/// Listener's authenticated challenge in configure mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyChallenge {
    pub version: u16,
    pub public_key: String,
    pub nonce: String,
    pub proof: String,
}

impl KeyChallenge {
    pub fn new(
        public_key: impl Into<String>,
        nonce: impl Into<String>,
        proof: impl Into<String>,
    ) -> Self {
        Self {
            version: DUOCB_PROTO_VERSION,
            public_key: public_key.into(),
            nonce: nonce.into(),
            proof: proof.into(),
        }
    }
}

/// Dialer's proof after verifying [`KeyChallenge`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyProof {
    pub version: u16,
    pub proof: String,
}

impl KeyProof {
    pub fn new(proof: impl Into<String>) -> Self {
        Self {
            version: DUOCB_PROTO_VERSION,
            proof: proof.into(),
        }
    }
}

/// Listener's reply to a PIN [`AuthRequest`], carrying its own challenge nonce. The dialer
/// answers with a [`PinResponse`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinChallenge {
    pub version: u16,
    /// The listener's random challenge nonce (base64url).
    pub nonce: String,
}

impl PinChallenge {
    pub fn new(nonce: impl Into<String>) -> Self {
        Self {
            version: DUOCB_PROTO_VERSION,
            nonce: nonce.into(),
        }
    }
}

/// Dialer's proof of PIN possession, in reply to a [`PinChallenge`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinResponse {
    pub version: u16,
    /// NIP-44 sealed proof over the two nonces under the PIN-derived key.
    pub proof: String,
}

impl PinResponse {
    pub fn new(proof: impl Into<String>) -> Self {
        Self {
            version: DUOCB_PROTO_VERSION,
            proof: proof.into(),
        }
    }
}

/// Listener's final PIN-auth verdict. On success it carries the listener's own proof so the
/// dialer can confirm the listener also holds the PIN (mutual authentication).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinConfirm {
    pub version: u16,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
}

impl PinConfirm {
    pub fn accepted(proof: impl Into<String>) -> Self {
        Self {
            version: DUOCB_PROTO_VERSION,
            accepted: true,
            reason: None,
            proof: Some(proof.into()),
        }
    }

    /// Create a rejection verdict with the given reason (truncated to
    /// [`MAX_REJECT_REASON_LENGTH`]).
    pub fn rejected(reason: impl Into<String>) -> Self {
        Self {
            version: DUOCB_PROTO_VERSION,
            accepted: false,
            reason: Some(truncate_reason(reason.into(), MAX_REJECT_REASON_LENGTH)),
            proof: None,
        }
    }
}

/// Final configure-mode authentication verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub version: u16,
    /// Whether authentication was accepted
    pub accepted: bool,
    /// Reason for rejection (if rejected)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl AuthResponse {
    pub fn accepted() -> Self {
        Self {
            version: DUOCB_PROTO_VERSION,
            accepted: true,
            reason: None,
        }
    }

    /// Create a rejection response with the given reason.
    /// The reason will be truncated if it exceeds [`MAX_REJECT_REASON_LENGTH`].
    pub fn rejected(reason: impl Into<String>) -> Self {
        Self {
            version: DUOCB_PROTO_VERSION,
            accepted: false,
            reason: Some(truncate_reason(reason.into(), MAX_REJECT_REASON_LENGTH)),
        }
    }
}

/// A frame on the post-auth session stream, flowing in both directions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipMsg {
    pub version: u16,
    #[serde(flatten)]
    pub body: ClipBody,
}

/// What a [`ClipMsg`] carries. Text only.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClipBody {
    /// A pushed clipboard item.
    Item { text: String, sent_at_ms: u64 },
    /// Ask the peer for the latest item it sent this session. Each side sends
    /// this when the clipboard stream (re-)opens, so content sent while the
    /// connection was interrupted is re-delivered on resume.
    PullLatest,
    /// Answer to [`ClipBody::PullLatest`]: a re-delivery of the latest sent
    /// item (not sent at all when nothing has been sent this session). The
    /// receiver may already hold it, so it is marked for deduplication.
    Latest { text: String, sent_at_ms: u64 },
}

impl ClipMsg {
    pub fn item(text: impl Into<String>, sent_at_ms: u64) -> Self {
        Self::of(ClipBody::Item {
            text: text.into(),
            sent_at_ms,
        })
    }

    pub fn pull_latest() -> Self {
        Self::of(ClipBody::PullLatest)
    }

    pub fn latest(text: impl Into<String>, sent_at_ms: u64) -> Self {
        Self::of(ClipBody::Latest {
            text: text.into(),
            sent_at_ms,
        })
    }

    fn of(body: ClipBody) -> Self {
        ClipMsg {
            version: DUOCB_PROTO_VERSION,
            body,
        }
    }

    fn version(&self) -> u16 {
        self.version
    }
}

// ============================================================================
// Length-Prefixed JSON Helpers
// ============================================================================

/// Encode a value as length-prefixed JSON bytes, capped at `max` encoded bytes.
fn encode_length_prefixed<T: Serialize>(value: &T, max: usize, type_name: &str) -> Result<Vec<u8>> {
    let json =
        serde_json::to_vec(value).with_context(|| format!("Failed to serialize {}", type_name))?;
    if json.len() > max {
        anyhow::bail!("{} too large: {} bytes", type_name, json.len());
    }
    let len = (json.len() as u32).to_be_bytes();
    let mut buf = Vec::with_capacity(4 + json.len());
    buf.extend_from_slice(&len);
    buf.extend_from_slice(&json);
    Ok(buf)
}

/// Decode a length-prefixed JSON value with version validation.
fn decode_length_prefixed<T: for<'de> Deserialize<'de>>(
    data: &[u8],
    max: usize,
    get_version: impl FnOnce(&T) -> u16,
    type_name: &str,
) -> Result<T> {
    if data.len() < 4 {
        anyhow::bail!("{} too short: {} bytes", type_name, data.len());
    }
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if len > max {
        anyhow::bail!("{} length too large: {} bytes", type_name, len);
    }
    if data.len() < 4 + len {
        anyhow::bail!(
            "{} incomplete: expected {} bytes, got {}",
            type_name,
            4 + len,
            data.len()
        );
    }
    // Strict frame boundary: a buffer holds exactly one length-prefixed frame.
    // Reject trailing bytes rather than silently ignoring them.
    if data.len() > 4 + len {
        anyhow::bail!(
            "{} has {} trailing byte(s) after the frame",
            type_name,
            data.len() - (4 + len)
        );
    }
    let value: T = serde_json::from_slice(&data[4..4 + len])
        .with_context(|| format!("Invalid {} JSON", type_name))?;
    let version = get_version(&value);
    if version != DUOCB_PROTO_VERSION {
        anyhow::bail!(
            "{} version mismatch: expected {}, got {}",
            type_name,
            DUOCB_PROTO_VERSION,
            version
        );
    }
    Ok(value)
}

/// Encode an AuthRequest as length-prefixed JSON bytes.
pub fn encode_auth_request(req: &AuthRequest) -> Result<Vec<u8>> {
    encode_length_prefixed(req, MAX_CONTROL_MESSAGE_SIZE, "AuthRequest")
}

/// Decode an AuthRequest from length-prefixed JSON bytes.
pub fn decode_auth_request(data: &[u8]) -> Result<AuthRequest> {
    decode_length_prefixed(
        data,
        MAX_CONTROL_MESSAGE_SIZE,
        |r: &AuthRequest| r.version(),
        "AuthRequest",
    )
}

pub fn encode_key_challenge(msg: &KeyChallenge) -> Result<Vec<u8>> {
    encode_length_prefixed(msg, MAX_CONTROL_MESSAGE_SIZE, "KeyChallenge")
}

pub fn decode_key_challenge(data: &[u8]) -> Result<KeyChallenge> {
    decode_length_prefixed(
        data,
        MAX_CONTROL_MESSAGE_SIZE,
        |m: &KeyChallenge| m.version,
        "KeyChallenge",
    )
}

pub fn encode_key_proof(msg: &KeyProof) -> Result<Vec<u8>> {
    encode_length_prefixed(msg, MAX_CONTROL_MESSAGE_SIZE, "KeyProof")
}

pub fn decode_key_proof(data: &[u8]) -> Result<KeyProof> {
    decode_length_prefixed(
        data,
        MAX_CONTROL_MESSAGE_SIZE,
        |m: &KeyProof| m.version,
        "KeyProof",
    )
}

/// Encode a PinChallenge as length-prefixed JSON bytes.
pub fn encode_pin_challenge(msg: &PinChallenge) -> Result<Vec<u8>> {
    encode_length_prefixed(msg, MAX_CONTROL_MESSAGE_SIZE, "PinChallenge")
}

/// Decode a PinChallenge from length-prefixed JSON bytes.
pub fn decode_pin_challenge(data: &[u8]) -> Result<PinChallenge> {
    decode_length_prefixed(
        data,
        MAX_CONTROL_MESSAGE_SIZE,
        |m: &PinChallenge| m.version,
        "PinChallenge",
    )
}

/// Encode a PinResponse as length-prefixed JSON bytes.
pub fn encode_pin_response(msg: &PinResponse) -> Result<Vec<u8>> {
    encode_length_prefixed(msg, MAX_CONTROL_MESSAGE_SIZE, "PinResponse")
}

/// Decode a PinResponse from length-prefixed JSON bytes.
pub fn decode_pin_response(data: &[u8]) -> Result<PinResponse> {
    decode_length_prefixed(
        data,
        MAX_CONTROL_MESSAGE_SIZE,
        |m: &PinResponse| m.version,
        "PinResponse",
    )
}

/// Encode a PinConfirm as length-prefixed JSON bytes.
pub fn encode_pin_confirm(msg: &PinConfirm) -> Result<Vec<u8>> {
    encode_length_prefixed(msg, MAX_CONTROL_MESSAGE_SIZE, "PinConfirm")
}

/// Decode a PinConfirm from length-prefixed JSON bytes.
pub fn decode_pin_confirm(data: &[u8]) -> Result<PinConfirm> {
    decode_length_prefixed(
        data,
        MAX_CONTROL_MESSAGE_SIZE,
        |m: &PinConfirm| m.version,
        "PinConfirm",
    )
}

/// Encode an AuthResponse as length-prefixed JSON bytes.
pub fn encode_auth_response(resp: &AuthResponse) -> Result<Vec<u8>> {
    encode_length_prefixed(resp, MAX_CONTROL_MESSAGE_SIZE, "AuthResponse")
}

/// Decode an AuthResponse from length-prefixed JSON bytes.
pub fn decode_auth_response(data: &[u8]) -> Result<AuthResponse> {
    decode_length_prefixed(
        data,
        MAX_CONTROL_MESSAGE_SIZE,
        |r: &AuthResponse| r.version,
        "AuthResponse",
    )
}

/// Encode a ClipMsg as length-prefixed JSON bytes (clipboard-size cap).
pub fn encode_clip_msg(msg: &ClipMsg) -> Result<Vec<u8>> {
    encode_length_prefixed(msg, MAX_CLIP_MESSAGE_SIZE, "ClipMsg")
}

/// Decode a ClipMsg from length-prefixed JSON bytes (clipboard-size cap).
pub fn decode_clip_msg(data: &[u8]) -> Result<ClipMsg> {
    decode_length_prefixed(
        data,
        MAX_CLIP_MESSAGE_SIZE,
        |m: &ClipMsg| m.version(),
        "ClipMsg",
    )
}

/// Read a length-prefixed message from a stream, rejecting frames whose length
/// prefix exceeds `max`. Returns the raw bytes including the length prefix.
pub async fn read_length_prefixed<R: tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
    max: usize,
) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .context("Failed to read message length")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max {
        anyhow::bail!("Message length too large: {} bytes", len);
    }
    let mut buf = Vec::with_capacity(4 + len);
    buf.extend_from_slice(&len_buf);
    buf.resize(4 + len, 0);
    reader
        .read_exact(&mut buf[4..])
        .await
        .context("Failed to read message body")?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_reason_no_truncation() {
        let reason = "short reason".to_string();
        let result = truncate_reason(reason.clone(), 100);
        assert_eq!(result, reason);
    }

    #[test]
    fn test_truncate_reason_ascii_truncation() {
        let reason = "a".repeat(20);
        let result = truncate_reason(reason, 10);
        assert_eq!(result, "aaaaaaa..."); // 7 chars + "..."
        assert_eq!(result.len(), 10);
    }

    #[test]
    fn test_truncate_reason_utf8_safe_truncation() {
        // "é" is 2 bytes in UTF-8
        let reason = "ééééé".to_string(); // 10 bytes
        let result = truncate_reason(reason, 8);
        // max_content_len = 8 - 3 = 5, floor_char_boundary(5) = 4 (2 chars)
        assert_eq!(result, "éé...");
        assert!(result.len() <= 8);
    }

    // ========================================================================
    // Decode error path tests
    // ========================================================================

    #[test]
    fn test_decode_auth_request_too_short() {
        assert!(decode_auth_request(&[0, 0]).is_err());
    }

    #[test]
    fn test_decode_auth_request_incomplete() {
        // Length prefix says 100 bytes but only 4 bytes of body follow
        let mut buf = vec![0, 0, 0, 100];
        buf.extend_from_slice(b"abcd");
        assert!(decode_auth_request(&buf).is_err());
    }

    #[test]
    fn test_decode_auth_request_invalid_json() {
        let body = b"not json";
        let len = (body.len() as u32).to_be_bytes();
        let mut buf = Vec::from(len);
        buf.extend_from_slice(body);
        assert!(decode_auth_request(&buf).is_err());
    }

    #[test]
    fn test_decode_rejects_trailing_bytes() {
        // A valid frame with extra bytes appended must be rejected, not silently
        // truncated to the framed length.
        let mut buf = encode_auth_request(&AuthRequest::key("abc", "nonce")).unwrap();
        assert!(decode_auth_request(&buf).is_ok());
        buf.extend_from_slice(b"trailing");
        let err = decode_auth_request(&buf).unwrap_err();
        assert!(err.to_string().contains("trailing"));
    }

    #[test]
    fn test_decode_control_exceeds_max_size() {
        // Length prefix claims a size larger than MAX_CONTROL_MESSAGE_SIZE
        let len = ((MAX_CONTROL_MESSAGE_SIZE + 1) as u32).to_be_bytes();
        let buf = Vec::from(len);
        let err = decode_auth_request(&buf).unwrap_err();
        assert!(err.to_string().contains("too large"));
    }

    // ========================================================================
    // AuthRequest / AuthResponse roundtrip tests
    // ========================================================================

    #[test]
    fn test_auth_request_key_roundtrip() {
        let req = AuthRequest::key("public-key", "client-nonce");
        let encoded = encode_auth_request(&req).unwrap();
        let decoded = decode_auth_request(&encoded).unwrap();
        match decoded {
            AuthRequest::Key {
                version,
                public_key,
                nonce,
            } => {
                assert_eq!(version, DUOCB_PROTO_VERSION);
                assert_eq!(public_key, "public-key");
                assert_eq!(nonce, "client-nonce");
            }
            other => panic!("expected Key, got {other:?}"),
        }
    }

    #[test]
    fn test_key_challenge_and_proof_roundtrip() {
        let challenge = KeyChallenge::new("server-key", "server-nonce", "server-proof");
        let decoded =
            decode_key_challenge(&encode_key_challenge(&challenge).unwrap()).unwrap();
        assert_eq!(decoded.public_key, "server-key");
        assert_eq!(decoded.nonce, "server-nonce");
        assert_eq!(decoded.proof, "server-proof");

        let proof = KeyProof::new("client-proof");
        let decoded = decode_key_proof(&encode_key_proof(&proof).unwrap()).unwrap();
        assert_eq!(decoded.proof, "client-proof");
    }

    #[test]
    fn test_auth_request_pin_roundtrip() {
        let req = AuthRequest::pin("bm9uY2U");
        let decoded = decode_auth_request(&encode_auth_request(&req).unwrap()).unwrap();
        match decoded {
            AuthRequest::Pin { version, nonce } => {
                assert_eq!(version, DUOCB_PROTO_VERSION);
                assert_eq!(nonce, "bm9uY2U");
            }
            other => panic!("expected Pin, got {other:?}"),
        }
    }

    #[test]
    fn test_auth_request_wrong_version_rejected() {
        // Hand-craft a Pin request with a bad version; decode must reject it.
        let json = br#"{"method":"Pin","version":99,"nonce":"x"}"#;
        let len = (json.len() as u32).to_be_bytes();
        let mut buf = Vec::from(len);
        buf.extend_from_slice(json);
        let err = decode_auth_request(&buf).unwrap_err();
        assert!(err.to_string().contains("version mismatch"));
    }

    #[test]
    fn test_pin_challenge_response_roundtrip() {
        let challenge = PinChallenge::new("listener-nonce");
        let decoded = decode_pin_challenge(&encode_pin_challenge(&challenge).unwrap()).unwrap();
        assert_eq!(decoded.version, DUOCB_PROTO_VERSION);
        assert_eq!(decoded.nonce, "listener-nonce");

        let response = PinResponse::new("sealed-proof");
        let decoded = decode_pin_response(&encode_pin_response(&response).unwrap()).unwrap();
        assert_eq!(decoded.version, DUOCB_PROTO_VERSION);
        assert_eq!(decoded.proof, "sealed-proof");
    }

    #[test]
    fn test_pin_confirm_roundtrip() {
        let ok = PinConfirm::accepted("listener-proof");
        let decoded = decode_pin_confirm(&encode_pin_confirm(&ok).unwrap()).unwrap();
        assert!(decoded.accepted);
        assert_eq!(decoded.proof.as_deref(), Some("listener-proof"));
        assert!(decoded.reason.is_none());

        let rej = PinConfirm::rejected("no matching pin");
        let decoded = decode_pin_confirm(&encode_pin_confirm(&rej).unwrap()).unwrap();
        assert!(!decoded.accepted);
        assert_eq!(decoded.reason.as_deref(), Some("no matching pin"));
        assert!(decoded.proof.is_none());
    }

    #[test]
    fn test_auth_response_accepted_roundtrip() {
        let resp = AuthResponse::accepted();
        let encoded = encode_auth_response(&resp).unwrap();
        let decoded = decode_auth_response(&encoded).unwrap();
        assert_eq!(decoded.version, DUOCB_PROTO_VERSION);
        assert!(decoded.accepted);
        assert!(decoded.reason.is_none());
    }

    #[test]
    fn test_auth_response_rejected_roundtrip() {
        let resp = AuthResponse::rejected("untrusted key");
        let encoded = encode_auth_response(&resp).unwrap();
        let decoded = decode_auth_response(&encoded).unwrap();
        assert_eq!(decoded.version, DUOCB_PROTO_VERSION);
        assert!(!decoded.accepted);
        assert_eq!(decoded.reason.as_deref(), Some("untrusted key"));
    }

    // ========================================================================
    // ClipMsg tests
    // ========================================================================

    #[test]
    fn test_clip_msg_item_roundtrip() {
        let msg = ClipMsg::item("hello 🔐 world\nline two", 1_720_000_000_123);
        let decoded = decode_clip_msg(&encode_clip_msg(&msg).unwrap()).unwrap();
        assert_eq!(decoded.version, DUOCB_PROTO_VERSION);
        let ClipBody::Item { text, sent_at_ms } = decoded.body else {
            panic!("expected Item, got {:?}", decoded.body);
        };
        assert_eq!(text, "hello 🔐 world\nline two");
        assert_eq!(sent_at_ms, 1_720_000_000_123);
    }

    #[test]
    fn test_clip_msg_pull_latest_and_latest_roundtrip() {
        let decoded = decode_clip_msg(&encode_clip_msg(&ClipMsg::pull_latest()).unwrap()).unwrap();
        assert!(matches!(decoded.body, ClipBody::PullLatest));

        let decoded =
            decode_clip_msg(&encode_clip_msg(&ClipMsg::latest("resumed", 42)).unwrap()).unwrap();
        let ClipBody::Latest { text, sent_at_ms } = decoded.body else {
            panic!("expected Latest, got {:?}", decoded.body);
        };
        assert_eq!(text, "resumed");
        assert_eq!(sent_at_ms, 42);
    }

    #[test]
    fn test_clip_msg_accepts_larger_than_control_cap() {
        // A clipboard payload bigger than the control cap but under the clip cap
        // must encode and decode fine.
        let msg = ClipMsg::item("x".repeat(MAX_CONTROL_MESSAGE_SIZE * 2), 0);
        let encoded = encode_clip_msg(&msg).unwrap();
        assert!(encoded.len() > MAX_CONTROL_MESSAGE_SIZE);
        assert!(decode_clip_msg(&encoded).is_ok());
    }

    #[test]
    fn test_clip_msg_encode_exceeds_max_size() {
        let msg = ClipMsg::item("x".repeat(MAX_CLIP_MESSAGE_SIZE), 0);
        let err = encode_clip_msg(&msg).unwrap_err();
        assert!(err.to_string().contains("too large"));
    }

    #[test]
    fn test_clip_msg_decode_exceeds_max_size() {
        let len = ((MAX_CLIP_MESSAGE_SIZE + 1) as u32).to_be_bytes();
        let buf = Vec::from(len);
        let err = decode_clip_msg(&buf).unwrap_err();
        assert!(err.to_string().contains("too large"));
    }

    #[test]
    fn test_clip_msg_wrong_version_rejected() {
        let json = br#"{"version":99,"kind":"item","text":"x","sent_at_ms":0}"#;
        let len = (json.len() as u32).to_be_bytes();
        let mut buf = Vec::from(len);
        buf.extend_from_slice(json);
        let err = decode_clip_msg(&buf).unwrap_err();
        assert!(err.to_string().contains("version mismatch"));
    }

    #[tokio::test]
    async fn test_read_length_prefixed_respects_max() {
        // A frame valid under the clip cap must be rejected when read with the
        // control cap.
        let msg = ClipMsg::item("y".repeat(MAX_CONTROL_MESSAGE_SIZE * 2), 0);
        let encoded = encode_clip_msg(&msg).unwrap();
        let mut reader = std::io::Cursor::new(encoded.clone());
        let err = read_length_prefixed(&mut reader, MAX_CONTROL_MESSAGE_SIZE)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("too large"));

        let mut reader = std::io::Cursor::new(encoded.clone());
        let read = read_length_prefixed(&mut reader, MAX_CLIP_MESSAGE_SIZE)
            .await
            .unwrap();
        assert_eq!(read, encoded);
    }
}
