//! Push-frame wire codec (docs/pusher-design.md §3).
//!
//! A push body is a concatenation of frames:
//!
//! ```text
//! addr(32) | stamp(113) | wire_len(u16 LE) | wire(≤ 4104)
//! ```
//!
//! - `addr`  — chunk address (BMT root of the wire content).
//! - `stamp` — bee wire stamp `[batchID:32][index:8][timestamp:8][sig:65]`.
//! - `wire`  — span(8) + data(≤4096), exactly what pushsync carries.
//!
//! Transport-agnostic on purpose: the same frames could later ride a
//! WebSocket or WebTransport binding. Pure byte-shuffling — no deps beyond
//! the crate's `StampedChunk`, so it compiles identically on native and
//! wasm (the dApp encodes; the pusher decodes).

use crate::client::StampedChunk;

/// Fixed stamp length: `batchID(32) + index(8) + timestamp(8) + sig(65)`.
pub const STAMP_LEN: usize = 113;
/// Max wire length: span(8) + max chunk data(4096).
pub const MAX_WIRE_LEN: usize = 4104;
/// Fixed frame header before the variable wire: addr + stamp + len(u16).
/// Public because it is the smallest a frame can be, which is what bounds
/// how many frames a body of a given `Content-Length` can hold — the basis
/// of the metered reservation (`docs/pusher-incentives.md` §7.2) and of
/// Stage 0's per-frame byte accounting.
pub const HEADER_LEN: usize = 32 + STAMP_LEN + 2;
/// Upper bound on a single encoded frame.
pub const MAX_FRAME_LEN: usize = HEADER_LEN + MAX_WIRE_LEN;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("truncated frame at byte {0} (need more input)")]
    Truncated(usize),
    #[error("wire_len {0} exceeds max {MAX_WIRE_LEN}")]
    WireTooLong(usize),
    #[error("frame count {0} exceeds max {1}")]
    TooManyFrames(usize, usize),
}

/// Append one frame for `chunk` to `out`. The stamp must be exactly
/// [`STAMP_LEN`] and the wire at most [`MAX_WIRE_LEN`]; callers building
/// frames from `prepare_upload_*` output always satisfy this, so a
/// violation is a programming error and is asserted, not returned.
pub fn encode_frame(out: &mut Vec<u8>, chunk: &StampedChunk) {
    debug_assert_eq!(chunk.stamp.len(), STAMP_LEN, "stamp must be 113 bytes");
    debug_assert!(chunk.wire.len() <= MAX_WIRE_LEN, "wire too long");
    out.extend_from_slice(&chunk.addr);
    out.extend_from_slice(&chunk.stamp);
    out.extend_from_slice(&(chunk.wire.len() as u16).to_le_bytes());
    out.extend_from_slice(&chunk.wire);
}

/// Encode a batch of chunks into a single frame body.
pub fn encode_batch(chunks: &[StampedChunk]) -> Vec<u8> {
    let mut out = Vec::with_capacity(chunks.len() * (HEADER_LEN + 512));
    for c in chunks {
        encode_frame(&mut out, c);
    }
    out
}

/// Decode a frame body into chunks. `max_frames` bounds allocation
/// against a hostile body (the server passes its batch cap). A trailing
/// partial frame is a hard error — bodies are whole batches, not streams.
pub fn decode_batch(mut buf: &[u8], max_frames: usize) -> Result<Vec<StampedChunk>, FrameError> {
    let mut out = Vec::new();
    let mut consumed = 0usize;
    while !buf.is_empty() {
        if out.len() >= max_frames {
            return Err(FrameError::TooManyFrames(out.len() + 1, max_frames));
        }
        if buf.len() < HEADER_LEN {
            return Err(FrameError::Truncated(consumed));
        }
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&buf[..32]);
        let stamp = buf[32..32 + STAMP_LEN].to_vec();
        let wire_len = u16::from_le_bytes([buf[32 + STAMP_LEN], buf[32 + STAMP_LEN + 1]]) as usize;
        if wire_len > MAX_WIRE_LEN {
            return Err(FrameError::WireTooLong(wire_len));
        }
        let frame_len = HEADER_LEN + wire_len;
        if buf.len() < frame_len {
            return Err(FrameError::Truncated(consumed));
        }
        let wire = buf[HEADER_LEN..frame_len].to_vec();
        out.push(StampedChunk { addr, wire, stamp });
        buf = &buf[frame_len..];
        consumed += frame_len;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(seed: u8, wire_len: usize) -> StampedChunk {
        StampedChunk {
            addr: [seed; 32],
            wire: vec![seed ^ 0xAA; wire_len],
            stamp: vec![seed ^ 0x55; STAMP_LEN],
        }
    }

    #[test]
    fn roundtrip_batch() {
        let batch = vec![chunk(1, 4104), chunk(2, 8), chunk(3, 100)];
        let body = encode_batch(&batch);
        let back = decode_batch(&body, 1024).unwrap();
        assert_eq!(back.len(), 3);
        for (a, b) in batch.iter().zip(&back) {
            assert_eq!(a.addr, b.addr);
            assert_eq!(a.stamp, b.stamp);
            assert_eq!(a.wire, b.wire);
        }
    }

    #[test]
    fn empty_body_is_empty_batch() {
        assert!(decode_batch(&[], 16).unwrap().is_empty());
    }

    #[test]
    fn truncated_header_errors() {
        let body = encode_batch(&[chunk(1, 64)]);
        assert!(matches!(
            decode_batch(&body[..10], 16),
            Err(FrameError::Truncated(_))
        ));
    }

    #[test]
    fn truncated_wire_errors() {
        let body = encode_batch(&[chunk(1, 64)]);
        // Cut off the last 5 wire bytes.
        assert!(matches!(
            decode_batch(&body[..body.len() - 5], 16),
            Err(FrameError::Truncated(_))
        ));
    }

    #[test]
    fn frame_cap_enforced() {
        let body = encode_batch(&[chunk(1, 8), chunk(2, 8), chunk(3, 8)]);
        assert!(matches!(
            decode_batch(&body, 2),
            Err(FrameError::TooManyFrames(_, 2))
        ));
    }
}
