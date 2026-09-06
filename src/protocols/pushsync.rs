//! Bee pushsync protocol — `/swarm/pushsync/1.3.0/pushsync`.
//!
//! Client opens stream → sends `Headers { headers: [] }` → sends
//! `Delivery { address, data, stamp }` → reads `Headers` → reads `Receipt`.

use crate::proto::headers as hdr;
use crate::proto::pushsync as pb;
use crate::protocols::framing::{FrameError, read_message, write_message};
use thiserror::Error;

pub const PROTOCOL: &str = "/swarm/pushsync/1.3.1/pushsync";

#[derive(Debug, Error)]
pub enum PushsyncError {
    #[error("frame: {0}")]
    Frame(#[from] FrameError),
    #[error("peer error: {0}")]
    Peer(String),
}

#[derive(Debug, Clone)]
pub struct PushsyncReceipt {
    pub address: Vec<u8>,
    pub signature: Vec<u8>,
    pub nonce: Vec<u8>,
    pub storage_radius: u32,
}

impl PushsyncReceipt {
    /// Recover the overlay address of the bee node that signed this
    /// receipt. The signature is over the chunk address (EIP-191
    /// prefixed, keccak256-hashed by alloy's recovery helper); the
    /// overlay is then `keccak(eth_addr || network_id_LE_8 || nonce)`.
    /// Returns `None` if signature recovery or layout checks fail.
    pub fn storer_overlay(&self, network_id: u64) -> Option<[u8; 32]> {
        use alloy_signer::Signature;
        if self.address.len() != 32 || self.signature.len() != 65 || self.nonce.len() != 32 {
            return None;
        }
        let sig = Signature::from_raw(&self.signature).ok()?;
        let eth = sig.recover_address_from_msg(&self.address).ok()?;
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&self.nonce);
        Some(crate::signer::derive_overlay(&eth.0.0, network_id, &nonce))
    }

    /// Returns `true` when the receipt's signing peer was *not* in the
    /// chunk's storage neighborhood. Bee's check (mirrored from
    /// `pkg/pushsync/pushsync.go::checkReceipt`) compares
    /// `proximity(storer_overlay, chunk_addr)` against the receipt's
    /// claimed `storage_radius`. A shallow receipt means the chunk was
    /// only forwarded, not durably stored in any peer's reserve, and
    /// the upload should retry against a different peer.
    pub fn is_shallow(&self, network_id: u64) -> bool {
        let Some(overlay) = self.storer_overlay(network_id) else {
            return true;
        };
        if self.address.len() != 32 {
            return true;
        }
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&self.address);
        let po = crate::transport::proximity(&overlay, &addr);
        u32::from(po) < self.storage_radius
    }
}

/// Push a single chunk and read the receipt.
///
/// `chunk_data` must already include the 8-byte LE span prefix (i.e. the
/// nectar `ContentChunk::data()` framing).
pub async fn push<S>(
    stream: &mut S,
    address: &[u8; 32],
    chunk_data: &[u8],
    stamp: &[u8],
) -> Result<PushsyncReceipt, PushsyncError>
where
    S: futures::AsyncRead + futures::AsyncWrite + Unpin,
{
    // Per-phase timing emitted at the end as a single tracing line on
    // the `hoverfly::profile` target. Run with `RUST_LOG=hoverfly::profile=trace`
    // and pipe through `awk` to get a histogram of where push time goes.
    let t_start = web_time::Instant::now();

    // 1. Send empty request headers.
    let req_headers = hdr::Headers { headers: vec![] };
    write_message(stream, &req_headers).await?;
    let t_hdr_sent = web_time::Instant::now();

    // 2. Read response headers (ignored).
    let _resp_headers: hdr::Headers = read_message(stream).await?;
    let t_hdr_recv = web_time::Instant::now();

    // 3. Send delivery.
    let delivery = pb::Delivery {
        address: address.to_vec(),
        data: chunk_data.to_vec(),
        stamp: stamp.to_vec(),
    };
    write_message(stream, &delivery).await?;
    let t_delivery_sent = web_time::Instant::now();

    // 4. Read receipt.
    let receipt: pb::Receipt = read_message(stream).await?;
    let t_receipt_recv = web_time::Instant::now();

    tracing::trace!(
        target: "hoverfly::profile",
        addr = %hex::encode(address),
        hdr_send_us = (t_hdr_sent - t_start).as_micros() as u64,
        hdr_recv_us = (t_hdr_recv - t_hdr_sent).as_micros() as u64,
        delivery_send_us = (t_delivery_sent - t_hdr_recv).as_micros() as u64,
        receipt_recv_us = (t_receipt_recv - t_delivery_sent).as_micros() as u64,
        total_us = (t_receipt_recv - t_start).as_micros() as u64,
        chunk_bytes = chunk_data.len(),
        stamp_bytes = stamp.len(),
        "pushsync_phases",
    );

    if !receipt.err.is_empty() {
        return Err(PushsyncError::Peer(receipt.err));
    }
    // The receipt must be *for the chunk we pushed*. Two things go wrong
    // without this check, and both are reachable by any peer in the pool
    // (membership comes from hive gossip and the seed list, so it is not a
    // trusted set):
    //
    // 1. `address` is copied straight off the wire, and callers build a
    //    `[u8; 32]` from it with `copy_from_slice` (`src/client.rs:5380`,
    //    `:5398`), which panics on any other length. A 0- or 33-byte
    //    address is a remote panic that unwinds the push task.
    // 2. Nothing else compares it to what we sent. A peer could accept the
    //    Delivery, store nothing, and sign a receipt for some *other*
    //    address deep inside its own neighborhood: `is_shallow` and the
    //    `po` computation both read `r.address`, so the forged receipt
    //    looks like a perfect deep delivery and the chunk is acked `ok`
    //    having never been stored.
    //
    // Checking it here means every `PushsyncReceipt` in the codebase
    // carries exactly the 32-byte address that was pushed.
    if receipt.address != address[..] {
        return Err(PushsyncError::Peer(format!(
            "receipt address mismatch: pushed {}, receipt {}",
            hex::encode(address),
            hex::encode(&receipt.address),
        )));
    }
    Ok(PushsyncReceipt {
        address: receipt.address,
        signature: receipt.signature,
        nonce: receipt.nonce,
        storage_radius: receipt.storage_radius,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// Stream whose read side replays a canned peer response and whose
    /// write side is discarded — enough to drive `push` to the receipt.
    struct Canned {
        read: Vec<u8>,
        pos: usize,
    }

    impl futures::AsyncRead for Canned {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            let n = (self.read.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.read[self.pos..self.pos + n]);
            self.pos += n;
            Poll::Ready(Ok(n))
        }
    }

    impl futures::AsyncWrite for Canned {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Response headers followed by `receipt`, both length-delimited.
    fn peer_saying(receipt: pb::Receipt) -> Canned {
        let mut read = Vec::new();
        hdr::Headers { headers: vec![] }
            .encode_length_delimited(&mut read)
            .expect("encode headers");
        receipt
            .encode_length_delimited(&mut read)
            .expect("encode receipt");
        Canned { read, pos: 0 }
    }

    fn receipt_for(address: Vec<u8>) -> pb::Receipt {
        pb::Receipt {
            address,
            signature: vec![7u8; 65],
            nonce: vec![9u8; 32],
            err: String::new(),
            storage_radius: 8,
        }
    }

    fn push_against(receipt: pb::Receipt) -> Result<PushsyncReceipt, PushsyncError> {
        let pushed = [1u8; 32];
        let mut stream = peer_saying(receipt);
        tokio_test::block_on(push(&mut stream, &pushed, &[0u8; 16], &[0u8; 113]))
    }

    #[test]
    fn receipt_for_the_pushed_address_is_accepted() {
        let r = push_against(receipt_for(vec![1u8; 32])).expect("should accept");
        assert_eq!(r.address, vec![1u8; 32]);
        assert_eq!(r.storage_radius, 8);
    }

    /// A peer can otherwise sign a receipt for a *different* address deep in
    /// its own neighborhood, having stored nothing: `is_shallow` and the `po`
    /// computation both read the receipt's address, so it would look like a
    /// perfect delivery.
    #[test]
    fn receipt_for_a_different_address_is_rejected() {
        let err = push_against(receipt_for(vec![2u8; 32])).expect_err("should reject");
        assert!(
            matches!(&err, PushsyncError::Peer(m) if m.contains("address mismatch")),
            "unexpected error: {err}"
        );
    }

    /// Callers build `[u8; 32]` from this with `copy_from_slice`, which
    /// panics on any other length — so a malformed address must be rejected
    /// here rather than unwinding the push task.
    #[test]
    fn missized_addresses_are_rejected_not_panicked_on() {
        for bad in [vec![], vec![1u8; 31], vec![1u8; 33], vec![1u8; 64]] {
            let n = bad.len();
            let err =
                push_against(receipt_for(bad)).expect_err("missized address must be rejected");
            assert!(
                matches!(&err, PushsyncError::Peer(m) if m.contains("address mismatch")),
                "unexpected error for {n}-byte address: {err}"
            );
        }
    }
}
