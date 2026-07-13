//! Receive-side frame reassembly (design decision D4).
//!
//! TCP is a byte stream: a single socket read may deliver half a frame, one
//! frame, or several frames coalesced. The core — not the driver — owns the
//! partial-frame buffer, so a driver can pump *raw* socket bytes in and let the
//! core hand back whole frames. This is what makes the core a real sans-I/O
//! machine rather than one that assumes the driver pre-splits frames.
//!
//! Bounded by construction: [`peek_header`] rejects any header whose declared
//! length exceeds [`MAX_PAYLOAD_LEN`](crate::frame::MAX_PAYLOAD_LEN), so the
//! buffer can never grow past one max-sized frame while waiting for the rest —
//! predictable RAM on an ESP32. A malformed prefix errors immediately (Tuya
//! frames are back-to-back with no resync point; a bad prefix means a corrupt
//! stream → the caller resets the connection).

use alloc::vec::Vec;

use crate::frame::peek_header;
use crate::Result;

/// Accumulates socket bytes and yields complete frames.
#[derive(Debug, Default)]
pub struct RxBuffer {
    buf: Vec<u8>,
}

impl RxBuffer {
    /// A new, empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Appends freshly-read socket bytes.
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Extracts the next complete frame's bytes, consuming them from the buffer.
    ///
    /// * `Ok(Some(frame))` — one whole frame (prefix..suffix), removed from the
    ///   front of the buffer;
    /// * `Ok(None)` — not enough bytes yet; the driver keeps reading;
    /// * `Err(_)` — a malformed / oversized header. The buffer is left as-is; the
    ///   caller should [`clear`](Self::clear) and tear the connection down.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>> {
        let Some(header) = peek_header(&self.buf)? else {
            return Ok(None);
        };
        if self.buf.len() < header.frame_len {
            return Ok(None);
        }
        // Split at frame_len: `buf` keeps the frame, `rest` the remainder; swap so
        // `buf` becomes the remainder and we return the frame — one allocation.
        let rest = self.buf.split_off(header.frame_len);
        let frame = core::mem::replace(&mut self.buf, rest);
        Ok(Some(frame))
    }

    /// Drops all buffered bytes (on teardown, or after a framing error).
    pub fn clear(&mut self) {
        self.buf.clear();
    }

    /// Bytes currently buffered (bounded by one max frame; see the module docs).
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether the buffer holds no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{pack_55aa, Integrity};

    fn frame(seqno: u32, body: &[u8]) -> Vec<u8> {
        pack_55aa(seqno, 0x0a, body, Integrity::Crc32)
    }

    #[test]
    fn single_whole_frame() {
        let f = frame(1, b"hello");
        let mut rx = RxBuffer::new();
        rx.push(&f);
        assert_eq!(rx.next_frame().unwrap(), Some(f));
        assert_eq!(rx.next_frame().unwrap(), None);
        assert!(rx.is_empty());
    }

    #[test]
    fn byte_by_byte_dribble_reassembles() {
        let f = frame(2, b"dribble");
        let mut rx = RxBuffer::new();
        for (i, b) in f.iter().enumerate() {
            rx.push(&[*b]);
            if i + 1 < f.len() {
                assert_eq!(rx.next_frame().unwrap(), None, "incomplete at byte {i}");
            }
        }
        assert_eq!(rx.next_frame().unwrap(), Some(f));
    }

    #[test]
    fn coalesced_frames_split_in_order() {
        let a = frame(1, b"aaa");
        let b = frame(2, b"bbbb");
        let c = frame(3, b"c");
        let mut glued = Vec::new();
        glued.extend_from_slice(&a);
        glued.extend_from_slice(&b);
        glued.extend_from_slice(&c);
        let mut rx = RxBuffer::new();
        rx.push(&glued);
        assert_eq!(rx.next_frame().unwrap(), Some(a));
        assert_eq!(rx.next_frame().unwrap(), Some(b));
        assert_eq!(rx.next_frame().unwrap(), Some(c));
        assert_eq!(rx.next_frame().unwrap(), None);
    }

    #[test]
    fn frame_plus_partial_next() {
        let a = frame(1, b"first");
        let b = frame(2, b"second");
        let mut rx = RxBuffer::new();
        rx.push(&a);
        rx.push(&b[..5]); // only the header start of the second frame
        assert_eq!(rx.next_frame().unwrap(), Some(a));
        assert_eq!(rx.next_frame().unwrap(), None); // second not complete
        rx.push(&b[5..]);
        assert_eq!(rx.next_frame().unwrap(), Some(b));
    }

    #[test]
    fn bad_prefix_errors() {
        let mut rx = RxBuffer::new();
        rx.push(&[0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0]);
        assert!(rx.next_frame().is_err());
    }
}
