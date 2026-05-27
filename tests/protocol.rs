//! Round-trip tests for `pack_message` / `unpack_message` on the v3.3 (55AA + CRC32)
//! and v3.4/v3.5 (55AA + HMAC, 6699 + GCM) framing variants.

use rustuya::protocol::{
    MAX_PAYLOAD_LEN, PREFIX_55AA, PREFIX_6699, TuyaMessage, pack_message, parse_header,
    unpack_message,
};

const KEY: &[u8] = b"0123456789abcdef";

#[test]
fn pack_unpack_55aa_with_crc() {
    let msg = TuyaMessage {
        seqno: 7,
        cmd: 0x0a,
        retcode: None,
        payload: b"{\"hello\":\"world\"}".to_vec(),
        prefix: PREFIX_55AA,
        iv: None,
    };

    let bytes = pack_message(&msg, None).expect("pack must succeed");
    let header = parse_header(&bytes).expect("header parses");
    assert_eq!(header.prefix, PREFIX_55AA);
    assert_eq!(header.seqno, 7);
    assert_eq!(header.cmd, 0x0a);

    let decoded = unpack_message(&bytes, None, None, Some(true)).expect("unpack must succeed");
    assert_eq!(decoded.seqno, 7);
    assert_eq!(decoded.cmd, 0x0a);
    assert_eq!(decoded.payload, msg.payload);
    assert_eq!(decoded.prefix, PREFIX_55AA);
}

#[test]
fn pack_unpack_55aa_with_hmac() {
    let msg = TuyaMessage {
        seqno: 1,
        cmd: 0x0d,
        retcode: None,
        payload: b"hmac-protected".to_vec(),
        prefix: PREFIX_55AA,
        iv: None,
    };

    let bytes = pack_message(&msg, Some(KEY)).unwrap();
    let decoded = unpack_message(&bytes, Some(KEY), None, Some(true)).unwrap();
    assert_eq!(decoded.payload, msg.payload);
}

#[test]
fn unpack_55aa_hmac_detects_tampering() {
    let msg = TuyaMessage {
        seqno: 1,
        cmd: 0x0d,
        retcode: None,
        payload: b"tamper-me".to_vec(),
        prefix: PREFIX_55AA,
        iv: None,
    };

    let mut bytes = pack_message(&msg, Some(KEY)).unwrap();
    // Flip a payload byte (located right after the 16-byte header).
    bytes[16] ^= 0x01;

    let res = unpack_message(&bytes, Some(KEY), None, Some(true));
    assert!(res.is_err(), "tampered HMAC payload must fail to unpack");
}

#[test]
fn unpack_55aa_crc_detects_tampering() {
    let msg = TuyaMessage {
        seqno: 1,
        cmd: 0x0a,
        retcode: None,
        payload: b"crc-protected".to_vec(),
        prefix: PREFIX_55AA,
        iv: None,
    };

    let mut bytes = pack_message(&msg, None).unwrap();
    bytes[17] ^= 0x01; // tamper with payload

    let res = unpack_message(&bytes, None, None, Some(true));
    assert!(res.is_err(), "tampered CRC payload must fail to unpack");
}

#[test]
fn pack_unpack_6699_gcm_roundtrip() {
    let msg = TuyaMessage {
        seqno: 42,
        cmd: 0x0d,
        retcode: Some(0),
        payload: b"6699-payload".to_vec(),
        prefix: PREFIX_6699,
        iv: Some(vec![0u8; 12]),
    };

    let bytes = pack_message(&msg, Some(KEY)).expect("pack 6699");

    let header = parse_header(&bytes).unwrap();
    assert_eq!(header.prefix, PREFIX_6699);
    assert_eq!(header.seqno, 42);

    let decoded = unpack_message(&bytes, Some(KEY), None, Some(false)).expect("unpack 6699");
    assert_eq!(decoded.payload, msg.payload);
    assert_eq!(decoded.retcode, Some(0));
    assert_eq!(decoded.prefix, PREFIX_6699);
}

#[test]
fn parse_header_rejects_short_input() {
    let res = parse_header(&[0u8; 4]);
    assert!(res.is_err());
}

#[test]
fn parse_header_rejects_unknown_prefix() {
    let bytes = [0u8; 16];
    assert!(parse_header(&bytes).is_err());
}

/// Builds a minimal 16-byte 55AA header carrying `payload_len`; seqno and
/// cmd are left zero. Used to exercise the length-bound guard.
fn header_55aa(payload_len: u32) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..4].copy_from_slice(&PREFIX_55AA.to_be_bytes());
    b[12..16].copy_from_slice(&payload_len.to_be_bytes());
    b
}

#[test]
fn parse_header_accepts_max_payload_len() {
    let header = parse_header(&header_55aa(MAX_PAYLOAD_LEN)).expect("boundary value parses");
    assert_eq!(header.payload_len, MAX_PAYLOAD_LEN);
    assert_eq!(header.total_length, MAX_PAYLOAD_LEN + 16);
}

#[test]
fn parse_header_rejects_oversized_payload_len() {
    let res = parse_header(&header_55aa(MAX_PAYLOAD_LEN + 1));
    assert!(res.is_err(), "payload_len above the cap must be rejected");
}

#[test]
fn parse_header_rejects_overflow_payload_len() {
    // A near-u32::MAX length would overflow `payload_len + 16` and, without
    // the bound, drive a multi-GB allocation in read_full_packet.
    let res = parse_header(&header_55aa(u32::MAX));
    assert!(res.is_err(), "u32::MAX length must be rejected, not overflow");
}
