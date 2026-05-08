//! Round-trip tests for `TuyaCipher` (AES-128-ECB and AES-128-GCM).

use rustuya::crypto::TuyaCipher;

const KEY: &[u8] = b"0123456789abcdef";

#[test]
fn ecb_roundtrip_with_padding() {
    let cipher = TuyaCipher::new(KEY).unwrap();

    let cases: &[&[u8]] = &[
        b"",                                     // empty -> 16 bytes of pad
        b"hi",                                   // tiny
        b"this is exactly 15",                   // 18 bytes
        b"the quick brown fox jumps over",       // 30 bytes (mid-block)
        b"a 16-byte block!",                     // exactly 16 bytes -> +16 pad
    ];

    for plain in cases {
        let ct = cipher.encrypt(plain, false, None, None, true).unwrap();
        let pt = cipher.decrypt(&ct, false, None, None, None).unwrap();
        assert_eq!(pt.as_slice(), *plain, "ECB roundtrip mismatch for {plain:?}");
    }
}

#[test]
fn ecb_no_padding_requires_block_aligned_input() {
    let cipher = TuyaCipher::new(KEY).unwrap();
    // 13 bytes → not a multiple of 16 → encryption must fail
    assert!(cipher.encrypt(b"thirteen byte", false, None, None, false).is_err());
}

#[test]
fn ecb_decrypt_fails_on_non_block_aligned_input() {
    let cipher = TuyaCipher::new(KEY).unwrap();
    let bad = vec![0u8; 13];
    assert!(cipher.decrypt(&bad, false, None, None, None).is_err());
}

#[test]
fn gcm_roundtrip_with_aad() {
    let cipher = TuyaCipher::new(KEY).unwrap();
    let iv = [0u8; 12];
    let aad = b"header-bytes";
    let plaintext = b"payload to seal under GCM";

    let ct = cipher
        .encrypt(plaintext, false, Some(&iv), Some(aad), false)
        .unwrap();

    // GCM ciphertext = iv || ct || tag
    assert!(ct.len() > plaintext.len() + 12);
    assert_eq!(&ct[..12], &iv);

    let pt = cipher
        .decrypt(&ct[12..], false, Some(&iv), Some(aad), None)
        .unwrap();
    assert_eq!(pt.as_slice(), plaintext);
}

#[test]
fn gcm_aad_mismatch_fails() {
    let cipher = TuyaCipher::new(KEY).unwrap();
    let iv = [0u8; 12];
    let plaintext = b"sealed";

    let ct = cipher
        .encrypt(plaintext, false, Some(&iv), Some(b"good-aad"), false)
        .unwrap();
    let res = cipher.decrypt(&ct[12..], false, Some(&iv), Some(b"bad-aad"), None);
    assert!(res.is_err(), "GCM with wrong AAD must fail");
}

#[test]
fn ecb_with_base64_roundtrip() {
    let cipher = TuyaCipher::new(KEY).unwrap();
    let plaintext = b"with base64 wrapper";

    let ct = cipher.encrypt(plaintext, true, None, None, true).unwrap();
    // Base64 output is ASCII-only.
    assert!(ct.iter().all(|b| b.is_ascii()));

    let pt = cipher.decrypt(&ct, true, None, None, None).unwrap();
    assert_eq!(pt.as_slice(), plaintext);
}

#[test]
fn key_must_be_16_bytes() {
    assert!(TuyaCipher::new(&[0u8; 15]).is_err());
    assert!(TuyaCipher::new(&[0u8; 17]).is_err());
    assert!(TuyaCipher::new(&[0u8; 16]).is_ok());
}
