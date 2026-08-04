//! Protocol version, device type, and the per-version **wire profile**.
//!
//! The 0.3 core encoded per-version behaviour as a 15-method trait object with
//! one impl per version (`v31.rs` … `v35.rs`), most of it near-duplicated. Here
//! the parts that are genuinely *data* — which frame, which integrity, whether a
//! session key is negotiated, where the version header sits — live in a single
//! [`Profile`] table (`docs/DESIGN.md`, S7). Only the truly version-specific
//! behaviour (v3.1's md5/base64 wrapping) stays as code, in the payload codec.

/// Tuya local-protocol version. `Auto` is a config placeholder resolved before
/// any wire work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Version {
    #[default]
    Auto,
    V3_1,
    V3_2,
    V3_3,
    V3_4,
    V3_5,
}

impl Version {
    /// Canonical string (`"3.3"`, …; `"auto"` for [`Version::Auto`]).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Version::Auto => "auto",
            Version::V3_1 => "3.1",
            Version::V3_2 => "3.2",
            Version::V3_3 => "3.3",
            Version::V3_4 => "3.4",
            Version::V3_5 => "3.5",
        }
    }

    /// Parses a version string (case-insensitive; `""`/`"auto"` → `Auto`).
    /// Returns `None` for anything unrecognised — the driver maps that to its
    /// own error, keeping config concerns out of [`crate::CoreError`].
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            _ if s.is_empty() || s.eq_ignore_ascii_case("auto") => Version::Auto,
            "3.1" => Version::V3_1,
            "3.2" => Version::V3_2,
            "3.3" => Version::V3_3,
            "3.4" => Version::V3_4,
            "3.5" => Version::V3_5,
            _ => return None,
        })
    }

    /// The 15-byte version header some versions prepend to the payload
    /// (`"3.x"` + 12 zero bytes). Only meaningful where
    /// [`Profile::header`] is not [`HeaderPos::None`].
    ///
    /// [`Auto`](Self::Auto) stamps **v3.3's** header, because that is the
    /// profile it runs (see [`profile`](Self::profile)). Deriving the bytes from
    /// `as_str()` instead made it `"aut"`, which no device sends and none
    /// accepts: an `Auto` device's own pushes stopped being recognised as
    /// headered, so the header was never stripped, the remaining bytes were not
    /// a whole number of AES blocks, and the payload came back to the caller as
    /// raw ciphertext.
    #[must_use]
    pub fn header(self) -> [u8; 15] {
        let mut h = [0u8; 15];
        let wire = match self {
            Version::Auto => Version::V3_3,
            v => v,
        };
        h[..3].copy_from_slice(&wire.as_str().as_bytes()[..3]);
        h
    }

    /// The wire profile for this version (see [`Profile`]). `Auto` falls back to
    /// v3.3, matching the 0.3 dispatch.
    #[must_use]
    pub fn profile(self) -> Profile {
        use HeaderPos::{AfterEncrypt, BeforeEncrypt};
        use Integrity::{Crc32, Hmac};
        match self {
            Version::V3_1 => Profile {
                frame: Frame::F55AA(Crc32),
                payload_enc: PayloadEnc::Ecb,
                header: HeaderPos::None, // v3.1 uses its own md5/base64 scheme
                session_key: false,
            },
            Version::V3_2 | Version::V3_3 | Version::Auto => Profile {
                frame: Frame::F55AA(Crc32),
                payload_enc: PayloadEnc::Ecb,
                header: AfterEncrypt,
                session_key: false,
            },
            Version::V3_4 => Profile {
                frame: Frame::F55AA(Hmac),
                payload_enc: PayloadEnc::Ecb,
                header: BeforeEncrypt,
                session_key: true,
            },
            Version::V3_5 => Profile {
                frame: Frame::F6699,
                payload_enc: PayloadEnc::InFrameGcm,
                header: BeforeEncrypt, // ends up inside the GCM plaintext
                session_key: true,
            },
        }
    }
}

/// Device architecture dialect. `Device22` is a wrapper applied on top of a base
/// version (v3.2 is always Device22); it is orthogonal to [`Version`].
///
/// **No runtime auto-detection (DESIGN P7, a deliberate decision).** There is no
/// agreed algorithm for sniffing a "22-character device id" dialect from the wire
/// — the 0.3 heuristic was not tinytuya-authoritative and is a known-unknown. So
/// the core never guesses: [`Auto`](Self::Auto) behaves as [`Default`](Self::Default)
/// except that **v3.2 is always treated as `Device22`** (the one firm rule, in
/// [`crate::command::generate`]). A caller that knows better sets `Device22`
/// explicitly; any detection policy is an explicit driver decision, never hidden
/// in the core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceType {
    /// No dialect override: same as `Default`, plus the v3.2-is-Device22 rule.
    /// **Not** a request to auto-detect — the core performs no detection.
    #[default]
    Auto,
    /// The standard dialect.
    Default,
    /// The device22 wrapper: `DpQuery` becomes a `ControlNew` with a
    /// `{"1":null}` dps default (status reads DP 1 only, by design).
    Device22,
}

impl DeviceType {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DeviceType::Auto => "auto",
            DeviceType::Default => "default",
            DeviceType::Device22 => "device22",
        }
    }

    /// Parses a device-type string (case-insensitive; `""`/`"auto"` → `Auto`).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            _ if s.is_empty() || s.eq_ignore_ascii_case("auto") => DeviceType::Auto,
            _ if s.eq_ignore_ascii_case("default") => DeviceType::Default,
            _ if s.eq_ignore_ascii_case("device22") => DeviceType::Device22,
            _ => return None,
        })
    }
}

// -- wire profile -----------------------------------------------------------

/// The data-driven wire behaviour of a protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    /// Which on-wire frame format and (for 55AA) its integrity footer.
    pub frame: Frame,
    /// How the payload is encrypted beneath the frame.
    pub payload_enc: PayloadEnc,
    /// Where the version header sits relative to payload encryption.
    pub header: HeaderPos,
    /// Whether a session key must be negotiated (v3.4 / v3.5) before use.
    pub session_key: bool,
}

/// Frame format, carrying the 55AA integrity choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame {
    /// 55AA frame with a CRC-32 or HMAC-SHA256 footer.
    F55AA(Integrity),
    /// 6699 frame; AES-GCM provides both confidentiality and integrity.
    F6699,
}

/// The 55AA integrity footer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Integrity {
    /// CRC-32 (v3.1 / v3.3), no key.
    Crc32,
    /// HMAC-SHA256 keyed by the session key (v3.4).
    Hmac,
}

/// Payload encryption beneath the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadEnc {
    /// AES-128-ECB + PKCS7 (v3.1 / v3.3 / v3.4).
    Ecb,
    /// No separate step — the 6699 frame's GCM encrypts the whole payload (v3.5).
    InFrameGcm,
}

/// Position of the 15-byte version header relative to payload encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderPos {
    /// No version header (v3.1).
    None,
    /// Prepended before encryption — inside the ciphertext (v3.4 ECB, v3.5 GCM).
    BeforeEncrypt,
    /// Prepended after ECB encryption — outside the ciphertext, inside the
    /// frame (v3.3).
    AfterEncrypt,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parse_roundtrip_and_aliases() {
        for v in [
            Version::V3_1,
            Version::V3_2,
            Version::V3_3,
            Version::V3_4,
            Version::V3_5,
        ] {
            assert_eq!(Version::parse(v.as_str()), Some(v));
        }
        assert_eq!(Version::parse(""), Some(Version::Auto));
        assert_eq!(Version::parse("AUTO"), Some(Version::Auto));
        assert_eq!(Version::parse("3.9"), None);
        assert_eq!(Version::parse("nope"), None);
    }

    #[test]
    fn device_type_parse() {
        assert_eq!(DeviceType::parse("DEVICE22"), Some(DeviceType::Device22));
        assert_eq!(DeviceType::parse("default"), Some(DeviceType::Default));
        assert_eq!(DeviceType::parse(""), Some(DeviceType::Auto));
        assert_eq!(DeviceType::parse("device42"), None);
    }

    #[test]
    fn header_is_version_string_plus_zeros() {
        assert_eq!(&Version::V3_4.header(), b"3.4\0\0\0\0\0\0\0\0\0\0\0\0");
    }

    #[test]
    fn profiles_capture_the_version_matrix() {
        // v3.3: 55AA + CRC, ECB, header outside ciphertext, no session key.
        let p = Version::V3_3.profile();
        assert_eq!(p.frame, Frame::F55AA(Integrity::Crc32));
        assert_eq!(p.header, HeaderPos::AfterEncrypt);
        assert!(!p.session_key);

        // v3.4: 55AA + HMAC, ECB, header inside ciphertext, session key.
        let p = Version::V3_4.profile();
        assert_eq!(p.frame, Frame::F55AA(Integrity::Hmac));
        assert_eq!(p.header, HeaderPos::BeforeEncrypt);
        assert!(p.session_key);

        // v3.5: 6699 GCM, no separate payload enc, session key.
        let p = Version::V3_5.profile();
        assert_eq!(p.frame, Frame::F6699);
        assert_eq!(p.payload_enc, PayloadEnc::InFrameGcm);
        assert!(p.session_key);

        // v3.2 mirrors v3.3 on the wire (device22 is orthogonal).
        assert_eq!(Version::V3_2.profile(), Version::V3_3.profile());
    }
}
