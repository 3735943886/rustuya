//! LAN device discovery — the sans-I/O counterpart to [`crate::device`].
//!
//! Tuya devices announce themselves with periodic UDP broadcasts (and answer
//! active broadcast probes) on well-known ports. This module is the pure state
//! machine for that: the driver owns the UDP sockets and feeds each received
//! datagram in via [`Discovery::handle_input`]; the core decrypts/parses it
//! (reusing [`crate::frame`] + [`crate::crypto`]) and emits [`Event::Found`] for
//! each newly-seen or changed device, deduplicated by a TTL cache.
//!
//! **v1: passive receive + dedup only.** Active broadcast probing (outbound
//! packets on a cadence, [`poll_transmit`](Discovery::poll_transmit) /
//! [`poll_timeout`](Discovery::poll_timeout)) is a later increment.
//!
//! Datagrams are datagrams: unlike TCP there is no reassembly — one packet is
//! one frame — so this FSM is markedly simpler than the connection FSM.
//!
//! Naming note: this replaces the 0.3 tinytuya-derived `scanner` (and its
//! process-wide `OnceLock` singleton) with an owned, single-instance FSM.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::net::IpAddr;

use crate::crypto::TuyaCipher;
use crate::frame::{peek_header, unpack_55aa, unpack_6699, Integrity, PREFIX_55AA, PREFIX_6699};
use crate::json;
use crate::time::{Duration, Instant};
use crate::version::Version;

/// The v3.4/v3.5 UDP discovery key: `md5("yGAdlopoPVldABfn")`. The provenance is
/// pinned by the `udp_key_v35_is_md5_of_the_known_string` test below — the 0.3
/// code stored these bytes as an undocumented literal (a smell).
const UDP_KEY_V35: [u8; 16] = [
    0x6c, 0x1e, 0xc8, 0xe2, 0xbb, 0x9b, 0xb5, 0x9a, 0xb5, 0x0b, 0x0d, 0xaf, 0x64, 0x9b, 0x41, 0x0a,
];

/// The v3.3 UDP discovery key — a plain ASCII key, **not** md5-derived.
const UDP_KEY_V33: &[u8; 16] = b"yG9shRKIBrIBUjc3";

/// A device that announced itself on the LAN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    /// `gwId` / `devId` / `id` from the broadcast — the device identity.
    pub id: String,
    /// The device's LAN address (its self-reported `ip`).
    pub ip: IpAddr,
    /// Protocol version, if the broadcast declared one.
    pub version: Option<Version>,
    /// `productKey`, if present.
    pub product_key: Option<String>,
}

/// An input pushed into the discovery FSM by the driver.
pub enum Input<'a> {
    /// One UDP datagram the driver read, with its source address.
    Datagram { data: &'a [u8], from: IpAddr },
}

/// An event drained by the driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A device seen for the first time, or whose details changed.
    Found(DeviceInfo),
}

/// Discovery configuration (driver-injected policy).
pub struct Config {
    /// How long a cached device is remembered before a re-announcement counts as
    /// "new" again.
    pub cache_ttl: Duration,
}

struct CacheEntry {
    ip: IpAddr,
    version: Option<Version>,
    product_key: Option<String>,
    seen: Instant,
}

impl CacheEntry {
    fn matches(&self, info: &DeviceInfo) -> bool {
        self.ip == info.ip && self.version == info.version && self.product_key == info.product_key
    }
}

/// The pure discovery state machine.
pub struct Discovery {
    cfg: Config,
    cache: BTreeMap<String, CacheEntry>,
    events: VecDeque<Event>,
}

impl Discovery {
    #[must_use]
    pub fn new(cfg: Config) -> Self {
        Self { cfg, cache: BTreeMap::new(), events: VecDeque::new() }
    }

    /// Feeds one input; queues a [`Event::Found`] for a new/changed device.
    pub fn handle_input(&mut self, input: Input<'_>, now: Instant) {
        match input {
            Input::Datagram { data, from: _ } => self.on_datagram(data, now),
        }
    }

    /// Events for the driver/caller (drain to `None`).
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Number of devices currently remembered (for diagnostics/tests).
    #[must_use]
    pub fn cached(&self) -> usize {
        self.cache.len()
    }

    // -- internals -----------------------------------------------------------

    fn on_datagram(&mut self, data: &[u8], now: Instant) {
        // Undecodable packets (noise, unknown dialects) are silently ignored —
        // discovery is best-effort.
        let Some(info) = decode(data) else { return };

        self.evict_expired(now);

        let fresh = match self.cache.get(&info.id) {
            Some(entry) if entry.matches(&info) => false, // known & unchanged
            _ => true,
        };
        self.cache.insert(
            info.id.clone(),
            CacheEntry {
                ip: info.ip,
                version: info.version,
                product_key: info.product_key.clone(),
                seen: now,
            },
        );
        if fresh {
            self.events.push_back(Event::Found(info));
        }
    }

    fn evict_expired(&mut self, now: Instant) {
        let ttl = self.cfg.cache_ttl;
        self.cache
            .retain(|_, e| now.saturating_duration_since(e.seen) <= ttl);
    }
}

// -- packet decode ----------------------------------------------------------

/// Decrypt + parse a discovery datagram into a [`DeviceInfo`], or `None` if it
/// isn't a recognizable announcement.
///
/// Like dev22 detection, the exact per-version discovery encoding is not cleanly
/// self-describing; this is a **structured, bounded** decode (6699/GCM, then
/// 55AA plaintext / ECB with an optional version-header strip), not the 0.3
/// open-ended brute force. It is validated against self-crafted packets only —
/// not authoritative against every real firmware.
fn decode(data: &[u8]) -> Option<DeviceInfo> {
    let header = peek_header(data).ok()??;
    let body = match header.prefix {
        // v3.5: 6699 frame, GCM under the v3.5 UDP key; body is plaintext JSON.
        PREFIX_6699 => unpack_6699(data, &UDP_KEY_V35).ok()?.body,
        // v3.1/3.3: 55AA/CRC frame; body is plaintext or ECB-encrypted JSON.
        PREFIX_55AA => {
            let raw = unpack_55aa(data, Integrity::Crc32).ok()?.body;
            decode_55aa_body(&raw)?
        }
        _ => return None,
    };
    parse_json(&body)
}

/// Recover JSON bytes from a 55AA discovery body: plaintext, or AES-ECB under a
/// UDP key, each also tried after stripping a leading 15-byte version header.
fn decode_55aa_body(raw: &[u8]) -> Option<Vec<u8>> {
    for candidate in [raw, strip_version_header(raw)] {
        if looks_like_json(candidate) {
            return Some(candidate.to_vec());
        }
        for key in [UDP_KEY_V33.as_slice(), UDP_KEY_V35.as_slice()] {
            if let Ok(cipher) = TuyaCipher::new(key)
                && let Ok(pt) = cipher.ecb_decrypt(candidate)
                && looks_like_json(&pt)
            {
                return Some(pt);
            }
        }
    }
    None
}

/// If `raw` begins with a `"3.x"` version header, return the bytes after the
/// 15-byte header; otherwise `raw` unchanged.
fn strip_version_header(raw: &[u8]) -> &[u8] {
    if raw.len() > 15 && raw[0] == b'3' && raw[1] == b'.' {
        &raw[15..]
    } else {
        raw
    }
}

/// Cheap "is this a JSON object" check: first non-space byte is `{`.
fn looks_like_json(b: &[u8]) -> bool {
    matches!(b.iter().find(|c| !c.is_ascii_whitespace()), Some(b'{'))
}

fn parse_json(body: &[u8]) -> Option<DeviceInfo> {
    let value = json::from_bytes(body)?;
    let obj = value.as_object()?;
    let id = obj
        .get("gwId")
        .or_else(|| obj.get("devId"))
        .or_else(|| obj.get("id"))?
        .as_str()?
        .to_string();
    let ip = obj.get("ip")?.as_str()?.parse::<IpAddr>().ok()?;
    let version = obj.get("version").and_then(|v| v.as_str()).and_then(Version::parse);
    let product_key = obj.get("productKey").and_then(|v| v.as_str()).map(ToString::to_string);
    Some(DeviceInfo { id, ip, version, product_key })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{pack_55aa, pack_6699};
    use alloc::vec;

    const IP: IpAddr = IpAddr::V4(core::net::Ipv4Addr::new(192, 168, 0, 42));
    const TTL: Duration = Duration::from_secs(60);

    fn disco() -> Discovery {
        Discovery::new(Config { cache_ttl: TTL })
    }

    fn json_bytes(id: &str, ip: &str, version: &str) -> Vec<u8> {
        let s = alloc::format!(r#"{{"gwId":"{id}","ip":"{ip}","version":"{version}","productKey":"pk"}}"#);
        s.into_bytes()
    }

    /// A plaintext v3.1-style 55AA discovery packet (port 6666 dialect).
    fn packet_55aa_plain(id: &str, ip: &str) -> Vec<u8> {
        pack_55aa(0, 0x13, &json_bytes(id, ip, "3.1"), Integrity::Crc32)
    }

    /// An ECB-encrypted v3.3-style 55AA discovery packet (port 6667 dialect).
    fn packet_55aa_ecb(id: &str, ip: &str) -> Vec<u8> {
        let cipher = TuyaCipher::new(UDP_KEY_V33).unwrap();
        let ct = cipher.ecb_encrypt(&json_bytes(id, ip, "3.3")).unwrap();
        pack_55aa(0, 0x13, &ct, Integrity::Crc32)
    }

    /// A v3.5 6699/GCM discovery packet (port 7000 dialect).
    fn packet_6699(id: &str, ip: &str) -> Vec<u8> {
        pack_6699(0, 0x25, &json_bytes(id, ip, "3.5"), &UDP_KEY_V35, &[9u8; 12]).unwrap()
    }

    #[test]
    fn udp_key_v35_is_md5_of_the_known_string() {
        use md5::{Digest, Md5};
        let mut h = Md5::new();
        h.update(b"yGAdlopoPVldABfn");
        assert_eq!(<[u8; 16]>::from(h.finalize()), UDP_KEY_V35);
    }

    #[test]
    fn decodes_all_three_dialects() {
        assert!(decode(&packet_55aa_plain("aa", "192.168.0.1")).is_some());
        assert!(decode(&packet_55aa_ecb("bb", "192.168.0.2")).is_some());
        let info = decode(&packet_6699("cc", "192.168.0.3")).unwrap();
        assert_eq!(info.id, "cc");
        assert_eq!(info.ip, "192.168.0.3".parse::<IpAddr>().unwrap());
        assert_eq!(info.version, Some(Version::V3_5));
        assert_eq!(info.product_key.as_deref(), Some("pk"));
    }

    #[test]
    fn found_emitted_once_then_deduped() {
        let mut d = disco();
        let pkt = packet_6699("dev1", "192.168.0.42");
        let now = Instant::from_millis(0);

        d.handle_input(Input::Datagram { data: &pkt, from: IP }, now);
        assert!(matches!(d.poll_event(), Some(Event::Found(i)) if i.id == "dev1"));
        assert_eq!(d.cached(), 1);

        // Same device, unchanged: no second Found.
        d.handle_input(Input::Datagram { data: &pkt, from: IP }, now + Duration::from_secs(1));
        assert!(d.poll_event().is_none());
    }

    #[test]
    fn change_in_ip_re_emits() {
        let mut d = disco();
        let now = Instant::from_millis(0);
        d.handle_input(Input::Datagram { data: &packet_6699("dev1", "192.168.0.10"), from: IP }, now);
        let _ = d.poll_event();
        // Same id, different ip → a fresh Found.
        d.handle_input(
            Input::Datagram { data: &packet_6699("dev1", "192.168.0.11"), from: IP },
            now + Duration::from_secs(1),
        );
        assert!(matches!(d.poll_event(), Some(Event::Found(i)) if i.ip == "192.168.0.11".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn re_announcement_after_ttl_is_fresh_again() {
        let mut d = disco();
        let pkt = packet_6699("dev1", "192.168.0.42");
        d.handle_input(Input::Datagram { data: &pkt, from: IP }, Instant::from_millis(0));
        let _ = d.poll_event();
        // Past the TTL: the entry is evicted, so the same packet is "new" again.
        let later = Instant::from_millis(0) + TTL + Duration::from_secs(1);
        d.handle_input(Input::Datagram { data: &pkt, from: IP }, later);
        assert!(matches!(d.poll_event(), Some(Event::Found(_))));
    }

    #[test]
    fn garbage_and_malformed_are_ignored() {
        let mut d = disco();
        let now = Instant::from_millis(0);
        d.handle_input(Input::Datagram { data: &[0, 1, 2, 3], from: IP }, now);
        d.handle_input(Input::Datagram { data: &vec![0xff; 40], from: IP }, now);
        assert!(d.poll_event().is_none());
        assert_eq!(d.cached(), 0);
    }
}
