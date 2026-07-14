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
use core::net::{IpAddr, Ipv4Addr};
use rand_core::RngCore;

use crate::command::CommandType;
use crate::crypto::TuyaCipher;
use crate::frame::{pack_55aa, pack_6699, peek_header, unpack_55aa, unpack_6699, Integrity, PREFIX_55AA, PREFIX_6699};
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

/// Which wire dialect an active probe uses on a given port (SMELLS Q5: a typed
/// descriptor replacing the 0.3 scattered `== 7000` literals).
#[derive(Debug, Clone, Copy)]
enum Dialect {
    /// 55AA / CRC, cmd `UdpNew`, plaintext payload — v3.1/3.3 ports (6666/6667).
    Legacy,
    /// 6699 / GCM under the v3.5 UDP key, cmd `ReqDevInfo` — v3.5 port (7000).
    V35,
}

/// One probe target: a broadcast port and the dialect to speak on it.
#[derive(Debug, Clone, Copy)]
struct Probe {
    port: u16,
    dialect: Dialect,
}

/// The standard Tuya discovery ports and their dialects.
const DEFAULT_PROBES: &[Probe] = &[
    Probe { port: 6666, dialect: Dialect::Legacy },
    Probe { port: 6667, dialect: Dialect::Legacy },
    Probe { port: 7000, dialect: Dialect::V35 },
];

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
    /// Begin (or restart) active broadcast probing: the FSM arms an immediate
    /// broadcast, then re-broadcasts every `broadcast_interval` until the burst
    /// (`broadcast_burst`) is exhausted — or forever if it is `None`.
    StartScan,
    /// Stop active probing; passive receive continues.
    StopScan,
}

/// An event drained by the driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A device seen for the first time, or whose details changed (ip / version /
    /// productKey). Carries the full info — for the discovered bus and address
    /// resolution.
    Found(DeviceInfo),
    /// A device re-announced with **nothing changed** (still the same ip). Carries
    /// only the id: a pure liveness tick the driver routes to a disconnected
    /// device of that id so a **same-IP** reconnect fires the instant the device
    /// reappears, rather than waiting out backoff — without the full-info churn a
    /// `Found` implies (it's TTL-deduped away today). Unregistered ids are ignored.
    Seen(String),
}

/// Discovery configuration (driver-injected policy).
pub struct Config {
    /// How long a cached device is remembered before a re-announcement counts as
    /// "new" again.
    pub cache_ttl: Duration,
    /// Delay between active broadcast rounds (SMELLS Q4: injected, not a
    /// hardcoded 6 s).
    pub broadcast_interval: Duration,
    /// How many broadcast rounds one `StartScan` fires. `None` = broadcast
    /// perpetually (a long-lived controller); `Some(n)` = a bounded scan.
    pub broadcast_burst: Option<u32>,
    /// Local IPv4 addresses stamped into v3.5 probes so devices know where to
    /// reply. **One probe per source**, so a multi-homed host actively elicits
    /// devices across several subnets (SMELLS Q6 — the 0.3 `discovery_sources`).
    /// Selecting them is the driver's job; empty degrades to a single `0.0.0.0`
    /// probe, which some firmware ignores. The driver sends each probe from the
    /// socket bound to the tagged source (see [`poll_transmit`](Discovery::poll_transmit)).
    pub local_ips: Vec<Ipv4Addr>,
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
    /// Outbound probe packets: (bytes, destination port, source IP to send from).
    /// The driver sends each to the local broadcast address on that port, from the
    /// socket bound to the tagged source (`None` = the default/any socket).
    tx: VecDeque<(Vec<u8>, u16, Option<Ipv4Addr>)>,
    /// When the next active broadcast round is due (`None` = not scanning).
    next_broadcast: Option<Instant>,
    /// Broadcast rounds still to fire in the current burst (`None` = perpetual).
    bursts_left: Option<u32>,
}

impl Discovery {
    #[must_use]
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            cache: BTreeMap::new(),
            events: VecDeque::new(),
            tx: VecDeque::new(),
            next_broadcast: None,
            bursts_left: None,
        }
    }

    /// Feeds one input. `rng` supplies the fresh GCM IV for v3.5 probes; passive
    /// receive uses none but the signature is uniform.
    pub fn handle_input(&mut self, input: Input<'_>, now: Instant, rng: &mut impl RngCore) {
        match input {
            Input::Datagram { data, from: _ } => self.on_datagram(data, now),
            Input::StartScan => self.on_start_scan(now, rng),
            Input::StopScan => {
                self.next_broadcast = None;
                self.bursts_left = None;
            }
        }
    }

    /// Fires the broadcast timer: if a round is due, queue a probe per port and
    /// schedule (or end) the next round.
    pub fn handle_timeout(&mut self, now: Instant, rng: &mut impl RngCore) {
        if let Some(next) = self.next_broadcast
            && now >= next
        {
            self.emit_probes(rng);
            let more = match self.bursts_left.as_mut() {
                None => true, // perpetual
                Some(n) => {
                    *n = n.saturating_sub(1);
                    *n > 0
                }
            };
            self.next_broadcast = more.then(|| now.saturating_add(self.cfg.broadcast_interval));
        }
    }

    /// Events for the driver/caller (drain to `None`).
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Outbound probe packets as `(bytes, port, source)` (drain to `None`). The
    /// driver sends each to the broadcast address on that port, from the socket
    /// bound to `source` (`None` = the default socket).
    pub fn poll_transmit(&mut self) -> Option<(Vec<u8>, u16, Option<Ipv4Addr>)> {
        self.tx.pop_front()
    }

    /// The next broadcast deadline the driver should arm a timer for (D2).
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.next_broadcast
    }

    /// Number of devices currently remembered (for diagnostics/tests).
    #[must_use]
    pub fn cached(&self) -> usize {
        self.cache.len()
    }

    // -- internals -----------------------------------------------------------

    fn on_start_scan(&mut self, now: Instant, _rng: &mut impl RngCore) {
        // A zero-count burst would scan nothing; treat it as "don't start".
        if self.cfg.broadcast_burst == Some(0) {
            return;
        }
        self.bursts_left = self.cfg.broadcast_burst;
        self.next_broadcast = Some(now); // first round is immediate
    }

    fn emit_probes(&mut self, rng: &mut impl RngCore) {
        for probe in DEFAULT_PROBES {
            match probe.dialect {
                Dialect::Legacy => {
                    // seqno 0, plaintext + CRC (no key, no source binding).
                    let pkt = pack_55aa(
                        0,
                        CommandType::UdpNew as u32,
                        br#"{"gwId":"","devId":""}"#,
                        Integrity::Crc32,
                    );
                    self.tx.push_back((pkt, probe.port, None));
                }
                Dialect::V35 => {
                    // One probe per configured source (so a multi-homed host
                    // elicits across subnets); no sources → a single 0.0.0.0 probe.
                    if self.cfg.local_ips.is_empty() {
                        if let Some(pkt) = build_v35_probe(None, rng) {
                            self.tx.push_back((pkt, probe.port, None));
                        }
                    } else {
                        for src in self.cfg.local_ips.clone() {
                            if let Some(pkt) = build_v35_probe(Some(src), rng) {
                                self.tx.push_back((pkt, probe.port, Some(src)));
                            }
                        }
                    }
                }
            }
        }
    }

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
        } else {
            // Known & unchanged: not a Found (deduped), but still a liveness tick
            // for the driver to wake a disconnected device of this id (same-IP
            // reconnect, ①).
            self.events.push_back(Event::Seen(info.id));
        }
    }

    fn evict_expired(&mut self, now: Instant) {
        let ttl = self.cfg.cache_ttl;
        self.cache
            .retain(|_, e| now.saturating_duration_since(e.seen) <= ttl);
    }
}

// -- packet decode ----------------------------------------------------------

/// Build one v3.5 (6699/GCM) active probe carrying `src` as the reply address
/// (`0.0.0.0` when `None`). A fresh IV is drawn from the injected RNG.
fn build_v35_probe(src: Option<Ipv4Addr>, rng: &mut impl RngCore) -> Option<Vec<u8>> {
    let ip = src.map_or_else(|| "0.0.0.0".to_string(), |i| i.to_string());
    let payload = alloc::format!(r#"{{"from":"app","ip":"{ip}"}}"#).into_bytes();
    let mut iv = [0u8; 12];
    rng.fill_bytes(&mut iv);
    pack_6699(0, CommandType::ReqDevInfo as u32, &payload, &UDP_KEY_V35, &iv).ok()
}

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

    const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 42));
    const TTL: Duration = Duration::from_secs(60);

    struct SeededRng(u64);
    impl RngCore for SeededRng {
        fn next_u32(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
        fn next_u64(&mut self) -> u64 {
            (u64::from(self.next_u32()) << 32) | u64::from(self.next_u32())
        }
        fn fill_bytes(&mut self, dst: &mut [u8]) {
            for b in dst.iter_mut() {
                *b = self.next_u32() as u8;
            }
        }
    }

    fn disco() -> Discovery {
        Discovery::new(Config {
            cache_ttl: TTL,
            broadcast_interval: Duration::from_secs(6),
            broadcast_burst: Some(3),
            local_ips: vec![Ipv4Addr::new(192, 168, 0, 100)],
        })
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
    fn found_once_then_seen_on_unchanged_reannounce() {
        let mut d = disco();
        let mut rng = SeededRng(1);
        let pkt = packet_6699("dev1", "192.168.0.42");
        let now = Instant::from_millis(0);

        d.handle_input(Input::Datagram { data: &pkt, from: IP }, now, &mut rng);
        assert!(matches!(d.poll_event(), Some(Event::Found(i)) if i.id == "dev1"));
        assert_eq!(d.cached(), 1);

        // Same device, unchanged: not a second Found, but a Seen liveness tick
        // (the driver routes it to wake a disconnected device — ①).
        d.handle_input(Input::Datagram { data: &pkt, from: IP }, now + Duration::from_secs(1), &mut rng);
        assert!(matches!(d.poll_event(), Some(Event::Seen(id)) if id == "dev1"));
        assert!(d.poll_event().is_none());
    }

    #[test]
    fn change_in_ip_re_emits() {
        let mut d = disco();
        let mut rng = SeededRng(1);
        let now = Instant::from_millis(0);
        d.handle_input(Input::Datagram { data: &packet_6699("dev1", "192.168.0.10"), from: IP }, now, &mut rng);
        let _ = d.poll_event();
        // Same id, different ip → a fresh Found.
        d.handle_input(
            Input::Datagram { data: &packet_6699("dev1", "192.168.0.11"), from: IP },
            now + Duration::from_secs(1),
            &mut rng,
        );
        assert!(matches!(d.poll_event(), Some(Event::Found(i)) if i.ip == "192.168.0.11".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn re_announcement_after_ttl_is_fresh_again() {
        let mut d = disco();
        let mut rng = SeededRng(1);
        let pkt = packet_6699("dev1", "192.168.0.42");
        d.handle_input(Input::Datagram { data: &pkt, from: IP }, Instant::from_millis(0), &mut rng);
        let _ = d.poll_event();
        // Past the TTL: the entry is evicted, so the same packet is "new" again.
        let later = Instant::from_millis(0) + TTL + Duration::from_secs(1);
        d.handle_input(Input::Datagram { data: &pkt, from: IP }, later, &mut rng);
        assert!(matches!(d.poll_event(), Some(Event::Found(_))));
    }

    #[test]
    fn garbage_and_malformed_are_ignored() {
        let mut d = disco();
        let mut rng = SeededRng(1);
        let now = Instant::from_millis(0);
        d.handle_input(Input::Datagram { data: &[0, 1, 2, 3], from: IP }, now, &mut rng);
        d.handle_input(Input::Datagram { data: &[0xff; 40], from: IP }, now, &mut rng);
        assert!(d.poll_event().is_none());
        assert_eq!(d.cached(), 0);
    }

    // -- active broadcast (v2) ----------------------------------------------

    /// Drain all queued probe packets, returning (port, decoded DeviceInfo-ok?).
    fn drain_probes(d: &mut Discovery) -> Vec<u16> {
        let mut ports = Vec::new();
        while let Some((_, port, _)) = d.poll_transmit() {
            ports.push(port);
        }
        ports
    }

    #[test]
    fn start_scan_broadcasts_all_ports_immediately() {
        let mut d = disco();
        let mut rng = SeededRng(7);
        let t0 = Instant::from_millis(0);
        d.handle_input(Input::StartScan, t0, &mut rng);
        // First round is due now.
        assert_eq!(d.poll_timeout(), Some(t0));
        d.handle_timeout(t0, &mut rng);
        assert_eq!(drain_probes(&mut d), vec![6666, 6667, 7000]);
    }

    #[test]
    fn probes_are_valid_frames_the_decoder_accepts_shape() {
        // The v3.5 (7000) probe must be a well-formed 6699 frame under the UDP
        // key — i.e. it round-trips through unpack_6699.
        let mut d = disco();
        let mut rng = SeededRng(7);
        d.handle_input(Input::StartScan, Instant::from_millis(0), &mut rng);
        d.handle_timeout(Instant::from_millis(0), &mut rng);
        while let Some((bytes, port, _)) = d.poll_transmit() {
            if port == 7000 {
                let f = unpack_6699(&bytes, &UDP_KEY_V35).unwrap();
                assert!(looks_like_json(&f.body), "v3.5 probe carries JSON: {:?}", f.body);
            } else {
                assert!(unpack_55aa(&bytes, Integrity::Crc32).is_ok(), "legacy probe is 55AA/CRC");
            }
        }
    }

    #[test]
    fn multi_source_emits_one_v35_probe_per_source() {
        // Two source IPs → one v3.5 (7000) probe each, tagged with its source and
        // carrying that source as the reply `ip`; legacy ports stay single.
        let mut d = Discovery::new(Config {
            cache_ttl: TTL,
            broadcast_interval: Duration::from_secs(6),
            broadcast_burst: Some(1),
            local_ips: vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 1, 1)],
        });
        let mut rng = SeededRng(7);
        let t0 = Instant::from_millis(0);
        d.handle_input(Input::StartScan, t0, &mut rng);
        d.handle_timeout(t0, &mut rng);

        let mut v35_sources = Vec::new();
        let mut legacy = 0;
        while let Some((bytes, port, source)) = d.poll_transmit() {
            if port == 7000 {
                // The tagged source is echoed inside the decrypted payload `ip`.
                let body = unpack_6699(&bytes, &UDP_KEY_V35).unwrap().body;
                let ip = source.expect("v3.5 probe tagged with its source");
                assert!(
                    core::str::from_utf8(&body).unwrap().contains(&ip.to_string()),
                    "probe payload carries its source ip"
                );
                v35_sources.push(ip);
            } else {
                assert!(source.is_none(), "legacy probes have no source binding");
                legacy += 1;
            }
        }
        v35_sources.sort();
        assert_eq!(v35_sources, vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 1, 1)]);
        assert_eq!(legacy, 2, "6666 + 6667 legacy probes");
    }

    #[test]
    fn burst_stops_after_configured_rounds() {
        let mut d = disco(); // broadcast_burst = Some(3), interval 6 s
        let mut rng = SeededRng(7);
        let mut t = Instant::from_millis(0);
        d.handle_input(Input::StartScan, t, &mut rng);
        for round in 0..3 {
            assert_eq!(d.poll_timeout(), Some(t), "round {round} due");
            d.handle_timeout(t, &mut rng);
            assert_eq!(drain_probes(&mut d).len(), 3, "round {round} hits 3 ports");
            t = t + Duration::from_secs(6);
        }
        // After 3 rounds the burst is spent: no further deadline, firing is inert.
        assert_eq!(d.poll_timeout(), None);
        d.handle_timeout(t, &mut rng);
        assert!(d.poll_transmit().is_none());
    }

    #[test]
    fn perpetual_burst_never_stops() {
        let mut d = Discovery::new(Config {
            cache_ttl: TTL,
            broadcast_interval: Duration::from_secs(6),
            broadcast_burst: None, // perpetual
            local_ips: Vec::new(),
        });
        let mut rng = SeededRng(7);
        let mut t = Instant::from_millis(0);
        d.handle_input(Input::StartScan, t, &mut rng);
        for _ in 0..10 {
            d.handle_timeout(t, &mut rng);
            let _ = drain_probes(&mut d);
            let next = d.poll_timeout().expect("still scanning");
            assert_eq!(next, t + Duration::from_secs(6));
            t = next;
        }
    }

    #[test]
    fn stop_scan_clears_the_schedule() {
        let mut d = disco();
        let mut rng = SeededRng(7);
        d.handle_input(Input::StartScan, Instant::from_millis(0), &mut rng);
        d.handle_input(Input::StopScan, Instant::from_millis(0), &mut rng);
        assert_eq!(d.poll_timeout(), None);
        d.handle_timeout(Instant::from_millis(0), &mut rng);
        assert!(d.poll_transmit().is_none());
    }

    #[test]
    fn v35_probe_ivs_are_unique_across_rounds() {
        let mut d = Discovery::new(Config {
            cache_ttl: TTL,
            broadcast_interval: Duration::from_secs(6),
            broadcast_burst: None,
            local_ips: vec![Ipv4Addr::new(10, 0, 0, 5)],
        });
        let mut rng = SeededRng(7);
        let mut ivs = Vec::new();
        let mut t = Instant::from_millis(0);
        d.handle_input(Input::StartScan, t, &mut rng);
        for _ in 0..5 {
            d.handle_timeout(t, &mut rng);
            while let Some((bytes, port, _)) = d.poll_transmit() {
                if port == 7000 {
                    ivs.push(bytes[18..30].to_vec()); // 6699 IV
                }
            }
            t = d.poll_timeout().unwrap();
        }
        for i in 0..ivs.len() {
            for j in (i + 1)..ivs.len() {
                assert_ne!(ivs[i], ivs[j], "probe IV reuse ({i},{j})");
            }
        }
    }
}
