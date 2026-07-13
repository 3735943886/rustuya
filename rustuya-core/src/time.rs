//! Core-local monotonic time (design decision D3).
//!
//! The core never reads a clock; the driver stamps a monotonic `now` and passes
//! it in. To stay `no_std` (no `std::time`) and driver-agnostic, the core defines
//! its own [`Instant`] / [`Duration`] as plain millisecond newtypes with
//! **saturating** arithmetic — each driver converts from its own clock
//! (`tokio::time::Instant`, `std::time::Instant`, `embassy_time::Instant`) at the
//! boundary. Only *differences* and *ordering* are meaningful, so the epoch is
//! whatever the driver chooses; the core compares and adds, never interprets.

use core::ops::{Add, Sub};

/// A monotonic instant, in milliseconds since a driver-chosen epoch.
///
/// Only comparisons and durations between two `Instant`s are meaningful — the
/// absolute value carries no wall-clock meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(u64);

/// A span of time, in milliseconds. Saturating throughout (no panics on ESP32).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Duration(u64);

impl Instant {
    /// An `Instant` at `millis` past the driver's epoch.
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// Milliseconds since the driver's epoch.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// `self + d`, saturating at `u64::MAX` instead of overflowing.
    #[must_use]
    pub const fn saturating_add(self, d: Duration) -> Self {
        Self(self.0.saturating_add(d.0))
    }

    /// The span from `earlier` to `self`; zero if `earlier` is in the future.
    #[must_use]
    pub const fn saturating_duration_since(self, earlier: Instant) -> Duration {
        Duration(self.0.saturating_sub(earlier.0))
    }
}

impl Duration {
    /// The zero duration.
    pub const ZERO: Duration = Duration(0);

    /// A duration of `millis` milliseconds.
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// A duration of `secs` seconds (saturating).
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs.saturating_mul(1000))
    }

    /// This duration in milliseconds.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// `self * factor`, saturating.
    #[must_use]
    pub const fn saturating_mul(self, factor: u64) -> Self {
        Self(self.0.saturating_mul(factor))
    }

    /// The smaller of two durations.
    #[must_use]
    pub const fn min(self, other: Duration) -> Self {
        if self.0 <= other.0 { self } else { other }
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;
    fn add(self, d: Duration) -> Instant {
        self.saturating_add(d)
    }
}

impl Sub<Instant> for Instant {
    type Output = Duration;
    fn sub(self, earlier: Instant) -> Duration {
        self.saturating_duration_since(earlier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_diff_are_saturating() {
        let t0 = Instant::from_millis(1_000);
        let t1 = t0 + Duration::from_secs(2);
        assert_eq!(t1.as_millis(), 3_000);
        assert_eq!((t1 - t0), Duration::from_millis(2_000));
        // earlier-in-future clamps to zero, never underflows
        assert_eq!((t0 - t1), Duration::ZERO);
        // overflow clamps instead of panicking
        assert_eq!(Instant::from_millis(u64::MAX) + Duration::from_millis(5), Instant::from_millis(u64::MAX));
    }

    #[test]
    fn duration_helpers() {
        assert_eq!(Duration::from_secs(1), Duration::from_millis(1000));
        assert_eq!(Duration::from_millis(10).saturating_mul(3), Duration::from_millis(30));
        assert_eq!(Duration::from_millis(u64::MAX).saturating_mul(2), Duration::from_millis(u64::MAX));
        assert_eq!(Duration::from_millis(5).min(Duration::from_millis(9)), Duration::from_millis(5));
    }
}
