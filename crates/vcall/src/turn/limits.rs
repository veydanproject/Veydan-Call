//! What keeps one client, and all of them, from taking the node: a token
//! bucket for bandwidth, and counts per address.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Bytes per second, with a second's worth of burst. A packet that finds
/// the bucket empty is dropped, as a full link would drop it: TURN carries
/// UDP, and UDP is allowed to lose.
pub struct Bucket {
    rate: f64,
    burst: f64,
    state: Mutex<(f64, Instant)>,
}

impl Bucket {
    /// `bytes_per_sec` 0: no limit.
    pub fn new(bytes_per_sec: u64) -> Self {
        let rate = bytes_per_sec as f64;
        Self { rate, burst: rate, state: Mutex::new((rate, Instant::now())) }
    }

    pub fn from_mbps(mbps: u64) -> Self {
        Self::new(mbps * 1_000_000 / 8)
    }

    pub fn from_kbps(kbps: u64) -> Self {
        Self::new(kbps * 1000 / 8)
    }

    /// What the bucket lets through, bytes a second; 0 for no limit.
    pub fn bytes_per_sec(&self) -> u64 {
        self.rate as u64
    }

    /// Takes `n` bytes if they are there.
    pub fn take(&self, n: usize) -> bool {
        if self.rate == 0.0 {
            return true;
        }
        let mut s = self.state.lock().expect("bucket");
        let now = Instant::now();
        let (tokens, last) = *s;
        let tokens = (tokens + now.duration_since(last).as_secs_f64() * self.rate).min(self.burst);
        let n = n as f64;
        if tokens >= n {
            *s = (tokens - n, now);
            true
        } else {
            *s = (tokens, now);
            false
        }
    }
}

/// How many of something each address holds right now.
#[derive(Default)]
pub struct PerIp {
    counts: Mutex<HashMap<IpAddr, u32>>,
}

impl PerIp {
    /// One more for `ip`, unless it has `max` already.
    pub fn acquire(&self, ip: IpAddr, max: u32) -> bool {
        let mut counts = self.counts.lock().expect("per-ip");
        let n = counts.entry(ip).or_insert(0);
        if *n >= max {
            return false;
        }
        *n += 1;
        true
    }

    pub fn release(&self, ip: IpAddr) {
        let mut counts = self.counts.lock().expect("per-ip");
        if let Some(n) = counts.get_mut(&ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                counts.remove(&ip);
            }
        }
    }

    pub fn count(&self, ip: IpAddr) -> u32 {
        self.counts.lock().expect("per-ip").get(&ip).copied().unwrap_or(0)
    }
}

/// How many times something happened from each address in a window:
/// credentials asked, for one.
pub struct RateWindow {
    window: Duration,
    max: u32,
    seen: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl RateWindow {
    pub fn new(window: Duration, max: u32) -> Self {
        Self { window, max, seen: Mutex::new(HashMap::new()) }
    }

    /// Whether the address has used up the allowance of the window already;
    /// nothing is counted.
    pub fn exhausted(&self, ip: IpAddr) -> bool {
        let seen = self.seen.lock().expect("rate");
        seen.get(&ip).is_some_and(|(start, n)| start.elapsed() < self.window && *n >= self.max)
    }

    /// Counts one more and says whether it is within the allowance.
    pub fn allow(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut seen = self.seen.lock().expect("rate");
        // Forgotten addresses are swept when the map grows, so that a scan
        // of the whole internet cannot make it grow without end.
        if seen.len() > 10_000 {
            let window = self.window;
            seen.retain(|_, (start, _)| now.duration_since(*start) < window);
        }
        let entry = seen.entry(ip).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= self.max
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bucket_gives_a_second_of_bytes_then_waits() {
        let b = Bucket::new(1000);
        assert!(b.take(600));
        assert!(b.take(400));
        assert!(!b.take(1), "empty now");
        std::thread::sleep(Duration::from_millis(60));
        assert!(b.take(40), "about 60 bytes came back");
        assert!(!b.take(500));
        assert!(Bucket::new(0).take(usize::MAX / 2), "no limit");
        assert!(!Bucket::new(100).take(101), "more than the burst never fits");
    }

    #[test]
    fn addresses_are_counted() {
        let p = PerIp::default();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(p.acquire(ip, 2));
        assert!(p.acquire(ip, 2));
        assert!(!p.acquire(ip, 2));
        assert_eq!(p.count(ip), 2);
        p.release(ip);
        assert!(p.acquire(ip, 2));
        p.release(ip);
        p.release(ip);
        p.release(ip);
        assert_eq!(p.count(ip), 0);
    }

    #[test]
    fn a_window_allows_so_many() {
        let w = RateWindow::new(Duration::from_secs(60), 3);
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let other: IpAddr = "203.0.113.8".parse().unwrap();
        assert!(w.allow(ip) && w.allow(ip) && w.allow(ip));
        assert!(!w.allow(ip));
        assert!(w.allow(other));
    }
}
