//! Where TURN may send: public addresses, and nothing else.
//!
//! A TURN relay sends UDP wherever its client asks. Without this check a
//! volunteer's node would be a door into the network it stands in: the
//! client names 10.0.0.5 or 127.0.0.1 as its peer, and the node delivers.
//! So every peer address, in CreatePermission, ChannelBind and Send, must
//! be a public unicast address, and not the node's own, except at a relay
//! port that an allocation holds right now: two clients of the same node
//! reach each other through them. Any other port of the node's own
//! address is a service of the machine (WireGuard, mosh, whatever listens
//! in the range), reached over the loopback interface where a firewall
//! lets everything through, so it is refused whether or not the port is
//! in `VCALL_RELAY_PORTS`.
//!
//! Which addresses are the node's own is not a list alone: the public
//! address and the listening addresses are known, a second address of the
//! same machine is not. So an address is also tried with a bind: what the
//! machine can bind to is its own. The answer is remembered per address,
//! in a bounded cache, because Send asks on every packet.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;

/// How many addresses the own-or-not cache remembers before it forgets
/// them all: a client names at most a few peers, an attacker many.
const LOCAL_CACHE: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Forbidden {
    Unspecified,
    Loopback,
    Private,
    LinkLocal,
    Multicast,
    Broadcast,
    Reserved,
    /// The node itself, at a port that is not a relay port of a live allocation.
    OwnAddress,
    /// Port 0, where the port is used.
    NoPort,
}

impl std::fmt::Display for Forbidden {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unspecified => "unspecified address",
            Self::Loopback => "loopback address",
            Self::Private => "private address",
            Self::LinkLocal => "link-local address",
            Self::Multicast => "multicast address",
            Self::Broadcast => "broadcast address",
            Self::Reserved => "reserved address",
            Self::OwnAddress => "the node's own address",
            Self::NoPort => "port 0",
        })
    }
}

/// What the port of a peer address means in the request at hand.
#[derive(Clone, Copy)]
pub enum Port<'a> {
    /// CreatePermission: a permission is for an address, the port is not
    /// looked at (RFC 8656 9.1), 0 included. The node's own address passes
    /// here: whether a packet may go there is decided where it is sent.
    Ignored,
    /// Send, ChannelBind: packets go to this port. The node's own address
    /// only at one of these, the relay ports of live allocations.
    Used { live_relay_ports: &'a HashSet<u16> },
}

pub struct PeerPolicy {
    /// The node's own addresses as far as it knows: the public one, and
    /// whatever it listens on. Others of the machine are found by `is_own`.
    pub own: Vec<IpAddr>,
    /// Loopback, private and own addresses allowed: for tests on one
    /// machine only. A node on the internet with this set relays into the
    /// network behind it.
    pub allow_private: bool,
    /// Addresses tried with a bind, and whether the machine has them.
    local: Mutex<HashMap<IpAddr, bool>>,
}

impl PeerPolicy {
    pub fn new(own: Vec<IpAddr>, allow_private: bool) -> Self {
        Self { own, allow_private, local: Mutex::new(HashMap::new()) }
    }

    pub fn check(&self, peer: SocketAddr, port: Port<'_>) -> Result<(), Forbidden> {
        let ip = canonical(peer.ip());
        match ip {
            IpAddr::V4(v4) => check_v4(v4, self.allow_private)?,
            IpAddr::V6(v6) => check_v6(v6, self.allow_private)?,
        }
        match port {
            Port::Ignored => Ok(()),
            Port::Used { live_relay_ports } => {
                if peer.port() == 0 {
                    return Err(Forbidden::NoPort);
                }
                if !self.allow_private && !live_relay_ports.contains(&peer.port()) && self.is_own(ip) {
                    return Err(Forbidden::OwnAddress);
                }
                Ok(())
            }
        }
    }

    /// Is `ip` an address of this machine? The known ones, or whatever a
    /// socket can be bound to.
    pub fn is_own(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        if self.own.contains(&ip) {
            return true;
        }
        let mut local = self.local.lock().expect("local");
        if let Some(known) = local.get(&ip) {
            return *known;
        }
        let own = std::net::UdpSocket::bind(SocketAddr::new(ip, 0)).is_ok();
        if local.len() >= LOCAL_CACHE {
            local.clear();
        }
        local.insert(ip, own);
        own
    }
}

/// `::ffff:a.b.c.d` is a.b.c.d, and judged as such.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

fn check_v4(ip: Ipv4Addr, allow_private: bool) -> Result<(), Forbidden> {
    let [a, b, c, _] = ip.octets();
    if ip.is_broadcast() {
        return Err(Forbidden::Broadcast);
    }
    if ip.is_multicast() {
        return Err(Forbidden::Multicast);
    }
    if a == 0 {
        return Err(Forbidden::Unspecified);
    }
    if a >= 240 {
        return Err(Forbidden::Reserved);
    }
    // 192.0.0.0/24 IETF protocol assignments (DS-Lite among them),
    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 documentation,
    // 192.88.99.0/24 the old 6to4 anycast, 198.18.0.0/15 benchmarking:
    // nothing on the internet answers there, and the benchmarking range is
    // used as a private one by hosters and VPNs.
    if (a == 192 && b == 0 && (c == 0 || c == 2)) || (a == 198 && b == 51 && c == 100) || (a == 203 && b == 0 && c == 113) {
        return Err(Forbidden::Reserved);
    }
    if (a == 192 && b == 88 && c == 99) || (a == 198 && (b == 18 || b == 19)) {
        return Err(Forbidden::Reserved);
    }
    if allow_private {
        return Ok(());
    }
    if ip.is_loopback() {
        return Err(Forbidden::Loopback);
    }
    if ip.is_link_local() {
        return Err(Forbidden::LinkLocal);
    }
    // RFC 1918, and the carrier-grade NAT range 100.64.0.0/10 (RFC 6598),
    // which is as private from the outside.
    if ip.is_private() || (a == 100 && (64..=127).contains(&b)) {
        return Err(Forbidden::Private);
    }
    Ok(())
}

fn check_v6(ip: Ipv6Addr, allow_private: bool) -> Result<(), Forbidden> {
    let s = ip.segments();
    let v4_in = |hi: u16, lo: u16| Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8);
    if ip.is_unspecified() {
        return Err(Forbidden::Unspecified);
    }
    if ip.is_multicast() {
        return Err(Forbidden::Multicast);
    }
    // 100::/64 discards.
    if s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0 {
        return Err(Forbidden::Reserved);
    }
    // Every way an IPv4 address hides in an IPv6 one is judged by the IPv4
    // address: ::ffff:0:0/96 (v4-mapped), ::ffff:0:0:0/96 (the old SIIT),
    // ::/96 (the deprecated v4-compatible, ::1 aside), 64:ff9b::/96
    // (NAT64), 2002::/16 (6to4). Without this, [::10.0.0.1] would be a
    // public IPv6 address to a relay with IPv6.
    if s[..5] == [0, 0, 0, 0, 0] && s[5] == 0xffff {
        return check_v4(v4_in(s[6], s[7]), allow_private);
    }
    if s[..4] == [0, 0, 0, 0] && s[4] == 0xffff && s[5] == 0 {
        return check_v4(v4_in(s[6], s[7]), allow_private);
    }
    if s[..6] == [0, 0, 0, 0, 0, 0] && !ip.is_loopback() {
        return check_v4(v4_in(s[6], s[7]), allow_private);
    }
    if s[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
        return check_v4(v4_in(s[6], s[7]), allow_private);
    }
    if s[0] == 0x2002 {
        return check_v4(v4_in(s[1], s[2]), allow_private);
    }
    if allow_private {
        return Ok(());
    }
    if ip.is_loopback() {
        return Err(Forbidden::Loopback);
    }
    // fe80::/10 link-local, fec0::/10 the old site-local.
    if s[0] & 0xffc0 == 0xfe80 || s[0] & 0xffc0 == 0xfec0 {
        return Err(Forbidden::LinkLocal);
    }
    // fc00::/7 unique local.
    if s[0] & 0xfe00 == 0xfc00 {
        return Err(Forbidden::Private);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> PeerPolicy {
        PeerPolicy::new(vec!["11.22.33.7".parse().unwrap(), "2001:db8::7".parse().unwrap()], false)
    }

    /// The port used, with 50000 the one live relay port.
    fn check(addr: &str) -> Result<(), Forbidden> {
        let live: HashSet<u16> = [50000].into_iter().collect();
        policy().check(addr.parse().unwrap(), Port::Used { live_relay_ports: &live })
    }

    fn permission(addr: &str) -> Result<(), Forbidden> {
        policy().check(addr.parse().unwrap(), Port::Ignored)
    }

    #[test]
    fn public_addresses_pass() {
        for addr in ["93.184.216.34:40000", "8.8.8.8:53", "1.1.1.1:1", "[2001:db8::1]:5000", "[2a00:1450:4001::1]:443"] {
            assert_eq!(check(addr), Ok(()), "{addr}");
        }
    }

    #[test]
    fn the_inside_of_the_network_is_refused() {
        assert_eq!(check("127.0.0.1:3478"), Err(Forbidden::Loopback));
        assert_eq!(check("127.5.5.5:1"), Err(Forbidden::Loopback));
        assert_eq!(check("10.0.0.1:53"), Err(Forbidden::Private));
        assert_eq!(check("10.255.255.255:53"), Err(Forbidden::Private));
        assert_eq!(check("172.16.0.1:53"), Err(Forbidden::Private));
        assert_eq!(check("172.31.255.1:53"), Err(Forbidden::Private));
        assert_eq!(check("192.168.1.1:80"), Err(Forbidden::Private));
        assert_eq!(check("100.64.0.1:80"), Err(Forbidden::Private));
        assert_eq!(check("100.127.255.255:80"), Err(Forbidden::Private));
        assert_eq!(check("169.254.169.254:80"), Err(Forbidden::LinkLocal), "the cloud metadata address");
        assert_eq!(check("224.0.0.1:5000"), Err(Forbidden::Multicast));
        assert_eq!(check("255.255.255.255:5000"), Err(Forbidden::Broadcast));
        assert_eq!(check("0.0.0.0:5000"), Err(Forbidden::Unspecified));
        assert_eq!(check("0.1.2.3:5000"), Err(Forbidden::Unspecified));
        assert_eq!(check("240.0.0.1:5000"), Err(Forbidden::Reserved));
        assert_eq!(check("8.8.8.8:0"), Err(Forbidden::NoPort));
        // Neighbours of the ranges stay public.
        assert_eq!(check("172.32.0.1:53"), Ok(()));
        assert_eq!(check("100.128.0.1:53"), Ok(()));
        assert_eq!(check("11.0.0.1:53"), Ok(()));
    }

    #[test]
    fn special_use_ranges_are_refused() {
        for addr in [
            "192.0.0.1:53",      // IETF protocol assignments
            "192.0.0.9:53",      // DS-Lite
            "192.0.2.1:53",      // documentation
            "198.51.100.5:53",   // documentation
            "203.0.113.9:53",    // documentation
            "192.88.99.1:53",    // 6to4 anycast
            "198.18.5.5:53",     // benchmarking
            "198.19.255.255:53", // benchmarking
        ] {
            assert_eq!(check(addr), Err(Forbidden::Reserved), "{addr}");
        }
        // Their neighbours are public.
        for addr in ["192.0.1.1:53", "192.0.3.1:53", "198.51.101.1:53", "203.0.114.1:53", "192.88.100.1:53", "198.17.255.255:53", "198.20.0.1:53"] {
            assert_eq!(check(addr), Ok(()), "{addr}");
        }
    }

    #[test]
    fn ipv6_and_its_disguises() {
        assert_eq!(check("[::1]:5000"), Err(Forbidden::Loopback));
        assert_eq!(check("[::]:5000"), Err(Forbidden::Unspecified));
        assert_eq!(check("[fe80::1]:5000"), Err(Forbidden::LinkLocal));
        assert_eq!(check("[fec0::1]:5000"), Err(Forbidden::LinkLocal));
        assert_eq!(check("[fc00::1]:5000"), Err(Forbidden::Private));
        assert_eq!(check("[fd12:3456::1]:5000"), Err(Forbidden::Private));
        assert_eq!(check("[ff02::1]:5000"), Err(Forbidden::Multicast));
        assert_eq!(check("[100::1]:5000"), Err(Forbidden::Reserved));
        assert_eq!(check("[::ffff:10.0.0.1]:5000"), Err(Forbidden::Private), "v4-mapped");
        assert_eq!(check("[::ffff:127.0.0.1]:5000"), Err(Forbidden::Loopback));
        assert_eq!(check("[64:ff9b::a00:1]:5000"), Err(Forbidden::Private), "NAT64");
        assert_eq!(check("[2002:a00:1::1]:5000"), Err(Forbidden::Private), "6to4");
        assert_eq!(check("[::ffff:8.8.8.8]:5000"), Ok(()));
        // The v4-compatible and SIIT forms carry an IPv4 address too.
        assert_eq!(check("[::10.0.0.1]:5000"), Err(Forbidden::Private), "v4-compatible");
        assert_eq!(check("[::a00:1]:5000"), Err(Forbidden::Private), "v4-compatible, in hex");
        assert_eq!(check("[::127.0.0.1]:5000"), Err(Forbidden::Loopback));
        assert_eq!(check("[::8.8.8.8]:5000"), Ok(()));
        assert_eq!(check("[::ffff:0:10.0.0.1]:5000"), Err(Forbidden::Private), "SIIT");
        assert_eq!(check("[::ffff:0:a00:1]:5000"), Err(Forbidden::Private), "SIIT, in hex");
        assert_eq!(check("[::ffff:0:8.8.8.8]:5000"), Ok(()));
        // Below check_v6 the same forms are judged as the IPv4 address too.
        assert_eq!(check_v6("::10.0.0.1".parse().unwrap(), false), Err(Forbidden::Private));
        assert_eq!(check_v6("::ffff:10.0.0.1".parse().unwrap(), false), Err(Forbidden::Private));
        assert_eq!(check_v6("::ffff:0:10.0.0.1".parse().unwrap(), false), Err(Forbidden::Private));
        assert_eq!(check_v6("::1".parse().unwrap(), false), Err(Forbidden::Loopback));
    }

    #[test]
    fn the_node_itself_only_at_live_relay_ports() {
        assert_eq!(check("11.22.33.7:443"), Err(Forbidden::OwnAddress));
        assert_eq!(check("11.22.33.7:3478"), Err(Forbidden::OwnAddress));
        assert_eq!(check("11.22.33.7:22"), Err(Forbidden::OwnAddress));
        // In the relay range, but no allocation holds it: a service of the machine.
        assert_eq!(check("11.22.33.7:51820"), Err(Forbidden::OwnAddress), "WireGuard");
        assert_eq!(check("11.22.33.7:60001"), Err(Forbidden::OwnAddress), "mosh");
        assert_eq!(check("11.22.33.7:50000"), Ok(()), "a live relay port");
        assert_eq!(check("[2001:db8::7]:22"), Err(Forbidden::OwnAddress));
        assert_eq!(check("[::ffff:11.22.33.7]:22"), Err(Forbidden::OwnAddress));
        // A permission is for the address: it may name the node, so that
        // two clients of one node reach each other through its relay.
        assert_eq!(permission("11.22.33.7:22"), Ok(()));
        assert_eq!(permission("11.22.33.7:0"), Ok(()), "port 0 is not looked at");
        assert_eq!(permission("10.0.0.1:0"), Err(Forbidden::Private), "the address still is");
    }

    #[test]
    fn addresses_of_this_machine_are_found_by_a_bind() {
        let p = policy();
        // Loopback is bindable on every machine; a documentation address is not.
        assert!(p.is_own("127.0.0.1".parse().unwrap()));
        assert!(!p.is_own("192.0.2.1".parse().unwrap()));
        assert!(p.is_own("11.22.33.7".parse().unwrap()), "known without a bind");
        assert!(p.is_own("::ffff:11.22.33.7".parse().unwrap()));
        // Remembered: the second answer is the same.
        assert!(!p.is_own("192.0.2.1".parse().unwrap()));
        assert_eq!(p.local.lock().unwrap().len(), 2);
    }

    #[test]
    fn tests_on_one_machine_may_allow_the_inside() {
        let p = PeerPolicy::new(vec!["11.22.33.7".parse().unwrap()], true);
        let live = HashSet::new();
        let used = Port::Used { live_relay_ports: &live };
        assert_eq!(p.check("127.0.0.1:5000".parse().unwrap(), used), Ok(()));
        assert_eq!(p.check("10.0.0.1:5000".parse().unwrap(), used), Ok(()));
        assert_eq!(p.check("11.22.33.7:22".parse().unwrap(), used), Ok(()));
        assert_eq!(p.check("224.0.0.1:5000".parse().unwrap(), used), Err(Forbidden::Multicast));
        assert_eq!(p.check("0.0.0.0:5000".parse().unwrap(), used), Err(Forbidden::Unspecified));
        assert_eq!(p.check("127.0.0.1:0".parse().unwrap(), used), Err(Forbidden::NoPort));
        assert_eq!(p.check("127.0.0.1:0".parse().unwrap(), Port::Ignored), Ok(()));
    }
}
