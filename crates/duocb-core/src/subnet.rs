//! Local IPv4 subnet discovery and host-IP entry validation for the LAN-only
//! join screen.
//!
//! When multicast discovery is blocked the joiner types the host's LAN IPv4 by
//! hand (`crate::lan::unicast`). LAN-only pairing requires both devices on the
//! same network, so that address must fall inside one of *this* device's own
//! private IPv4 subnets. Reading those subnets — address **and netmask**, which
//! iroh's address list doesn't carry — from the OS lets the join UI lock the
//! fixed network octets of the entry, hint the valid range, and reject an
//! out-of-range address before the dial ever starts.
//!
//! The constraint is a join-side affordance only; it never gates the actual
//! dial, which still accepts any well-formed IPv4 (a host on an unusual setup
//! must remain reachable). Loopback (127/8) is always accepted so same-machine
//! testing over `127.0.0.1` works regardless of the detected LAN subnet.

use std::net::Ipv4Addr;

use netdev::ipnet::Ipv4Net;

/// A local private IPv4 subnet the joiner sits on — the network address plus its
/// CIDR prefix length, read from one of this device's network interfaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Subnet(Ipv4Net);

impl Ipv4Subnet {
    /// Whether `ip` falls within this subnet.
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        self.0.contains(&ip)
    }

    /// The leading whole octets fixed by the prefix, as a dotted string ending
    /// in `.`, e.g. `"10.22.33."` for a /24 or `"10.22."` for a /20 — the octets
    /// the join UI locks so the user types only what follows. Empty when the
    /// prefix is shorter than one octet (< /8), where nothing is fully fixed.
    pub fn locked_prefix(&self) -> String {
        let whole = usize::from(self.0.prefix_len() / 8);
        let octets = self.0.network().octets();
        let mut prefix = String::new();
        for octet in &octets[..whole] {
            prefix.push_str(&octet.to_string());
            prefix.push('.');
        }
        prefix
    }

    /// Whether the prefix splits an octet (its length is not a multiple of 8,
    /// e.g. /20 or /28), so the editable tail spans a partial range worth
    /// hinting. For an octet-aligned prefix (/8, /16, /24) every value the user
    /// can type in the tail is in range, so no hint is needed.
    pub fn splits_an_octet(&self) -> bool {
        !self.0.prefix_len().is_multiple_of(8)
    }

    /// The inclusive address span (network .. broadcast) for the hint line — the
    /// full range the typed host address may legitimately land in.
    pub fn range(&self) -> (Ipv4Addr, Ipv4Addr) {
        (self.0.network(), self.0.broadcast())
    }

    /// CIDR label for messages, e.g. `"10.22.33.0/24"`.
    pub fn label(&self) -> String {
        format!("{}/{}", self.0.network(), self.0.prefix_len())
    }
}

/// This device's private IPv4 subnets, the default-route interface first (the
/// most likely LAN when several are present, so its prefix drives the locked
/// entry). Loopback interfaces and non-private addresses (public, 169.254
/// link-local) are excluded; the result is deduplicated.
pub fn local_private_ipv4_subnets() -> Vec<Ipv4Subnet> {
    let default_index = netdev::get_default_interface().ok().map(|iface| iface.index);
    let mut interfaces = netdev::get_interfaces();
    // Default-route interface first; the rest keep their reported order.
    interfaces.sort_by_key(|iface| Some(iface.index) != default_index);

    let mut subnets: Vec<Ipv4Subnet> = Vec::new();
    for iface in interfaces {
        if iface.is_loopback() {
            continue;
        }
        for net in iface.ipv4 {
            if !net.addr().is_private() {
                continue;
            }
            // Normalize to the network address so equal subnets on two aliases
            // of the same interface dedupe.
            let subnet = Ipv4Subnet(net.trunc());
            if !subnets.contains(&subnet) {
                subnets.push(subnet);
            }
        }
    }
    subnets
}

/// The outcome of validating the joiner's typed host-IP entry against the
/// local-subnet constraint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinIpOutcome {
    /// Nothing typed — resolve the host via mDNS instead of the side channel.
    Empty,
    /// A well-formed address within an allowed subnet (or the constraint is
    /// inactive). Carries the full address to dial.
    InRange(Ipv4Addr),
    /// A well-formed IPv4 that falls outside every allowed subnet.
    OutOfRange,
    /// Not a well-formed IPv4 address.
    Malformed,
}

/// The constraint the joiner's host-IP entry is held to: the local private
/// subnets, with the primary (default-route) one driving the locked prefix and
/// the range hint. When no private subnet is detected the constraint is
/// *inactive* — any well-formed IPv4 is accepted, matching an unconstrained
/// free-text entry.
#[derive(Clone, Debug, Default)]
pub struct JoinIpConstraint {
    subnets: Vec<Ipv4Subnet>,
}

impl JoinIpConstraint {
    /// Read the constraint from this device's current interfaces.
    pub fn detect() -> Self {
        Self {
            subnets: local_private_ipv4_subnets(),
        }
    }

    /// An inactive constraint (no subnets) — the default, and what a device with
    /// no private IPv4 subnet resolves to.
    pub fn unconstrained() -> Self {
        Self::default()
    }

    /// Whether a subnet was detected (so the entry is actually constrained).
    pub fn is_active(&self) -> bool {
        !self.subnets.is_empty()
    }

    /// The primary subnet, whose prefix the entry locks to.
    fn primary(&self) -> Option<&Ipv4Subnet> {
        self.subnets.first()
    }

    /// The locked network prefix the user types after, e.g. `"10.22.33."`; empty
    /// when the constraint is inactive (free full-IP entry).
    pub fn locked_prefix(&self) -> String {
        self.primary().map(Ipv4Subnet::locked_prefix).unwrap_or_default()
    }

    /// A "valid range" hint for a partial-octet primary subnet (e.g. a /20),
    /// where not every tail value is in range; empty otherwise.
    pub fn hint(&self) -> String {
        match self.primary() {
            Some(subnet) if subnet.splits_an_octet() => {
                let (lo, hi) = subnet.range();
                format!("Valid range: {lo} – {hi}")
            }
            _ => String::new(),
        }
    }

    /// The primary subnet's CIDR label for the out-of-range message, e.g.
    /// `"10.22.33.0/24"`; empty when inactive.
    pub fn label(&self) -> String {
        self.primary().map(Ipv4Subnet::label).unwrap_or_default()
    }

    /// Validate what the user typed into the (tail) entry. Accepts either a bare
    /// host part appended to the locked prefix (`"15"` → `"10.22.33.15"`) or a
    /// full dotted-quad pasted whole (`"10.22.33.15"`), so copy-pasting the IP
    /// shown on the host works as well as typing just the last octet.
    pub fn resolve(&self, entry: &str) -> JoinIpOutcome {
        let entry = entry.trim();
        if entry.is_empty() {
            return JoinIpOutcome::Empty;
        }
        // A value that already parses as a full IPv4 is taken verbatim (a paste);
        // otherwise it's the host part after the locked network prefix.
        let full = if entry.parse::<Ipv4Addr>().is_ok() {
            entry.to_string()
        } else {
            format!("{}{entry}", self.locked_prefix())
        };
        let Ok(ip) = full.parse::<Ipv4Addr>() else {
            return JoinIpOutcome::Malformed;
        };
        // Loopback is always local; otherwise it must sit in an allowed subnet
        // (or the constraint is inactive).
        if ip.is_loopback() || !self.is_active() || self.subnets.iter().any(|s| s.contains(ip)) {
            JoinIpOutcome::InRange(ip)
        } else {
            JoinIpOutcome::OutOfRange
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subnet(cidr: &str) -> Ipv4Subnet {
        Ipv4Subnet(cidr.parse::<Ipv4Net>().unwrap().trunc())
    }

    fn constraint(cidrs: &[&str]) -> JoinIpConstraint {
        JoinIpConstraint {
            subnets: cidrs.iter().map(|c| subnet(c)).collect(),
        }
    }

    #[test]
    fn locked_prefix_covers_whole_octets_only() {
        assert_eq!(subnet("10.22.33.0/24").locked_prefix(), "10.22.33.");
        assert_eq!(subnet("10.22.32.0/20").locked_prefix(), "10.22.");
        assert_eq!(subnet("192.168.1.0/16").locked_prefix(), "192.168.");
        assert_eq!(subnet("10.0.0.0/8").locked_prefix(), "10.");
    }

    #[test]
    fn splits_an_octet_flags_non_aligned_prefixes() {
        assert!(!subnet("10.22.33.0/24").splits_an_octet());
        assert!(!subnet("10.0.0.0/8").splits_an_octet());
        assert!(subnet("10.22.32.0/20").splits_an_octet());
        assert!(subnet("10.22.33.0/28").splits_an_octet());
    }

    #[test]
    fn range_and_label_describe_the_subnet() {
        let s = subnet("10.22.32.0/20");
        assert_eq!(
            s.range(),
            ("10.22.32.0".parse().unwrap(), "10.22.47.255".parse().unwrap())
        );
        assert_eq!(s.label(), "10.22.32.0/20");
    }

    #[test]
    fn resolve_accepts_the_host_part_after_the_locked_prefix() {
        let c = constraint(&["10.22.33.0/24"]);
        assert_eq!(c.locked_prefix(), "10.22.33.");
        assert_eq!(
            c.resolve("15"),
            JoinIpOutcome::InRange("10.22.33.15".parse().unwrap())
        );
    }

    #[test]
    fn resolve_accepts_a_pasted_full_address_in_range() {
        let c = constraint(&["10.22.33.0/24"]);
        assert_eq!(
            c.resolve("10.22.33.200"),
            JoinIpOutcome::InRange("10.22.33.200".parse().unwrap())
        );
    }

    #[test]
    fn resolve_rejects_out_of_range_for_a_partial_octet_prefix() {
        let c = constraint(&["10.22.32.0/20"]);
        // 10.22.35.x is inside 10.22.32.0/20 (third octet 32..=47).
        assert_eq!(
            c.resolve("35.7"),
            JoinIpOutcome::InRange("10.22.35.7".parse().unwrap())
        );
        // 10.22.60.x is outside it.
        assert_eq!(c.resolve("60.7"), JoinIpOutcome::OutOfRange);
        assert!(c.hint().starts_with("Valid range: 10.22.32.0"));
    }

    #[test]
    fn resolve_accepts_any_of_several_subnets() {
        let c = constraint(&["10.22.33.0/24", "192.168.1.0/24"]);
        // Primary prefix locks to the first subnet, but a pasted full address in
        // any detected subnet is accepted.
        assert!(matches!(
            c.resolve("192.168.1.9"),
            JoinIpOutcome::InRange(_)
        ));
        assert_eq!(c.resolve("172.16.0.1"), JoinIpOutcome::OutOfRange);
    }

    #[test]
    fn resolve_always_accepts_loopback_and_empty_and_malformed() {
        let c = constraint(&["10.22.33.0/24"]);
        assert!(matches!(c.resolve("127.0.0.1"), JoinIpOutcome::InRange(_)));
        assert_eq!(c.resolve("   "), JoinIpOutcome::Empty);
        // A full dotted-quad with a bad octet is malformed, not out-of-range.
        assert_eq!(c.resolve("10.22.33.999"), JoinIpOutcome::Malformed);
    }

    #[test]
    fn inactive_constraint_accepts_any_well_formed_ipv4() {
        let c = JoinIpConstraint::unconstrained();
        assert!(!c.is_active());
        assert_eq!(c.locked_prefix(), "");
        assert_eq!(c.hint(), "");
        assert!(matches!(
            c.resolve("203.0.113.7"),
            JoinIpOutcome::InRange(_)
        ));
        assert_eq!(c.resolve("nope"), JoinIpOutcome::Malformed);
        assert_eq!(c.resolve(""), JoinIpOutcome::Empty);
    }
}
