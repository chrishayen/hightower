use std::net::Ipv4Addr;

/// The standard mDNS port as defined in RFC 6762
pub const MDNS_PORT: u16 = 5353;

/// The standard mDNS multicast IPv4 address (224.0.0.251) as defined in RFC 6762
pub const MDNS_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);