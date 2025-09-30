use std::net::Ipv4Addr;

pub const MDNS_PORT: u16 = 5353;
pub const MDNS_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);