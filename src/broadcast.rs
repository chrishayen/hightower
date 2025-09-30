use std::net::{IpAddr, SocketAddr};
use std::net::Ipv4Addr;
use socket2::Socket;
use tokio::time;
use std::time::Duration;

use crate::constants::{MDNS_PORT, MDNS_MULTICAST_ADDR};
use crate::packet::{build_mdns_packet, build_goodbye_packet};

/// Continuously broadcast mDNS announcements
pub async fn broadcast_loop(socket: &Socket, name: &str, domain: &str, ip: Ipv4Addr, interval: Duration) {
    let mut interval = time::interval(interval);

    loop {
        interval.tick().await;
        broadcast(socket, name, domain, ip).await;
    }
}

/// Broadcast a single mDNS announcement
async fn broadcast(socket: &Socket, name: &str, domain: &str, ip: Ipv4Addr) {
    let packet = build_mdns_packet(name, domain, ip);
    let addr = SocketAddr::new(IpAddr::V4(MDNS_MULTICAST_ADDR), MDNS_PORT);

    match socket.send_to(&packet, &addr.into()) {
        Ok(_) => log::debug!("Broadcasted mDNS announcement for {}.{}", name, domain),
        Err(e) => log::error!("Failed to send mDNS packet: {}", e),
    }
}

/// Send a goodbye packet (TTL=0) to notify others this host is leaving
pub async fn send_goodbye(socket: &Socket, name: &str, domain: &str, ip: Ipv4Addr) {
    let packet = build_goodbye_packet(name, domain, ip);
    let addr = SocketAddr::new(IpAddr::V4(MDNS_MULTICAST_ADDR), MDNS_PORT);

    match socket.send_to(&packet, &addr.into()) {
        Ok(_) => log::info!("Sent goodbye packet for {}.{}", name, domain),
        Err(e) => log::error!("Failed to send goodbye packet: {}", e),
    }
}