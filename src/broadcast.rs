use std::net::{IpAddr, SocketAddr};
use std::net::Ipv4Addr;
use socket2::Socket;
use tokio::time;
use std::time::Duration;

use crate::constants::{MDNS_PORT, MDNS_MULTICAST_ADDR};
use crate::packet::build_mdns_packet;

/// Continuously broadcast mDNS announcements
pub async fn broadcast_loop(socket: &Socket, name: &str, ip: Ipv4Addr, interval: Duration) {
    let mut interval = time::interval(interval);

    loop {
        interval.tick().await;
        broadcast(socket, name, ip).await;
    }
}

/// Broadcast a single mDNS announcement
async fn broadcast(socket: &Socket, name: &str, ip: Ipv4Addr) {
    let packet = build_mdns_packet(name, ip);
    let addr = SocketAddr::new(IpAddr::V4(MDNS_MULTICAST_ADDR), MDNS_PORT);

    if let Err(e) = socket.send_to(&packet, &addr.into()) {
        eprintln!("Failed to send mDNS packet: {}", e);
    }
}