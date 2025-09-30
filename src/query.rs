use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use socket2::Socket;

use crate::constants::{MDNS_PORT, MDNS_MULTICAST_ADDR};
use crate::packet::{build_mdns_packet, build_mdns_query, parse_mdns_query, parse_mdns_response};
use crate::{HostDiscoveryCallback, QueryResponseCallback};

/// Send a query for a specific hostname
///
/// # Arguments
///
/// * `socket` - The socket to send the query on
/// * `hostname` - The hostname to query (without domain suffix)
/// * `domain` - The domain to use
pub async fn query(socket: &Socket, hostname: &str, domain: &str) {
    let packet = build_mdns_query(hostname, domain);
    let addr = SocketAddr::new(IpAddr::V4(MDNS_MULTICAST_ADDR), MDNS_PORT);

    match socket.send_to(&packet, &addr.into()) {
        Ok(_) => log::debug!("Sent query for {}.{}", hostname, domain),
        Err(e) => log::error!("Failed to send mDNS query: {}", e),
    }
}

/// Listen for and respond to mDNS queries
pub async fn listen(socket: &Socket, send_socket: &Socket, name: &str, domain: &str, ip: Ipv4Addr, on_host_discovered: Option<HostDiscoveryCallback>, on_query_response: Option<QueryResponseCallback>) {
    let mut buf: [MaybeUninit<u8>; 4096] = [MaybeUninit::uninit(); 4096];

    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, _addr)) => {
                // Safety: recv_from initializes the bytes it reads
                let data = unsafe {
                    std::slice::from_raw_parts(buf.as_ptr() as *const u8, len)
                };

                // Check for queries
                if let Some(query_name) = parse_mdns_query(data) {
                    let expected_name = format!("{}.{}", name, domain);
                    if query_name == expected_name {
                        log::debug!("Received query for {}.{}, sending response", name, domain);
                        respond_to_query(send_socket, name, domain, ip).await;
                    }
                }

                // Check for responses/announcements
                if let Some(hostname) = parse_mdns_response(data) {
                    let expected_name = format!("{}.{}", name, domain);
                    if hostname != expected_name {
                        log::info!("Discovered host: {}", hostname);

                        // Call both callbacks if present
                        if let Some(ref callback) = on_host_discovered {
                            callback(hostname.clone());
                        }
                        if let Some(ref callback) = on_query_response {
                            callback(hostname);
                        }
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No data available, yield to other tasks
                tokio::task::yield_now().await;
            }
            Err(e) => {
                log::error!("Failed to receive mDNS query: {}", e);
            }
        }
    }
}

/// Send a response to an mDNS query
async fn respond_to_query(socket: &Socket, name: &str, domain: &str, ip: Ipv4Addr) {
    let packet = build_mdns_packet(name, domain, ip);
    let addr = SocketAddr::new(IpAddr::V4(MDNS_MULTICAST_ADDR), MDNS_PORT);

    match socket.send_to(&packet, &addr.into()) {
        Ok(_) => log::debug!("Sent response for {}.{}", name, domain),
        Err(e) => log::error!("Failed to send mDNS response: {}", e),
    }
}