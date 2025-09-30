use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use socket2::Socket;

use crate::constants::{MDNS_PORT, MDNS_MULTICAST_ADDR};
use crate::packet::{build_mdns_packet, build_mdns_query, parse_mdns_query};

/// Send a query for a specific hostname
///
/// # Arguments
///
/// * `socket` - The socket to send the query on
/// * `hostname` - The hostname to query (without .local suffix)
pub async fn query(socket: &Socket, hostname: &str) {
    let packet = build_mdns_query(hostname);
    let addr = SocketAddr::new(IpAddr::V4(MDNS_MULTICAST_ADDR), MDNS_PORT);

    if let Err(e) = socket.send_to(&packet, &addr.into()) {
        eprintln!("Failed to send mDNS query: {}", e);
    }
}

/// Listen for and respond to mDNS queries
pub async fn listen(socket: &Socket, send_socket: &Socket, name: &str, ip: Ipv4Addr) {
    let mut buf: [MaybeUninit<u8>; 4096] = [MaybeUninit::uninit(); 4096];

    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, _addr)) => {
                // Safety: recv_from initializes the bytes it reads
                let data = unsafe {
                    std::slice::from_raw_parts(buf.as_ptr() as *const u8, len)
                };

                if let Some(query_name) = parse_mdns_query(data) {
                    let expected_name = format!("{}.local", name);
                    if query_name == expected_name {
                        println!("Received query for {}.local, sending response", name);
                        respond_to_query(send_socket, name, ip).await;
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to receive mDNS query: {}", e);
            }
        }
    }
}

/// Send a response to an mDNS query
async fn respond_to_query(socket: &Socket, name: &str, ip: Ipv4Addr) {
    let packet = build_mdns_packet(name, ip);
    let addr = SocketAddr::new(IpAddr::V4(MDNS_MULTICAST_ADDR), MDNS_PORT);

    if let Err(e) = socket.send_to(&packet, &addr.into()) {
        eprintln!("Failed to send mDNS response: {}", e);
    }
}