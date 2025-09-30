use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use socket2::{Domain, Protocol, Socket, Type};

use crate::constants::{MDNS_PORT, MDNS_MULTICAST_ADDR};

/// Create a UDP socket for sending mDNS packets
pub fn create_send_socket() -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_reuse_address(true)?;
    socket.set_multicast_loop_v4(true)?;
    socket.set_multicast_ttl_v4(255)?;

    Ok(socket)
}

/// Create a UDP socket for receiving mDNS packets
pub fn create_recv_socket() -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;

    // Bind to mDNS port
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), MDNS_PORT);
    socket.bind(&addr.into())?;

    // Join multicast group
    socket.join_multicast_v4(&MDNS_MULTICAST_ADDR, &Ipv4Addr::UNSPECIFIED)?;

    Ok(socket)
}