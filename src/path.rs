use std::net::SocketAddr;

#[derive(Copy,Clone,Debug, Eq, PartialEq, Hash)]
pub struct Path {
    local: SocketAddr,
    remote: SocketAddr,
}
