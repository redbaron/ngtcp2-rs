use socket2::SockAddr;

#[derive(Clone,Debug, Eq, PartialEq, Hash)]
pub struct Path {
    pub local: SockAddr,
    pub remote: SockAddr,
}

