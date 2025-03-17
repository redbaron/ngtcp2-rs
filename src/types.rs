use std::num::NonZeroU8;
use ngtcp2_sys::NGTCP2_MAX_CIDLEN;

#[derive(Copy,Clone)]
pub struct CID {
    pub len: NonZeroU8,
    pub data: [u8; NGTCP2_MAX_CIDLEN as _],
}

impl CID {
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len.get() as _]
    }
}
