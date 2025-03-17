use bitflags::bitflags;
use ngtcp2_sys::{ngtcp2_pkt_hd, ngtcp2_pkt_type};
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::num::NonZeroU32;

/// Version and connection IDs extracted from a packet header.
/// A short header contains just the Destination Connection ID.
/// A long header carries the version, destination, and source Connection IDs.
/// The version is presented as-is (if present), and it might not be supported by ngtcp2.
/// Likewise, the length of Connection IDs might exceed the maximum allowed length
/// by currently supported versions of the QUIC protocol.
pub struct PktVersionCid<'a> {
    pub version: Option<NonZeroU32>,
    pub dcid: &'a [u8],
    pub scid: Option<&'a [u8]>,
}

bitflags! {
    #[repr(transparent)]
    #[derive(Copy,Clone)]
    pub struct PktFlags: u8 {
        const LONG_FORM = ngtcp2_sys::NGTCP2_PKT_FLAG_LONG_FORM as _;
        const FIXED_BIT_CLEAR = ngtcp2_sys::NGTCP2_PKT_FLAG_FIXED_BIT_CLEAR as _;
        const KEY_PHASE = ngtcp2_sys::NGTCP2_PKT_FLAG_KEY_PHASE as _;

        // In case future ngtcp2 introduce new bits, preserve them
        const _ = !0;
    }

}

#[repr(u8)]
#[derive(Copy, Clone)]
pub enum PktType {
    VersionNegotiation = ngtcp2_pkt_type::NGTCP2_PKT_VERSION_NEGOTIATION as _,
    StatelessReset = ngtcp2_pkt_type::NGTCP2_PKT_STATELESS_RESET as _,
    Initial = ngtcp2_pkt_type::NGTCP2_PKT_INITIAL as _,
    Rtt0 = ngtcp2_pkt_type::NGTCP2_PKT_0RTT as _,
    Handshake = ngtcp2_pkt_type::NGTCP2_PKT_HANDSHAKE as _,
    Retry = ngtcp2_pkt_type::NGTCP2_PKT_RETRY as _,
    Rtt1 = ngtcp2_pkt_type::NGTCP2_PKT_1RTT as _,
}

impl From<ngtcp2_pkt_type> for PktType {
    fn from(value: ngtcp2_pkt_type) -> Self {
        match value {
            ngtcp2_pkt_type::NGTCP2_PKT_VERSION_NEGOTIATION => PktType::VersionNegotiation,
            ngtcp2_pkt_type::NGTCP2_PKT_STATELESS_RESET => PktType::StatelessReset,
            ngtcp2_pkt_type::NGTCP2_PKT_INITIAL => PktType::Initial,
            ngtcp2_pkt_type::NGTCP2_PKT_0RTT => PktType::Rtt0,
            ngtcp2_pkt_type::NGTCP2_PKT_HANDSHAKE => PktType::Handshake,
            ngtcp2_pkt_type::NGTCP2_PKT_RETRY => PktType::Retry,
            ngtcp2_pkt_type::NGTCP2_PKT_1RTT => PktType::Rtt1,
            // No default case to fail compilation if new variants added
        }
    }
}

#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct Pkt<'a> {
    inner: ngtcp2_pkt_hd,
    _1: PhantomData<&'a [u8]>,
}

impl Pkt<'_> {
    pub fn dcid(&self) -> &[u8] {
        &self.inner.dcid.data[..self.inner.dcid.datalen]
    }

    pub fn scid(&self) -> Option<&[u8]> {
        if self.inner.scid.datalen == 0 || self.inner.scid.datalen > self.inner.scid.data.len() {
            None
        } else {
            Some(&self.inner.scid.data[..self.inner.scid.datalen])
        }
    }

    /// Token is present only in Initial packets
    pub fn token(&self) -> Option<&[u8]> {
        if self.inner.token.is_null() {
            None
        } else {
            // SAFETY: token pointer points to buf with same lifetime as Self
            Some(unsafe { std::slice::from_raw_parts(self.inner.token, self.inner.tokenlen) })
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len as _
    }

    pub fn version(&self) -> Option<NonZeroU32> {
        NonZeroU32::new(self.inner.version)
    }

    pub fn type_(&self) -> PktType {
        let v: ngtcp2_pkt_type = unsafe { std::mem::transmute(self.inner.type_ as u32) };
        PktType::from(v)
    }

    pub fn flags(&self) -> PktFlags {
        PktFlags::from_bits_truncate(self.inner.flags)
    }
}

pub fn decode_version_cid(buf: &[u8], short_dcidlen: usize) -> Option<(PktVersionCid, bool)> {
    let mut uninit = MaybeUninit::uninit();
    // SAFETY:
    // - we pass pointer to a memory suitable for ngtcp2_version_cid both in size and alignment
    // - ngtcp2_pkt_decode_version_cid does not  read beyond provided buffer (or so it claims :) )
    let rv = unsafe {
        ngtcp2_sys::ngtcp2_pkt_decode_version_cid(
            uninit.as_mut_ptr(),
            buf.as_ptr(),
            buf.len(),
            short_dcidlen,
        )
    };

    // SAFETY: ngtcp2_pkt_decode_version_cid initialized the memory
    let pkt_version = unsafe { uninit.assume_init_ref() };

    let need_version_negotiation = match rv {
        ngtcp2_sys::NGTCP2_ERR_VERSION_NEGOTIATION => true,
        0 => false,
        _ => return None,
    };

    // SAFETY:
    // All slice::from_raw_parts are called with addresses from the same `buf` arg which is
    // continous memory. Our return lifetime is same as input lifetime, so these slices won't
    // outlive the input buffer.
    let pkt_ver = PktVersionCid {
        version: NonZeroU32::new(pkt_version.version),
        dcid: unsafe { std::slice::from_raw_parts(pkt_version.dcid, pkt_version.dcidlen) },
        scid: if pkt_version.scid.is_null() {
            None
        } else {
            Some(unsafe { std::slice::from_raw_parts(pkt_version.scid, pkt_version.scidlen) })
        },
    };
    Some((pkt_ver, need_version_negotiation))
}

/// decodes QUIC long header in `buf`. This function does not verify that length field is correct.
/// In other words, this function succeeds even if retrned Pkt.len > buf.len().
/// This function can handle Connection ID up to NGTCP2_MAX_CIDLEN. Consider to use
/// `[pkt_decode_version_cid()]` to get longer Connection ID.
///
/// This function handles Version Negotiation specially. If version field is 0, pkt must contain
/// Version Negotiation packet. Version Negotiation packet has random type in wire format.
/// For convenience, this function sets `Pkt::type` to `NGTCP2_PKT_VERSION_NEGOTIATION`,
/// clears NGTCP2_PKT_FLAG_LONG_FORM flag from `Pkt::flags`, and sets 0 to `Pkt::len`.
/// Version Negotiation packet occupies a single packet.
///
/// Function returns parsed Pkt and number of bytes read from `buf`.
pub fn decode_hd_long(buf: &[u8]) -> Option<(Pkt, usize)> {
    let mut uninit = MaybeUninit::uninit();
    // SAFETY:
    // - we pass pointer to a memory suitable for ngtcp2_pkt_decode_hd_short both in size and alignment
    // - ngtcp2_pkt_decode_hd_long does not read beyond provided buffer (or so it claims :) )
    let rv = unsafe {
        ngtcp2_sys::ngtcp2_pkt_decode_hd_long(uninit.as_mut_ptr(), buf.as_ptr(), buf.len())
    };

    if rv < 0 {
        return None;
    }

    Some((
        Pkt {
            // SAFETY: ngtcp2_pkt_decode_hd_short initialized the memory
            inner: unsafe { uninit.assume_init() },
            _1: PhantomData,
        },
        rv as _,
    ))
}

#[cfg(test)]
mod tests {
    // use super::*;

    // #[test]
    // fn test_decode_version_cid() {
    //     let mut buf = [0u8;ngtcp2_sys::NGTCP2_MAX_UDP_PAYLOAD_SIZE as usize];
    //     buf[0] = 0x80;
    //
    // }
}
