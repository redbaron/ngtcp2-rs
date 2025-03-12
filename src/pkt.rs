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
pub fn decode_version_cid(buf: &[u8], short_dcidlen: usize) -> Option<(PktVersionCid, bool)> {
    let mut uninit = MaybeUninit::uninit();
    /// SAFETY:
    /// - we pass pointer to a memory suitable for ngtcp2_version_cid both in size and alignment
    /// - ngtcp2_pkt_decode_version_cid does not  read beyond provided buffer (or so it claims :) )
    let rv = unsafe {
        ngtcp2_sys::ngtcp2_pkt_decode_version_cid(
            uninit.as_mut_ptr(),
            buf.as_ptr(),
            buf.len(),
            short_dcidlen,
        )
    };

    /// SAFETY: ngtcp2_pkt_decode_version_cid initialized the memory
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
        scid: if pkt_version.scid.is_null() { None } else { Some(unsafe {
            std::slice::from_raw_parts(pkt_version.scid, pkt_version.scidlen)
        })},
    };
    Some((pkt_ver, need_version_negotiation))
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
