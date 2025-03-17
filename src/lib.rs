pub mod error;
pub mod path;

mod pkt;
mod types;

pub use pkt::decode_version_cid as pkt_decode_version_cid;
pub use pkt::decode_hd_long as pkt_decode_hd_long;

use ngtcp2_sys;

pub type Result<T> = std::result::Result<T, error::ErrorCode>;

pub struct Version {
    pub version_num: i32,
    pub version_str: &'static str,
}

impl Version {
    pub fn major(&self) -> u8 {
        (self.version_num >> 16) as u8
    }

    pub fn minor(&self) -> u8 {
        (self.version_num >> 8) as u8
    }

    pub fn patch(&self) -> u8 {
        self.version_num as u8
    }
}

pub fn ngtcp2_version() -> Version {
    // SAFETY:
    // - with least_version=0 always returns !NULL
    // - version_str is a pointer to a static string
    unsafe {
        let v = ngtcp2_sys::ngtcp2_version(0);
        Version {
            version_num: (*v).version_num,
            version_str: std::ffi::CStr::from_ptr((*v).version_str).to_str().unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ngtcp2_version() {
        let v = ngtcp2_version();
        assert_eq!(v.version_str, "1.11.0");
        assert_eq!(v.major(), 1);
        assert_eq!(v.minor(), 11);
        assert_eq!(v.patch(), 0);
    }
}
