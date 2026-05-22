//! Cross-platform `if_nametoindex` wrapper.
//!
//! Unix: delegates to `libc::if_nametoindex`.
//! Windows: delegates to `iphlpapi.dll`'s `if_nametoindex` (Vista+).

use std::{ffi::CString, io};

pub fn if_nametoindex(name: &str) -> io::Result<u32> {
    let cstr = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name contains NUL"))?;
    // Safety: `cstr` is a valid NUL-terminated C string.
    let idx = unsafe { sys::if_nametoindex_raw(cstr.as_ptr()) };
    if idx == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(idx)
    }
}

#[cfg(unix)]
mod sys {
    pub(super) unsafe fn if_nametoindex_raw(name: *const libc::c_char) -> libc::c_uint {
        unsafe { libc::if_nametoindex(name) }
    }
}

#[cfg(windows)]
mod sys {
    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn if_nametoindex(InterfaceName: *const libc::c_char) -> libc::c_uint;
    }

    pub(super) unsafe fn if_nametoindex_raw(name: *const libc::c_char) -> libc::c_uint {
        unsafe { if_nametoindex(name) }
    }
}
