//! Live Sysmon subscription via the Windows Event Log API (push mode).
//!
//! `EvtSubscribe` invokes `on_event` on an OS thread-pool thread for every new
//! record in the Sysmon channel. The callback renders it to XML and hands it
//! to the `Store`; it never touches Python, so it runs without the GIL.

use crate::store::Store;
use std::sync::Arc;

pub const DEFAULT_CHANNEL: &str = "Microsoft-Windows-Sysmon/Operational";

#[cfg(windows)]
mod imp {
    use super::*;
    use std::ffi::c_void;
    use std::sync::atomic::Ordering;
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER};
    use windows_sys::Win32::System::EventLog::{
        EvtClose, EvtRender, EvtRenderEventXml, EvtSubscribe, EvtSubscribeActionDeliver,
        EvtSubscribeToFutureEvents, EVT_HANDLE, EVT_SUBSCRIBE_NOTIFY_ACTION,
    };

    pub struct Subscription {
        handle: EVT_HANDLE,
        ctx: *const Store,
    }

    // The handle and the leaked Arc are only touched through EvtClose / Drop.
    unsafe impl Send for Subscription {}
    unsafe impl Sync for Subscription {}

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Subscribe to future events on `channel`. Err carries the Win32 error code
    /// (15007 = channel not found, i.e. Sysmon not installed; 5 = access denied).
    pub fn subscribe(store: Arc<Store>, channel: &str) -> Result<Subscription, u32> {
        let chan = wide(channel);
        let query = wide("*");
        let ctx = Arc::into_raw(store);
        let handle = unsafe {
            EvtSubscribe(
                0,
                std::ptr::null_mut(),
                chan.as_ptr(),
                query.as_ptr(),
                0,
                ctx as *const c_void,
                Some(on_event),
                EvtSubscribeToFutureEvents,
            )
        };
        if handle == 0 {
            let err = unsafe { GetLastError() };
            drop(unsafe { Arc::from_raw(ctx) });
            return Err(err);
        }
        Ok(Subscription { handle, ctx })
    }

    impl Drop for Subscription {
        fn drop(&mut self) {
            // EvtClose waits for in-flight callbacks, so the Store outlives them.
            unsafe {
                EvtClose(self.handle);
                drop(Arc::from_raw(self.ctx));
            }
        }
    }

    unsafe extern "system" fn on_event(
        action: EVT_SUBSCRIBE_NOTIFY_ACTION,
        ctx: *const c_void,
        event: EVT_HANDLE,
    ) -> u32 {
        let store = &*(ctx as *const Store);
        if action != EvtSubscribeActionDeliver {
            // EvtSubscribeActionError: `event` carries the error code.
            store.parse_errors.fetch_add(1, Ordering::Relaxed);
            return 0;
        }
        match render_xml(event) {
            Some(xml) => {
                store.ingest_xml(&xml);
            }
            None => {
                store.parse_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        0
    }

    unsafe fn render_xml(event: EVT_HANDLE) -> Option<String> {
        let mut used = 0u32;
        let mut props = 0u32;
        if EvtRender(0, event, EvtRenderEventXml, 0, std::ptr::null_mut(), &mut used, &mut props) == 0
            && GetLastError() != ERROR_INSUFFICIENT_BUFFER
        {
            return None;
        }
        let mut buf = vec![0u16; (used as usize + 1) / 2 + 1];
        let size = (buf.len() * 2) as u32;
        if EvtRender(0, event, EvtRenderEventXml, size, buf.as_mut_ptr() as *mut c_void, &mut used, &mut props) == 0 {
            return None;
        }
        let n = (used as usize / 2).min(buf.len());
        let s = String::from_utf16_lossy(&buf[..n]);
        Some(s.trim_end_matches('\0').to_string())
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;

    pub struct Subscription;

    pub fn subscribe(_store: Arc<Store>, _channel: &str) -> Result<Subscription, u32> {
        Err(50) // ERROR_NOT_SUPPORTED
    }
}

pub use imp::{subscribe, Subscription};
