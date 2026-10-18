//! Per-process event buffers, shared between the Sysmon callback thread and Python.

use crate::event::{self, Owned};
use crate::features::{self, Event, FEATURE_DIM, WINDOW};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

struct Proc {
    /// Earliest `WINDOW` events by time -- the same window the builder used.
    window: Vec<Event>,
    /// Earliest EventID-1 row (kept even if it falls outside the window).
    creation: Option<Event>,
    last_seen: u64,
}

struct Inner {
    procs: HashMap<String, Proc>,
    /// Latest ProcessGuid seen for each PID; a new EventID 1 replaces a reused PID.
    pid_guid: HashMap<u32, String>,
    tick: u64,
}

pub struct Store {
    inner: Mutex<Inner>,
    max_processes: usize,
    pub received: AtomicU64,
    pub ingested: AtomicU64,
    pub parse_errors: AtomicU64,
    pub evicted: AtomicU64,
}

impl Store {
    pub fn new(max_processes: usize) -> Self {
        Store {
            inner: Mutex::new(Inner { procs: HashMap::new(), pid_guid: HashMap::new(), tick: 0 }),
            max_processes: max_processes.max(16),
            received: AtomicU64::new(0),
            ingested: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
            evicted: AtomicU64::new(0),
        }
    }

    /// Parse and store one rendered Sysmon event. Returns true if it was kept.
    pub fn ingest_xml(&self, xml: &str) -> bool {
        self.received.fetch_add(1, Ordering::Relaxed);
        match event::from_xml(xml) {
            Ok(Some(o)) => {
                self.ingest(o);
                true
            }
            Ok(None) => false,
            Err(_) => {
                self.parse_errors.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    pub fn ingest(&self, o: Owned) {
        let Owned { guid, pid, event: ev } = o;
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.tick += 1;
        let tick = g.tick;
        g.pid_guid.insert(pid, guid.clone());
        let p = g.procs.entry(guid).or_insert_with(|| Proc { window: Vec::new(), creation: None, last_seen: 0 });
        p.last_seen = tick;
        if ev.eid == 1 && p.creation.as_ref().map_or(true, |c| ev.sort_key() < c.sort_key()) {
            p.creation = Some(ev.clone());
        }
        let key = ev.sort_key();
        let pos = p.window.partition_point(|e| e.sort_key() <= key);
        if pos < WINDOW {
            p.window.insert(pos, ev);
            p.window.truncate(WINDOW);
        }
        self.ingested.fetch_add(1, Ordering::Relaxed);
        if g.procs.len() > self.max_processes {
            self.evict(&mut g);
        }
    }

    /// Drop the least recently active 10% of processes.
    fn evict(&self, g: &mut Inner) {
        let target = self.max_processes * 9 / 10;
        let mut ages: Vec<(u64, String)> = g.procs.iter().map(|(k, p)| (p.last_seen, k.clone())).collect();
        ages.sort_unstable();
        let n = g.procs.len().saturating_sub(target);
        for (_, guid) in ages.into_iter().take(n) {
            g.procs.remove(&guid);
        }
        let procs = &g.procs;
        g.pid_guid.retain(|_, guid| procs.contains_key(guid));
        self.evicted.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// Feature vector for the process currently holding `pid`, or None
    /// if it has fewer than `min_events` events (training used MIN_LEN = 3).
    pub fn features(&self, pid: u32, min_events: usize) -> Option<[f32; FEATURE_DIM]> {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let p = g.procs.get(g.pid_guid.get(&pid)?)?;
        if p.window.len() < min_events.max(1) {
            return None;
        }
        Some(features::compute(&p.window, p.creation.as_ref()))
    }

    /// Image path from the process-creation event (EventID 1) of the process
    /// currently holding `pid`. Lets the agent triage processes that exited
    /// before it could read their path from the OS.
    pub fn creation_image(&self, pid: u32) -> Option<String> {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let p = g.procs.get(g.pid_guid.get(&pid)?)?;
        let img = p.creation.as_ref()?.image.trim();
        if img.is_empty() { None } else { Some(img.to_string()) }
    }

    pub fn event_count(&self, pid: u32) -> usize {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.pid_guid.get(&pid).and_then(|k| g.procs.get(k)).map_or(0, |p| p.window.len())
    }

    pub fn forget(&self, pid: u32) {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(guid) = g.pid_guid.remove(&pid) {
            g.procs.remove(&guid);
        }
    }

    pub fn tracked(&self) -> usize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).procs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(guid: &str, pid: u32, eid: u32, t: i64) -> Owned {
        Owned { guid: guid.into(), pid, event: Event { eid, t_ns: Some(t), ..Default::default() } }
    }

    #[test]
    fn window_keeps_earliest_and_needs_min_events() {
        let s = Store::new(100);
        s.ingest(owned("a", 7, 3, 10));
        s.ingest(owned("a", 7, 3, 20));
        assert!(s.features(7, 3).is_none());
        for t in (0..60).rev() {
            s.ingest(owned("a", 7, 11, 1000 + t));
        }
        assert_eq!(s.event_count(7), WINDOW);
        assert!(s.features(7, 3).is_some());
    }

    #[test]
    fn pid_reuse_switches_process() {
        let s = Store::new(100);
        for t in 0..5 {
            s.ingest(owned("old", 9, 3, t));
        }
        s.ingest(owned("new", 9, 1, 100));
        assert_eq!(s.event_count(9), 1);
        s.forget(9);
        assert_eq!(s.event_count(9), 0);
        assert_eq!(s.tracked(), 1); // "old" stays until evicted
    }

    #[test]
    fn creation_image_follows_current_process() {
        let s = Store::new(100);
        s.ingest(owned("a", 5, 3, 0));
        assert_eq!(s.creation_image(5), None);          // no EventID 1 yet
        let mut c = owned("a", 5, 1, 1);
        c.event.image = r"C:\Tools\x.exe".into();
        s.ingest(c);
        assert_eq!(s.creation_image(5).as_deref(), Some(r"C:\Tools\x.exe"));
        let mut n = owned("b", 5, 1, 9);                // PID reused by a new process
        n.event.image = r"C:\Other\y.exe".into();
        s.ingest(n);
        assert_eq!(s.creation_image(5).as_deref(), Some(r"C:\Other\y.exe"));
    }

    #[test]
    fn eviction_bounds_memory() {
        let s = Store::new(20);
        for i in 0..100u32 {
            s.ingest(owned(&format!("g{i}"), i, 3, i as i64));
        }
        assert!(s.tracked() <= 20);
        assert_eq!(s.event_count(99), 1);
    }
}
