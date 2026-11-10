//! `edr_sensor` -- Python extension that turns live Sysmon telemetry into the
//! 99-feature behavioral vectors the Tier-1 / Tier-2 models were trained on.
//!
//! ```python
//! import edr_sensor
//! s = edr_sensor.Sensor()
//! s.start()                       # subscribe to Microsoft-Windows-Sysmon/Operational
//! vec = s.features(pid)           # list[float] (99) or None if < 3 events yet
//! ```

pub mod collector;
pub mod event;
pub mod features;
#[cfg(windows)]
pub mod identity;
pub mod ip;
pub mod store;

use pyo3::exceptions::{PyOSError, PyValueError};
use pyo3::prelude::*;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

/// Live Sysmon sensor. Events are buffered per process (by ProcessGuid) in Rust;
/// Python only asks for feature vectors.
#[pyclass(module = "edr_sensor")]
struct Sensor {
    store: Arc<store::Store>,
    channel: String,
    sub: Mutex<Option<collector::Subscription>>,
}

#[pymethods]
impl Sensor {
    #[new]
    #[pyo3(signature = (channel = collector::DEFAULT_CHANNEL.to_string(), max_processes = 8192))]
    fn new(channel: String, max_processes: usize) -> Self {
        Sensor { store: Arc::new(store::Store::new(max_processes)), channel, sub: Mutex::new(None) }
    }

    /// Start the event-log subscription. Raises OSError (with the Win32 code)
    /// if the channel is missing (Sysmon not installed) or access is denied.
    fn start(&self) -> PyResult<()> {
        let mut sub = self.sub.lock().unwrap();
        if sub.is_some() {
            return Ok(());
        }
        match collector::subscribe(self.store.clone(), &self.channel) {
            Ok(s) => {
                *sub = Some(s);
                Ok(())
            }
            Err(code) => Err(PyOSError::new_err((
                code as i32,
                format!("EvtSubscribe('{}') failed with Win32 error {code}", self.channel),
            ))),
        }
    }

    /// Stop the subscription (blocks until in-flight callbacks finish).
    fn stop(&self, py: Python<'_>) {
        let s = self.sub.lock().unwrap().take();
        py.allow_threads(move || drop(s));
    }

    #[getter]
    fn running(&self) -> bool {
        self.sub.lock().unwrap().is_some()
    }

    /// 99-feature vector for the process currently holding `pid`,
    /// or None while it has fewer than `min_events` buffered events.
    #[pyo3(signature = (pid, min_events = 3))]
    fn features(&self, py: Python<'_>, pid: u32, min_events: usize) -> Option<Vec<f32>> {
        py.allow_threads(|| self.store.features(pid, min_events)).map(|v| v.to_vec())
    }

    /// Image path recorded in the EventID-1 event of the process holding `pid`,
    /// or None. Works after the process has exited.
    fn creation_image(&self, pid: u32) -> Option<String> {
        self.store.creation_image(pid)
    }

    /// Number of buffered window events for `pid` (0 if unknown).
    fn event_count(&self, pid: u32) -> usize {
        self.store.event_count(pid)
    }

    /// Drop the buffer for `pid` (call when the agent stops watching it).
    fn forget(&self, pid: u32) {
        self.store.forget(pid)
    }

    /// Feed one rendered Sysmon event XML (for tests / replaying exported logs).
    fn ingest_xml(&self, xml: &str) -> bool {
        self.store.ingest_xml(xml)
    }

    fn stats(&self) -> HashMap<&'static str, u64> {
        let s = &self.store;
        HashMap::from([
            ("received", s.received.load(Ordering::Relaxed)),
            ("ingested", s.ingested.load(Ordering::Relaxed)),
            ("errors", s.parse_errors.load(Ordering::Relaxed)),
            ("evicted", s.evicted.load(Ordering::Relaxed)),
            ("tracked", s.tracked() as u64),
        ])
    }
}

/// Feature names in model-input order (must equal behavioral_dataset_meta.json).
#[pyfunction]
fn feature_names() -> Vec<String> {
    features::feature_names().to_vec()
}

/// Compute features for one process from a list of events given as dicts keyed
/// by Sysmon / dataset column names ("EventID", "SystemTime", "Image", ...).
/// Events outside EventID 1..23 are ignored, as in training.
#[pyfunction]
fn compute_features(events: Vec<HashMap<String, String>>) -> PyResult<Vec<f32>> {
    let evs: Vec<features::Event> = events.iter().filter_map(|m| event::from_fields(m)).map(|(_, _, e)| e).collect();
    if evs.is_empty() {
        return Err(PyValueError::new_err("no events with EventID in 1..23"));
    }
    let (window, creation) = features::split_events(evs);
    Ok(features::compute(&window, creation.as_ref()).to_vec())
}

/// Device key for signed Tier-2 requests: TPM when available, else software.
/// The private key never leaves the key store.
#[cfg(windows)]
#[pyclass(module = "edr_sensor")]
struct DeviceKey(identity::DeviceKey);

#[cfg(windows)]
#[pymethods]
impl DeviceKey {
    /// `machine=True` (the agent, running as SYSTEM) needs admin rights.
    #[new]
    #[pyo3(signature = (name = "TelltaleDeviceKey".to_string(), machine = true))]
    fn new(name: String, machine: bool) -> PyResult<Self> {
        identity::DeviceKey::open_or_create(&name, machine).map(DeviceKey).map_err(PyOSError::new_err)
    }

    /// "tpm" or "software" (shown as lower trust in the admin console).
    #[getter]
    fn kind(&self) -> &'static str {
        if self.0.tpm { "tpm" } else { "software" }
    }

    /// Uncompressed SEC1 public key (65 bytes).
    fn public_key(&self) -> PyResult<std::borrow::Cow<'static, [u8]>> {
        self.0.public_key().map(Into::into).map_err(PyOSError::new_err)
    }

    /// ECDSA P-256 over SHA-256(data), raw r||s (64 bytes).
    fn sign(&self, py: Python<'_>, data: &[u8]) -> PyResult<std::borrow::Cow<'static, [u8]>> {
        py.allow_threads(|| self.0.sign(data)).map(Into::into).map_err(PyOSError::new_err)
    }

    fn delete(&mut self) -> PyResult<()> {
        self.0.delete().map_err(PyOSError::new_err)
    }
}

/// Settings baked in by a release build (build.rs reads HALTLINE_* at compile time; empty in dev builds).
/// obfstr encrypts them, so the endpoints and keys don't show up in `strings` on the binary.
#[pyfunction]
fn release_config() -> HashMap<&'static str, String> {
    HashMap::from([
        ("endpoints", obfstr::obfstr!(env!("HALTLINE_ENDPOINTS")).to_string()),
        ("server_pubkey", obfstr::obfstr!(env!("HALTLINE_SERVER_PUBKEY")).to_string()),
        ("update_url", obfstr::obfstr!(env!("HALTLINE_UPDATE_URL")).to_string()),
        ("update_pubkey", obfstr::obfstr!(env!("HALTLINE_UPDATE_PUBKEY")).to_string()),
    ])
}

#[pymodule]
fn edr_sensor(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Sensor>()?;
    #[cfg(windows)]
    m.add_class::<DeviceKey>()?;
    m.add_function(wrap_pyfunction!(release_config, m)?)?;
    m.add_function(wrap_pyfunction!(feature_names, m)?)?;
    m.add_function(wrap_pyfunction!(compute_features, m)?)?;
    m.add("FEATURE_DIM", features::FEATURE_DIM)?;
    m.add("WINDOW", features::WINDOW)?;
    m.add("DEFAULT_CHANNEL", collector::DEFAULT_CHANNEL)?;
    Ok(())
}
