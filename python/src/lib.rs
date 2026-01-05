//! Python bindings for the rustuya library.
//!
//! This module provides a high-performance Python interface to interact with Tuya devices,
//! leveraging the underlying Rust implementation. It supports device discovery,
//! status monitoring, and command execution for both direct and gateway-connected devices.

use ::rustuya::Version;
use ::rustuya::protocol::DeviceType;
use ::rustuya::sync::{
    Device as SyncDevice, Manager as SyncManager, Scanner as SyncScanner,
    SubDevice as SyncSubDevice,
};
use log::LevelFilter;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyDictMethods, PyList, PyListMethods};
use serde_json::Value;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn set_payload<'py>(py: Python<'py>, dict: &Bound<'py, PyDict>, payload_str: &str) -> PyResult<()> {
    if let Ok(val) = serde_json::from_str::<Value>(payload_str) {
        dict.set_item("payload", pythonize::pythonize(py, &val)?)?;
    } else {
        dict.set_item("payload", payload_str)?;
    }
    Ok(())
}

fn recv_with_signals<T>(receiver: &std::sync::mpsc::Receiver<T>) -> PyResult<Option<T>> {
    loop {
        match receiver.recv_timeout(Duration::from_millis(500)) {
            Ok(msg) => return Ok(Some(msg)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                Python::attach(|py| py.check_signals())?;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Ok(None),
        }
    }
}

/// Scanner for Tuya devices in Python.
#[pyclass]
pub struct Scanner {
    inner: SyncScanner,
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

#[pymethods]
impl Scanner {
    #[new]
    pub fn new() -> Self {
        Scanner {
            inner: SyncScanner::new(),
        }
    }

    /// Sets the scan timeout in milliseconds.
    pub fn with_timeout(&self, timeout_ms: u64) -> Self {
        Scanner {
            inner: self
                .inner
                .clone()
                .with_timeout(Duration::from_millis(timeout_ms)),
        }
    }

    /// Sets the local address to bind to.
    pub fn set_bind_address(&mut self, addr: &str) -> PyResult<()> {
        self.inner.set_bind_address(addr).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("Failed to set bind address: {}", e))
        })
    }

    /// Scans the local network for Tuya devices.
    pub fn scan<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let (tx, rx) = std::sync::mpsc::channel();
        let scanner = self.inner.clone();
        std::thread::spawn(move || {
            let res = scanner.scan();
            let _ = tx.send(res);
        });
        let results = py.detach(
            move || -> PyResult<Vec<::rustuya::scanner::DiscoveryResult>> {
                match recv_with_signals(&rx)? {
                    Some(res) => res.map_err(|e| {
                        pyo3::exceptions::PyRuntimeError::new_err(format!("Scan failed: {}", e))
                    }),
                    None => Err(pyo3::exceptions::PyRuntimeError::new_err(
                        "Scan worker disconnected",
                    )),
                }
            },
        )?;
        let list = PyList::empty(py);
        for r in results {
            list.append(pythonize::pythonize(py, &r)?)?;
        }
        Ok(list)
    }

    /// Discovers a specific device by ID.
    pub fn discover<'py>(&self, py: Python<'py>, id: &str) -> PyResult<Option<Bound<'py, PyAny>>> {
        let result = py.detach(|| self.inner.discover(id));
        match result {
            Some(r) => Ok(Some(pythonize::pythonize(py, &r)?)),
            None => Ok(None),
        }
    }

    /// Stops the passive discovery listener.
    #[staticmethod]
    pub fn stop_passive_listener() {
        SyncScanner::stop_passive_listener();
    }
}

/// Sub-device handle for gateways in Python.
#[pyclass]
#[derive(Clone)]
pub struct SubDevice {
    inner: SyncSubDevice,
}

#[pymethods]
impl SubDevice {
    /// Returns the device ID.
    #[getter]
    pub fn id(&self) -> String {
        self.inner.id().to_string()
    }

    /// Requests the device status.
    pub fn status(&self, py: Python<'_>) {
        py.detach(|| self.inner.status());
    }

    pub fn __repr__(&self) -> String {
        format!("SubDevice(id='{}')", self.inner.id())
    }

    /// Sets multiple DP values.
    pub fn set_dps<'py>(&self, py: Python<'py>, dps: Bound<'py, PyAny>) -> PyResult<()> {
        let val: Value = pythonize::depythonize(&dps).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Invalid Python object: {}", e))
        })?;
        py.detach(|| self.inner.set_dps(val));
        Ok(())
    }

    /// Sets a single DP value.
    pub fn set_value<'py>(
        &self,
        py: Python<'py>,
        dp_id: Bound<'py, PyAny>,
        value: Bound<'py, PyAny>,
    ) -> PyResult<()> {
        let id_str = if let Ok(id) = dp_id.extract::<u32>() {
            id.to_string()
        } else if let Ok(id) = dp_id.extract::<String>() {
            id
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "dp_id must be an int or str",
            ));
        };

        let val: Value = pythonize::depythonize(&value).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Invalid Python object: {}", e))
        })?;
        py.detach(|| self.inner.set_value(id_str, val));
        Ok(())
    }
}

/// Device handle for Python.
#[pyclass]
#[derive(Clone)]
pub struct Device {
    inner: SyncDevice,
}

#[pymethods]
impl Device {
    #[new]
    pub fn new(id: &str, address: &str, local_key: &str, version: &str) -> PyResult<Self> {
        let v = Version::from_str(version).map_err(|_| {
            pyo3::exceptions::PyValueError::new_err(format!("Invalid version: {}", version))
        })?;
        Ok(Device {
            inner: SyncDevice::new(id, address, local_key.as_bytes(), v),
        })
    }

    /// Returns the device ID.
    #[getter]
    pub fn id(&self) -> String {
        self.inner.id().to_string()
    }

    /// Returns the protocol version.
    #[getter]
    pub fn version(&self) -> String {
        self.inner.version().to_string()
    }

    /// Returns the local key.
    #[getter]
    pub fn local_key(&self) -> String {
        hex::encode(self.inner.local_key())
    }

    /// Returns the device IP address.
    #[getter]
    pub fn address(&self) -> String {
        self.inner.address()
    }

    /// Returns the device type.
    #[getter]
    pub fn dev_type(&self) -> String {
        self.inner.dev_type().as_str().to_string()
    }

    /// Checks if the device is connected.
    #[getter]
    pub fn is_connected(&self) -> bool {
        self.inner.is_connected()
    }

    pub fn __repr__(&self) -> String {
        format!(
            "Device(id='{}', address='{}', version='{}')",
            self.inner.id(),
            self.inner.address(),
            self.inner.version()
        )
    }

    /// Sets whether to keep the connection persistent.
    pub fn set_persist(&self, persist: bool) {
        self.inner.set_persist(persist);
    }

    /// Sets the connection timeout in milliseconds.
    pub fn set_connection_timeout(&self, timeout_ms: u64) {
        self.inner
            .set_connection_timeout(Duration::from_millis(timeout_ms));
    }

    /// Sets the protocol version.
    pub fn set_version(&self, version: &str) {
        self.inner.set_version(version);
    }

    /// Sets the device type.
    pub fn set_dev_type(&self, dev_type: &str) -> PyResult<()> {
        let dt = DeviceType::from_str(dev_type).map_err(|_| {
            pyo3::exceptions::PyValueError::new_err(format!("Invalid device type: {}", dev_type))
        })?;
        self.inner.set_dev_type(dt);
        Ok(())
    }

    /// Requests the device status.
    pub fn status(&self, py: Python<'_>) {
        py.detach(|| self.inner.status());
    }

    /// Sets multiple DP values.
    pub fn set_dps<'py>(&self, py: Python<'py>, dps: Bound<'py, PyAny>) -> PyResult<()> {
        let val: Value = pythonize::depythonize(&dps).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Invalid Python object: {}", e))
        })?;
        py.detach(|| self.inner.set_dps(val));
        Ok(())
    }

    /// Sets a single DP value.
    pub fn set_value<'py>(
        &self,
        py: Python<'py>,
        dp_id: Bound<'py, PyAny>,
        value: Bound<'py, PyAny>,
    ) -> PyResult<()> {
        let id_str = if let Ok(id) = dp_id.extract::<u32>() {
            id.to_string()
        } else if let Ok(id) = dp_id.extract::<String>() {
            id
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "dp_id must be an int or str",
            ));
        };

        let val: Value = pythonize::depythonize(&value).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Invalid Python object: {}", e))
        })?;
        py.detach(|| self.inner.set_value(id_str, val));
        Ok(())
    }

    /// Sends a direct request to the device.
    #[pyo3(signature = (command, data=None, cid=None))]
    pub fn request<'py>(
        &self,
        py: Python<'py>,
        command: u32,
        data: Option<Bound<'py, PyAny>>,
        cid: Option<String>,
    ) -> PyResult<()> {
        let cmd = ::rustuya::protocol::CommandType::from_u32(command).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!("Invalid command type: {}", command))
        })?;
        let val: Option<Value> = if let Some(d) = data {
            Some(pythonize::depythonize(&d).map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("Invalid Python object: {}", e))
            })?)
        } else {
            None
        };
        py.detach(|| self.inner.request(cmd, val, cid));
        Ok(())
    }

    /// Discovers sub-devices (for gateways).
    pub fn sub_discover(&self, py: Python<'_>) {
        py.detach(|| self.inner.sub_discover());
    }

    /// Returns a sub-device handle.
    pub fn sub(&self, cid: &str) -> SubDevice {
        SubDevice {
            inner: self.inner.sub(cid),
        }
    }

    /// Closes the device connection.
    pub fn close(&self, py: Python<'_>) {
        py.detach(|| self.inner.close());
    }

    /// Stops the device and its internal tasks.
    pub fn stop(&self, py: Python<'_>) {
        py.detach(|| self.inner.stop());
    }

    /// Returns an event receiver for the device.
    pub fn listener(&self) -> DeviceEventReceiver {
        DeviceEventReceiver {
            inner: Arc::new(Mutex::new(self.inner.listener())),
        }
    }
}

#[pyclass]
pub struct DeviceEventReceiver {
    inner: Arc<Mutex<std::sync::mpsc::Receiver<::rustuya::protocol::TuyaMessage>>>,
}

#[pymethods]
impl DeviceEventReceiver {
    pub fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    pub fn __next__<'py>(&mut self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        self.recv(py, None)
    }

    #[pyo3(signature = (timeout_ms=None))]
    pub fn recv<'py>(
        &mut self,
        py: Python<'py>,
        timeout_ms: Option<u64>,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
        let result = py.detach(|| -> PyResult<_> {
            let receiver = self.inner.lock().map_err(|_| {
                pyo3::exceptions::PyRuntimeError::new_err("receiver mutex poisoned")
            })?;

            // Check for signals periodically if no timeout is specified
            // This allows Python to handle Ctrl+C
            if let Some(ms) = timeout_ms {
                Ok(receiver.recv_timeout(Duration::from_millis(ms)).ok())
            } else {
                recv_with_signals(&receiver)
            }
        })?;

        match result {
            Some(msg) => {
                let dict = PyDict::new(py);
                dict.set_item("cmd", msg.cmd)?;
                dict.set_item("seqno", msg.seqno)?;

                if let Some(payload_str) = msg.payload_as_string() {
                    set_payload(py, &dict, &payload_str)?;
                }
                Ok(Some(dict.into_any()))
            }
            None => Ok(None),
        }
    }
}

/// Receiver for manager events.
#[pyclass]
pub struct ManagerEventReceiver {
    inner: Arc<std::sync::Mutex<std::sync::mpsc::Receiver<::rustuya::manager::ManagerEvent>>>,
}

#[pymethods]
impl ManagerEventReceiver {
    pub fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    pub fn __next__<'py>(&mut self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        self.recv(py, None)
    }

    #[pyo3(signature = (timeout_ms=None))]
    pub fn recv<'py>(
        &mut self,
        py: Python<'py>,
        timeout_ms: Option<u64>,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
        let result = py.detach(|| -> PyResult<_> {
            let receiver = self.inner.lock().map_err(|_| {
                pyo3::exceptions::PyRuntimeError::new_err("receiver mutex poisoned")
            })?;

            // Check for signals periodically if no timeout is specified
            // This allows Python to handle Ctrl+C
            if let Some(ms) = timeout_ms {
                Ok(receiver.recv_timeout(Duration::from_millis(ms)).ok())
            } else {
                recv_with_signals(&receiver)
            }
        })?;

        match result {
            Some(event) => {
                let dict = PyDict::new(py);
                dict.set_item("device_id", event.device_id)?;
                dict.set_item("cmd", event.message.cmd)?;

                if let Some(payload_str) = event.message.payload_as_string() {
                    set_payload(py, &dict, &payload_str)?;
                }
                Ok(Some(dict.into_any()))
            }
            None => Ok(None),
        }
    }
}

#[pyclass(get_all)]
#[derive(Clone)]
pub struct DeviceInfo {
    pub id: String,
    pub address: String,
    pub local_key: String,
    pub version: String,
    pub is_connected: bool,
}

#[pyclass]
pub struct Manager {
    inner: SyncManager,
}

impl Default for Manager {
    fn default() -> Self {
        Self::new()
    }
}

#[pymethods]
impl Manager {
    #[new]
    pub fn new() -> Self {
        Manager {
            inner: SyncManager::new(),
        }
    }

    #[staticmethod]
    pub fn maximize_fd_limit() -> PyResult<()> {
        SyncManager::maximize_fd_limit().map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("Failed to maximize FD limit: {}", e))
        })
    }

    #[staticmethod]
    pub fn shutdown_all() {
        SyncManager::shutdown_all();
    }

    pub fn add(
        &self,
        py: Python<'_>,
        id: &str,
        address: &str,
        local_key: &str,
        version: &str,
    ) -> PyResult<()> {
        py.detach(|| self.inner.add(id, address, local_key, version))
            .map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("Failed to add device: {}", e))
            })
    }

    pub fn remove(&self, py: Python<'_>, id: &str) {
        py.detach(|| self.inner.remove(id));
    }

    pub fn delete(&self, py: Python<'_>, id: &str) {
        py.detach(|| self.inner.delete(id));
    }

    pub fn modify(
        &self,
        py: Python<'_>,
        id: &str,
        address: &str,
        local_key: &str,
        version: &str,
    ) -> PyResult<()> {
        py.detach(|| self.inner.modify(id, address, local_key, version))
            .map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("Failed to modify device: {}", e))
            })
    }

    pub fn get(&self, py: Python<'_>, id: &str) -> Option<Device> {
        py.detach(|| self.inner.get(id))
            .map(|d| Device { inner: d })
    }

    pub fn __getitem__(&self, py: Python<'_>, id: &str) -> PyResult<Device> {
        self.get(py, id).ok_or_else(|| {
            pyo3::exceptions::PyKeyError::new_err(format!("Device {} not found", id))
        })
    }

    pub fn __len__(&self, py: Python<'_>) -> usize {
        self.list(py).len()
    }

    pub fn clear(&self, py: Python<'_>) {
        py.detach(|| self.inner.clear());
    }

    pub fn list(&self, py: Python<'_>) -> Vec<DeviceInfo> {
        py.detach(|| {
            self.inner
                .list()
                .into_iter()
                .map(|info| DeviceInfo {
                    id: info.id,
                    address: info.address,
                    local_key: hex::encode(info.local_key),
                    version: info.version,
                    is_connected: info.is_connected,
                })
                .collect()
        })
    }

    pub fn listener(&self) -> ManagerEventReceiver {
        ManagerEventReceiver {
            inner: Arc::new(Mutex::new(self.inner.listener())),
        }
    }

    pub fn shutdown(&self, py: Python<'_>) {
        py.detach(|| self.inner.clone().shutdown());
    }
}

#[pymodule]
fn rustuya(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Force load logging module in main thread to avoid background thread import issues
    let _ = py.import("logging")?;

    // Initialize logging bridge from Rust to Python
    let _ = pyo3_log::try_init();

    #[pyfunction]
    fn _rustuya_atexit() {
        log::set_max_level(LevelFilter::Off);
        ::rustuya::scanner::Scanner::stop_passive_listener();
        ::rustuya::manager::Manager::shutdown_all();
    }

    #[pyfunction]
    fn version() -> &'static str {
        ::rustuya::version()
    }

    m.add_function(pyo3::wrap_pyfunction!(_rustuya_atexit, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(version, m)?)?;

    let atexit = py.import("atexit")?;
    atexit.call_method1("register", (m.getattr("_rustuya_atexit")?,))?;

    m.add_class::<Manager>()?;
    m.add_class::<Device>()?;
    m.add_class::<DeviceInfo>()?;
    m.add_class::<DeviceEventReceiver>()?;
    m.add_class::<SubDevice>()?;
    m.add_class::<ManagerEventReceiver>()?;
    m.add_class::<Scanner>()?;

    let cmd_type = PyDict::new(py);
    cmd_type.set_item("DpQuery", ::rustuya::protocol::CommandType::DpQuery as u32)?;
    cmd_type.set_item("Control", ::rustuya::protocol::CommandType::Control as u32)?;
    cmd_type.set_item(
        "HeartBeat",
        ::rustuya::protocol::CommandType::HeartBeat as u32,
    )?;
    cmd_type.set_item("Status", ::rustuya::protocol::CommandType::Status as u32)?;
    cmd_type.set_item(
        "QueryWifi",
        ::rustuya::protocol::CommandType::QueryWifi as u32,
    )?;
    m.add("CommandType", cmd_type)?;

    Ok(())
}
