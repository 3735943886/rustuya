//! Python bindings for the rustuya library.
//!
//! This module provides a high-performance Python interface to interact with Tuya devices,
//! leveraging the underlying Rust implementation. It supports device discovery,
//! status monitoring, and command execution for both direct and gateway-connected devices.

use ::rustuya::Version;
use ::rustuya::protocol::DeviceType;
use ::rustuya::sync::{
    Device as SyncDevice, Scanner as SyncScanner,
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
pub struct Scanner {}

#[pymethods]
impl Scanner {
    /// Returns a real-time scan iterator.
    pub fn scan_stream(&self) -> ScannerIterator {
        ScannerIterator {
            inner: Arc::new(Mutex::new(SyncScanner::get().scan_stream())),
        }
    }

    /// Scans the local network for Tuya devices.
    pub fn scan<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let (tx, rx) = std::sync::mpsc::channel();
        let scanner = SyncScanner::get();
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
        let result = py.detach(|| SyncScanner::get().discover(id));
        match result {
            Some(r) => Ok(Some(pythonize::pythonize(py, &r)?)),
            None => Ok(None),
        }
    }
}

#[pyclass]
pub struct ScannerIterator {
    inner: Arc<Mutex<std::sync::mpsc::Receiver<::rustuya::scanner::DiscoveryResult>>>,
}

#[pymethods]
impl ScannerIterator {
    pub fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    pub fn __next__<'py>(&mut self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        let result = py.detach(|| -> PyResult<_> {
            let receiver = self.inner.lock().map_err(|_| {
                pyo3::exceptions::PyRuntimeError::new_err("receiver mutex poisoned")
            })?;
            recv_with_signals(&receiver)
        })?;

        match result {
            Some(res) => Ok(Some(pythonize::pythonize(py, &res)?)),
            None => Ok(None),
        }
    }
}

#[pyfunction]
pub fn get_scanner() -> Scanner {
    Scanner {}
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
    #[pyo3(signature = (id, local_key, address="Auto", version="Auto", dev_type=None, persist=true, timeout_ms=None, nowait=false))]
    pub fn new(
        id: &str,
        local_key: &str,
        address: &str,
        version: &str,
        dev_type: Option<&str>,
        persist: bool,
        timeout_ms: Option<u64>,
        nowait: bool,
    ) -> PyResult<Self> {
        let v = Version::from_str(version).map_err(|_| {
            pyo3::exceptions::PyValueError::new_err(format!("Invalid version: {}", version))
        })?;

        let mut builder = SyncDevice::builder(id, local_key.as_bytes())
            .address(address)
            .version(v)
            .persist(persist)
            .nowait(nowait);

        if let Some(dt_str) = dev_type {
            let dt = DeviceType::from_str(dt_str).map_err(|_| {
                pyo3::exceptions::PyValueError::new_err(format!("Invalid device type: {}", dt_str))
            })?;
            builder = builder.dev_type(dt);
        }

        if let Some(ms) = timeout_ms {
            builder = builder.connection_timeout(Duration::from_millis(ms));
        }

        Ok(Device {
            inner: builder.run(),
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

    /// Returns the user-configured address (e.g., "Auto" or a specific IP).
    #[getter]
    pub fn config_address(&self) -> String {
        self.inner.config_address()
    }

    /// Returns the device type.
    #[getter]
    pub fn dev_type(&self) -> String {
        self.inner.dev_type().as_str().to_string()
    }

    /// Returns the device port.
    #[getter]
    pub fn port(&self) -> u16 {
        self.inner.port()
    }

    /// Returns whether the connection is persistent.
    #[getter]
    pub fn persist(&self) -> bool {
        self.inner.persist()
    }

    /// Returns the connection timeout in milliseconds.
    #[getter]
    pub fn connection_timeout(&self) -> u64 {
        self.inner.connection_timeout().as_millis() as u64
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

    /// Requests the device status.
    pub fn status(&self, py: Python<'_>) {
        py.detach(|| self.inner.status());
    }

    /// Returns whether the device is in nowait mode.
    #[getter]
    pub fn nowait(&self) -> bool {
        self.inner.nowait()
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
pub struct UnifiedEventReceiver {
    inner: Arc<
        Mutex<
            std::sync::mpsc::Receiver<
                Result<::rustuya::device::DeviceEvent, ::rustuya::error::TuyaError>,
            >,
        >,
    >,
}

#[pymethods]
impl UnifiedEventReceiver {
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

            if let Some(ms) = timeout_ms {
                Ok(receiver.recv_timeout(Duration::from_millis(ms)).ok())
            } else {
                recv_with_signals(&receiver)
            }
        })?;

        match result {
            Some(Ok(event)) => Ok(Some(pythonize::pythonize(py, &event)?)),
            Some(Err(e)) => Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                "Event error: {}",
                e
            ))),
            None => Ok(None),
        }
    }
}

#[pyfunction]
pub fn unified_listener(devices: Vec<Bound<'_, Device>>) -> PyResult<UnifiedEventReceiver> {
    let sync_devices: Vec<SyncDevice> = devices
        .into_iter()
        .map(|d| d.borrow().inner.clone())
        .collect();
    let receiver = ::rustuya::sync::unified_listener(sync_devices);
    Ok(UnifiedEventReceiver {
        inner: Arc::new(Mutex::new(receiver)),
    })
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

#[pymodule]
fn rustuya(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Force load logging module in main thread to avoid background thread import issues
    let _ = py.import("logging")?;

    // Initialize logging bridge from Rust to Python
    let _ = pyo3_log::try_init();

    #[pyfunction]
    fn _rustuya_atexit() {
        log::set_max_level(LevelFilter::Off);
    }

    #[pyfunction]
    fn version() -> &'static str {
        ::rustuya::version()
    }

    m.add_function(pyo3::wrap_pyfunction!(_rustuya_atexit, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(version, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(get_scanner, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(unified_listener, m)?)?;

    let atexit = py.import("atexit")?;
    atexit.call_method1("register", (m.getattr("_rustuya_atexit")?,))?;

    m.add_class::<Device>()?;
    m.add_class::<DeviceEventReceiver>()?;
    m.add_class::<UnifiedEventReceiver>()?;
    m.add_class::<SubDevice>()?;
    m.add_class::<Scanner>()?;
    m.add_class::<ScannerIterator>()?;

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
