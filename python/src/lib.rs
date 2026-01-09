//! Python bindings for the rustuya library.
//!
//! This module provides a high-performance Python interface to interact with Tuya devices,
//! leveraging the underlying Rust implementation. It supports device discovery,
//! status monitoring, and command execution for both direct and gateway-connected devices.

use ::rustuya::Version;
use ::rustuya::protocol::DeviceType;
use ::rustuya::sync::{
    Device as SyncDevice, DeviceCommand, Scanner as SyncScanner, SubDevice as SyncSubDevice,
    SubDeviceCommand, SyncRequest,
};
use log::LevelFilter;
use pyo3::IntoPyObjectExt;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyDictMethods, PyList, PyListMethods};
use serde_json::Value;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

fn interruptible_call<'py, C, R: Send>(
    py: Python<'py>,
    tx: &mpsc::Sender<SyncRequest<C, R>>,
    cmd: C,
) -> PyResult<R> {
    let (resp_tx, resp_rx) = std::sync::mpsc::channel();
    let req = SyncRequest {
        command: cmd,
        resp_tx,
    };

    // Use blocking_send as we are in a sync context (Python thread)
    tx.blocking_send(req)
        .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("Failed to send command"))?;

    let res = py.detach(move || recv_with_signals(&resp_rx));
    match res {
        Ok(Some(res)) => res.map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("Command failed: {}", e))
        }),
        Ok(None) | Err(_) => Err(pyo3::exceptions::PyRuntimeError::new_err(
            "Command worker died",
        )),
    }
}

fn to_py_result<'py>(py: Python<'py>, res: Option<String>) -> PyResult<Option<Bound<'py, PyAny>>> {
    match res {
        Some(s) => {
            if let Ok(val) = serde_json::from_str::<Value>(&s) {
                Ok(Some(pythonize::pythonize(py, &val)?))
            } else {
                Ok(Some(s.into_bound_py_any(py)?))
            }
        }
        None => Ok(None),
    }
}

fn recv_with_signals<T: Send>(receiver: &std::sync::mpsc::Receiver<T>) -> PyResult<Option<T>> {
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

fn message_to_dict<'py>(
    py: Python<'py>,
    id: &str,
    msg: &::rustuya::protocol::TuyaMessage,
) -> PyResult<Bound<'py, PyAny>> {
    let dict = PyDict::new(py);
    dict.set_item("id", id)?;
    dict.set_item("cmd", msg.cmd)?;
    dict.set_item("seqno", msg.seqno)?;

    if let Some(payload_str) = msg.payload_as_string() {
        if let Ok(val) = serde_json::from_str::<Value>(&payload_str) {
            dict.set_item("payload", pythonize::pythonize(py, &val)?)?;
        } else {
            dict.set_item("payload", payload_str)?;
        }
    }
    Ok(dict.into_any())
}

fn receive_event<'py, T: Send>(
    py: Python<'py>,
    inner: &Arc<Mutex<std::sync::mpsc::Receiver<T>>>,
    timeout_ms: Option<u64>,
) -> PyResult<Option<T>> {
    py.detach(|| -> PyResult<_> {
        let receiver = inner
            .lock()
            .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("receiver mutex poisoned"))?;

        if let Some(ms) = timeout_ms {
            Ok(receiver.recv_timeout(Duration::from_millis(ms)).ok())
        } else {
            recv_with_signals(&receiver)
        }
    })
}

/// Scanner for Tuya devices in Python.
#[pyclass]
pub struct Scanner {}

#[pymethods]
impl Scanner {
    /// Returns the global scanner instance.
    #[staticmethod]
    pub fn get() -> Self {
        Self {}
    }

    /// Returns a real-time scan iterator.
    #[staticmethod]
    pub fn scan_stream() -> ScannerIterator {
        ScannerIterator {
            inner: Arc::new(Mutex::new(SyncScanner::scan_stream())),
        }
    }

    /// Scans the local network for Tuya devices.
    #[staticmethod]
    pub fn scan<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let res = SyncScanner::scan();
            let _ = tx.send(res);
        });

        let results = match py.detach(move || recv_with_signals(&rx))? {
            Some(res) => res.map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("Scan failed: {}", e))
            })?,
            None => {
                return Err(pyo3::exceptions::PyRuntimeError::new_err(
                    "Scan worker disconnected",
                ));
            }
        };

        let list = PyList::empty(py);
        for r in results {
            list.append(pythonize::pythonize(py, &r)?)?;
        }
        Ok(list)
    }

    /// Discovers a specific device by ID.
    #[staticmethod]
    pub fn discover<'py>(py: Python<'py>, id: &str) -> PyResult<Option<Bound<'py, PyAny>>> {
        let (tx, rx) = std::sync::mpsc::channel();
        let id_owned = id.to_string();
        std::thread::spawn(move || {
            let res = SyncScanner::discover(&id_owned);
            let _ = tx.send(res);
        });

        match py.detach(move || recv_with_signals(&rx))? {
            Some(Some(r)) => Ok(Some(pythonize::pythonize(py, &r)?)),
            _ => Ok(None),
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
    pub fn status<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        let res = interruptible_call(py, &self.inner.cmd_tx, SubDeviceCommand::Status)?;
        to_py_result(py, res)
    }

    pub fn __repr__(&self) -> String {
        format!("SubDevice(id='{}')", self.inner.id())
    }

    /// Sets multiple DP values.
    pub fn set_dps<'py>(
        &self,
        py: Python<'py>,
        dps: Bound<'py, PyAny>,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
        let val: Value = pythonize::depythonize(&dps).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Invalid Python object: {}", e))
        })?;
        let res = interruptible_call(py, &self.inner.cmd_tx, SubDeviceCommand::SetDps(val))?;
        to_py_result(py, res)
    }

    /// Sets a single DP value.
    pub fn set_value<'py>(
        &self,
        py: Python<'py>,
        dp_id: Bound<'py, PyAny>,
        value: Bound<'py, PyAny>,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
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
        let res = interruptible_call(
            py,
            &self.inner.cmd_tx,
            SubDeviceCommand::SetValue(id_str, val),
        )?;
        to_py_result(py, res)
    }

    /// Sends a direct request to the sub-device.
    #[pyo3(signature = (command, data=None))]
    pub fn request<'py>(
        &self,
        py: Python<'py>,
        command: u32,
        data: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
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
        let res = interruptible_call(
            py,
            &self.inner.cmd_tx,
            SubDeviceCommand::Request {
                command: cmd,
                data: val,
            },
        )?;
        to_py_result(py, res)
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
    #[pyo3(signature = (id, local_key, address="Auto", version="Auto", dev_type=None, persist=true, timeout=None, nowait=false))]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        py: Python<'_>,
        id: &str,
        local_key: &str,
        address: &str,
        version: &str,
        dev_type: Option<&str>,
        persist: bool,
        timeout: Option<f64>,
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

        if let Some(secs) = timeout {
            builder = builder.timeout(Duration::from_secs_f64(secs));
        }

        let inner = py.detach(|| builder.run());
        Ok(Device { inner })
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

    /// Returns the connection timeout in seconds.
    #[getter]
    pub fn timeout(&self) -> f64 {
        self.inner.timeout().as_secs_f64()
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
    pub fn status<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        let res = interruptible_call(py, &self.inner.cmd_tx, DeviceCommand::Status)?;
        to_py_result(py, res)
    }

    /// Returns whether the device is in nowait mode.
    #[getter]
    pub fn nowait(&self) -> bool {
        self.inner.nowait()
    }

    /// Sets multiple DP values.
    pub fn set_dps<'py>(
        &self,
        py: Python<'py>,
        dps: Bound<'py, PyAny>,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
        let val: Value = pythonize::depythonize(&dps).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Invalid Python object: {}", e))
        })?;
        let res = interruptible_call(py, &self.inner.cmd_tx, DeviceCommand::SetDps(val))?;
        to_py_result(py, res)
    }

    /// Sets a single DP value.
    pub fn set_value<'py>(
        &self,
        py: Python<'py>,
        dp_id: Bound<'py, PyAny>,
        value: Bound<'py, PyAny>,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
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
        let res = interruptible_call(py, &self.inner.cmd_tx, DeviceCommand::SetValue(id_str, val))?;
        to_py_result(py, res)
    }

    /// Sends a direct request to the device.
    #[pyo3(signature = (command, data=None, cid=None))]
    pub fn request<'py>(
        &self,
        py: Python<'py>,
        command: u32,
        data: Option<Bound<'py, PyAny>>,
        cid: Option<String>,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
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
        let res = interruptible_call(
            py,
            &self.inner.cmd_tx,
            DeviceCommand::Request {
                command: cmd,
                data: val,
                cid,
            },
        )?;
        to_py_result(py, res)
    }

    /// Discovers sub-devices (for gateways).
    pub fn sub_discover<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        let res = interruptible_call(py, &self.inner.cmd_tx, DeviceCommand::SubDiscover)?;
        to_py_result(py, res)
    }

    /// Returns a sub-device handle.
    pub fn sub(&self, cid: &str) -> SubDevice {
        SubDevice {
            inner: self.inner.sub(cid),
        }
    }

    /// Closes the device connection.
    pub fn close(&self, py: Python<'_>) -> PyResult<()> {
        interruptible_call(py, &self.inner.cmd_tx, DeviceCommand::Close)?;
        Ok(())
    }

    /// Stops the device and its internal tasks.
    pub fn stop(&self, py: Python<'_>) -> PyResult<()> {
        interruptible_call(py, &self.inner.cmd_tx, DeviceCommand::Stop)?;
        Ok(())
    }

    /// Returns an event receiver for the device.
    pub fn listener(&self) -> DeviceEventReceiver {
        DeviceEventReceiver {
            id: self.inner.id().to_string(),
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
        match receive_event(py, &self.inner, timeout_ms)? {
            Some(Ok(event)) => Ok(Some(message_to_dict(py, &event.device_id, &event.message)?)),
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

#[pyfunction]
pub fn maximize_fd_limit() -> PyResult<()> {
    ::rustuya::maximize_fd_limit().map_err(|e| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("Failed to maximize FD limit: {}", e))
    })
}

#[pyclass]
pub struct DeviceEventReceiver {
    id: String,
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
        match receive_event(py, &self.inner, timeout_ms)? {
            Some(msg) => Ok(Some(message_to_dict(py, &self.id, &msg)?)),
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
    m.add_function(pyo3::wrap_pyfunction!(unified_listener, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(maximize_fd_limit, m)?)?;

    let atexit = py.import("atexit")?;
    atexit.call_method1("register", (m.getattr("_rustuya_atexit")?,))?;

    m.add_class::<Device>()?;
    m.add_class::<DeviceEventReceiver>()?;
    m.add_class::<UnifiedEventReceiver>()?;
    m.add_class::<SubDevice>()?;
    m.add_class::<Scanner>()?;
    m.add_class::<ScannerIterator>()?;

    let cmd_type = PyDict::new(py);
    cmd_type.set_item(
        "ApConfig",
        ::rustuya::protocol::CommandType::ApConfig as u32,
    )?;
    cmd_type.set_item("Active", ::rustuya::protocol::CommandType::Active as u32)?;
    cmd_type.set_item(
        "SessKeyNegStart",
        ::rustuya::protocol::CommandType::SessKeyNegStart as u32,
    )?;
    cmd_type.set_item(
        "SessKeyNegResp",
        ::rustuya::protocol::CommandType::SessKeyNegResp as u32,
    )?;
    cmd_type.set_item(
        "SessKeyNegFinish",
        ::rustuya::protocol::CommandType::SessKeyNegFinish as u32,
    )?;
    cmd_type.set_item("Unbind", ::rustuya::protocol::CommandType::Unbind as u32)?;
    cmd_type.set_item("Control", ::rustuya::protocol::CommandType::Control as u32)?;
    cmd_type.set_item("Status", ::rustuya::protocol::CommandType::Status as u32)?;
    cmd_type.set_item(
        "HeartBeat",
        ::rustuya::protocol::CommandType::HeartBeat as u32,
    )?;
    cmd_type.set_item("DpQuery", ::rustuya::protocol::CommandType::DpQuery as u32)?;
    cmd_type.set_item(
        "QueryWifi",
        ::rustuya::protocol::CommandType::QueryWifi as u32,
    )?;
    cmd_type.set_item(
        "TokenBind",
        ::rustuya::protocol::CommandType::TokenBind as u32,
    )?;
    cmd_type.set_item(
        "ControlNew",
        ::rustuya::protocol::CommandType::ControlNew as u32,
    )?;
    cmd_type.set_item(
        "EnableWifi",
        ::rustuya::protocol::CommandType::EnableWifi as u32,
    )?;
    cmd_type.set_item(
        "WifiInfo",
        ::rustuya::protocol::CommandType::WifiInfo as u32,
    )?;
    cmd_type.set_item(
        "DpQueryNew",
        ::rustuya::protocol::CommandType::DpQueryNew as u32,
    )?;
    cmd_type.set_item(
        "SceneExecute",
        ::rustuya::protocol::CommandType::SceneExecute as u32,
    )?;
    cmd_type.set_item(
        "UpdateDps",
        ::rustuya::protocol::CommandType::UpdateDps as u32,
    )?;
    cmd_type.set_item("UdpNew", ::rustuya::protocol::CommandType::UdpNew as u32)?;
    cmd_type.set_item(
        "ApConfigNew",
        ::rustuya::protocol::CommandType::ApConfigNew as u32,
    )?;
    cmd_type.set_item(
        "LanGwActive",
        ::rustuya::protocol::CommandType::LanGwActive as u32,
    )?;
    cmd_type.set_item(
        "LanSubDevRequest",
        ::rustuya::protocol::CommandType::LanSubDevRequest as u32,
    )?;
    cmd_type.set_item(
        "LanDeleteSubDev",
        ::rustuya::protocol::CommandType::LanDeleteSubDev as u32,
    )?;
    cmd_type.set_item(
        "LanReportSubDev",
        ::rustuya::protocol::CommandType::LanReportSubDev as u32,
    )?;
    cmd_type.set_item(
        "LanScene",
        ::rustuya::protocol::CommandType::LanScene as u32,
    )?;
    cmd_type.set_item(
        "LanPublishCloudConfig",
        ::rustuya::protocol::CommandType::LanPublishCloudConfig as u32,
    )?;
    cmd_type.set_item(
        "LanExportAppConfig",
        ::rustuya::protocol::CommandType::LanExportAppConfig as u32,
    )?;
    cmd_type.set_item(
        "LanPublishAppConfig",
        ::rustuya::protocol::CommandType::LanPublishAppConfig as u32,
    )?;
    cmd_type.set_item(
        "ReqDevInfo",
        ::rustuya::protocol::CommandType::ReqDevInfo as u32,
    )?;
    cmd_type.set_item(
        "LanExtStream",
        ::rustuya::protocol::CommandType::LanExtStream as u32,
    )?;
    m.add("CommandType", cmd_type)?;

    Ok(())
}
