"""End-to-end integration tests for the rustuya Python extension against the
tuyamock device emulator.

tuyamock (https://pypi.org/project/tuyamock/) is a Tuya LAN protocol server
validated against the tinytuya reference client. These tests point the *real*
rustuya client at an in-process mock and exercise the full wire path —
connection, framing, encryption, the v3.4/v3.5 session-key handshake, and the
device22 status dialect — without any physical hardware.

Run locally:

    cd python
    maturin develop                 # build the extension into your venv
    pip install tuyamock pytest
    pytest tests -v
"""

import time

import pytest

import rustuya
import tuyamock

# tuyamock accepts any 16-byte local key; this is the value from its docs.
LOCAL_KEY = "thisisarealkey00"
# A plain (non-device22) id and a 22-char id for the device22 dialect.
DEVICE_ID = "01234567890123456789"
DEVICE22_ID = "eb0123456789abcdefghij"

# Per-request connect keeps the mock's single-connection model simple and
# avoids a lingering socket between assertions.
CONNECT_TIMEOUT = 5.0


def _dps(status):
    """Extract the dps map from a status response, tolerating both the bare
    ``{"dps": {...}}`` and the wrapped ``{"data": {"dps": {...}}}`` shapes."""
    assert isinstance(status, dict), f"unexpected status: {status!r}"
    if "dps" in status:
        return status["dps"]
    return status.get("data", {}).get("dps")


# Plain devices: every supported version EXCEPT 3.2 (which is always device22).
PLAIN_VERSIONS = ["3.1", "3.3", "3.4", "3.5"]

# device22 is meaningful only on 3.2 (always), 3.3, and 3.4 (tuyamock rejects
# --dev22 on 3.1/3.5). On 3.2 rustuya auto-applies the device22 dialect, so no
# explicit dev_type is needed.
DEVICE22_CASES = [
    ("3.2", None),
    ("3.3", "device22"),
    ("3.4", "device22"),
]


@pytest.mark.parametrize("version", PLAIN_VERSIONS)
def test_status_and_set_roundtrip(version):
    """status() reads the device's full dps; set_value() mutates live state."""
    with tuyamock.MockDevice(
        local_key=LOCAL_KEY, version=version, dps={"1": True, "20": "white"}
    ) as mock:
        device = rustuya.Device(
            DEVICE_ID,
            LOCAL_KEY,
            address="127.0.0.1",
            version=version,
            port=mock.port,
            persist=False,
            timeout=CONNECT_TIMEOUT,
        )
        try:
            dps = _dps(device.status())
            assert dps == {"1": True, "20": "white"}, f"v{version}: {dps!r}"

            device.set_value("1", False)
            assert mock.dps.get("1") is False, f"v{version}: {mock.dps!r}"
        finally:
            device.stop()


@pytest.mark.parametrize("version,dev_type", DEVICE22_CASES)
def test_device22_status_and_set(version, dev_type):
    """A device22 device answers the status query (via the CONTROL_NEW dialect)
    returning only the requested dp, and accepts set commands."""
    with tuyamock.MockDevice(
        local_key=LOCAL_KEY,
        version=version,
        dps={"1": True, "20": "white"},
        dev22=True,
    ) as mock:
        device = rustuya.Device(
            DEVICE22_ID,
            LOCAL_KEY,
            address="127.0.0.1",
            version=version,
            dev_type=dev_type,
            port=mock.port,
            persist=False,
            timeout=CONNECT_TIMEOUT,
        )
        try:
            # rustuya queries device22 with dps={"1": null}, so the device
            # returns only dp 1 (it answers exactly what was asked for).
            dps = _dps(device.status())
            assert dps == {"1": True}, f"v{version} device22: {dps!r}"

            device.set_value("1", False)
            assert mock.dps.get("1") is False, f"v{version} device22: {mock.dps!r}"
        finally:
            device.stop()


# --- Network-fault handling -------------------------------------------------
# tuyamock's fault-injection knobs simulate a device that stops replying, drops
# the TCP link, and (with `outages`) recovers on a later reconnect:
#   go_dark_after=N   stop replying after N responses (0 = dark from connect)
#   drop_after_dark=s close the dark connection s seconds later
#   outages=N         inject N go-dark outages, then recover for good
# These exercise rustuya's own offline/reconnect path, not just the happy one.


def test_offline_status_raises():
    """A device that never answers (dark from connect) makes status() fail via
    timeout rather than hang. rustuya surfaces the offline device as an error,
    not as a silent ``None``."""
    with tuyamock.MockDevice(
        local_key=LOCAL_KEY, version="3.4", dps={"1": True}, go_dark_after=0
    ) as mock:
        device = rustuya.Device(
            DEVICE_ID,
            LOCAL_KEY,
            address="127.0.0.1",
            version="3.4",
            port=mock.port,
            persist=False,
            timeout=2.0,
        )
        try:
            with pytest.raises(Exception):
                device.status()
        finally:
            device.stop()


@pytest.mark.slow
def test_persist_recovers_after_drop():
    """persist=True end-to-end recovery: the device's first connection is a dead
    outage (dark, then the link drops); rustuya backs off, reconnects, and once
    the device has recovered ``status()`` round-trips again.

    NOTE: rustuya's reconnect floor is ``SLEEP_RECONNECT_MIN`` (16s), which is
    not configurable from Python, so a faithful auto-recovery run takes ~16-20s
    — hence the ``slow`` marker (excluded from the default integration run)."""
    with tuyamock.MockDevice(
        local_key=LOCAL_KEY,
        version="3.4",
        dps={"1": True},
        go_dark_after=0,
        drop_after_dark=0.3,
        outages=1,
    ) as mock:
        device = rustuya.Device(
            DEVICE_ID,
            LOCAL_KEY,
            address="127.0.0.1",
            version="3.4",
            port=mock.port,
            persist=True,
            timeout=2.0,
        )
        try:
            # First connection is the outage — the device is dark.
            with pytest.raises(Exception):
                device.status()

            # rustuya reconnects after its backoff; the device has recovered.
            recovered = None
            deadline = time.time() + 30
            while time.time() < deadline:
                try:
                    recovered = _dps(device.status())
                    break
                except Exception:
                    time.sleep(0.5)
            assert recovered == {"1": True}, f"did not recover: {recovered!r}"
            # At least the outage connection + one successful reconnect.
            assert mock.server.connections >= 2, mock.server.connections
        finally:
            device.stop()
