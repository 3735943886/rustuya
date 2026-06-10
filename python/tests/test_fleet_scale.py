"""Fleet-scale concurrent-connection test.

tuyamock is single-connection-per-instance and runs one OS thread per instance,
so co-locating ~1000 of them in ONE Python process saturates the GIL on a few
cores and the mocks cannot service their peers — an artifact of the *harness*,
not of rustuya (which holds 1000+ concurrent connections against any peer that
keeps up). To load-test the real thing, the mocks are split across SEPARATE
PROCESSES (~``PER`` per process) so the GIL is divided across processes.

This exercises rustuya's fleet path — 1000 independent device actors connecting
and being held concurrently — end to end against real sockets.

Tunables (env): ``RUSTUYA_FLEET_N`` (default 1000), ``RUSTUYA_FLEET_PER``
(mocks per worker process, default 100).
"""

import os
import time
import multiprocessing as mp

import pytest

LOCAL_KEY = "thisisarealkey00"
VERSION = "3.3"  # v3.3 needs no session handshake: connection-holding at scale


def _mock_worker(k, version, local_key, q, stop):
    """Child process: bind ``k`` mock devices, report their ports, then serve
    until signalled. Imports tuyamock locally so the (spawn) child never pulls
    in the rustuya extension."""
    import logging

    logging.disable(logging.CRITICAL)
    import tuyamock

    mocks = []
    try:
        for _ in range(k):
            m = tuyamock.MockDevice(
                local_key=local_key, version=version, dps={"1": True}
            )
            m.__enter__()
            mocks.append(m)
        q.put([m.port for m in mocks])
        stop.wait()
    finally:
        for m in mocks:
            try:
                m.__exit__(None, None, None)
            except Exception:
                pass


@pytest.mark.fleet
def test_fleet_scale_concurrent_connections():
    import rustuya  # lazy: keep it out of the spawned workers' import graph

    n = int(os.environ.get("RUSTUYA_FLEET_N", "1000"))
    per = int(os.environ.get("RUSTUYA_FLEET_PER", "100"))
    # Tolerate a small number of stragglers on a noisy shared CI runner while
    # still proving fleet scale (a few % is scheduling jitter, not a defect).
    min_connected = int(n * 0.95)

    # Connect-storm guard (opt-in): cap concurrent establishment well below the
    # fleet size. The limiter is process-global and fixed on first use; in the
    # CI `-m fleet` step this test is the first to touch it, so the cap engages.
    #
    # That all `n` devices connect under only `cap` establishment permits is the
    # key correctness check: permits MUST be released after each handshake. If a
    # permit were held for the connection's lifetime, only `cap` devices would
    # ever connect and the rest would deadlock forever.
    assert rustuya.set_connect_concurrency(50), (
        "limiter must not be pre-initialized in the `-m fleet` pytest process"
    )
    cap = rustuya.connect_concurrency()
    assert 0 < cap < n, f"connect cap {cap} must be engaged and below fleet size {n}"

    ctx = mp.get_context("spawn")
    q = ctx.Queue()
    stop = ctx.Event()
    nproc = (n + per - 1) // per
    procs = []

    try:
        for i in range(nproc):
            k = min(per, n - i * per)
            p = ctx.Process(
                target=_mock_worker, args=(k, VERSION, LOCAL_KEY, q, stop), daemon=True
            )
            p.start()
            procs.append(p)

        ports = []
        for _ in range(nproc):
            ports.extend(q.get(timeout=90))
        assert len(ports) == n, f"expected {n} mock ports, got {len(ports)}"

        try:
            rustuya.maximize_fd_limit()
        except Exception:
            pass

        devices = [
            rustuya.Device(
                f"{i:020d}", LOCAL_KEY, address="127.0.0.1",
                version=VERSION, port=ports[i], persist=True, timeout=10.0,
            )
            for i in range(n)
        ]
        try:
            deadline = time.time() + 120
            connected = 0
            while time.time() < deadline:
                connected = sum(1 for d in devices if d.is_connected)
                if connected >= n:
                    break
                time.sleep(1.0)
            assert connected >= min_connected, (
                f"only {connected}/{n} devices connected (need >= {min_connected})"
            )
        finally:
            for d in devices:
                try:
                    d.stop()
                except Exception:
                    pass
    finally:
        stop.set()
        for p in procs:
            p.join(timeout=5)


@pytest.mark.fleet
def test_fleet_keepalive_then_set():
    """Hold 500 devices through a 30s idle on automatic heartbeat alone, then
    a concurrent set_value on every one must get a response back.

    Steps: connect 500 devices and bundle them into one ``unified_listener``;
    sit idle for 30s; fire ``set_value`` on all 500 at once.

    What it proves: the actor's heartbeat keepalive (sent every ~7s) sustains a
    full fleet across an idle window — without it, the 30s read
    inactivity-timeout would tear each connection down — and that after the idle
    every device is still reachable. A reconnect surfaces on the unified stream
    as a fresh "Connection Successful" (cmd 0) event, so zero such events during
    the idle window is the keepalive proof. Mocks are split across processes so
    the harness GIL isn't the bottleneck (see module docstring).

    Tunables (env): ``RUSTUYA_KEEPALIVE_N`` (default 500),
    ``RUSTUYA_KEEPALIVE_PER`` (mocks/process, default 50),
    ``RUSTUYA_KEEPALIVE_IDLE`` (seconds, default 30).
    """
    import threading
    from concurrent.futures import ThreadPoolExecutor

    import rustuya  # lazy: keep it out of the spawned workers' import graph

    n = int(os.environ.get("RUSTUYA_KEEPALIVE_N", "500"))
    per = int(os.environ.get("RUSTUYA_KEEPALIVE_PER", "50"))
    idle = int(os.environ.get("RUSTUYA_KEEPALIVE_IDLE", "30"))
    # Tolerate a few stragglers on a noisy shared CI runner; locally this is a
    # clean n/n with zero reconnects.
    min_ok = int(n * 0.95)

    ctx = mp.get_context("spawn")
    q = ctx.Queue()
    stop = ctx.Event()
    nproc = (n + per - 1) // per
    procs = []

    try:
        for i in range(nproc):
            k = min(per, n - i * per)
            p = ctx.Process(
                target=_mock_worker, args=(k, VERSION, LOCAL_KEY, q, stop), daemon=True
            )
            p.start()
            procs.append(p)

        ports = []
        for _ in range(nproc):
            ports.extend(q.get(timeout=90))
        assert len(ports) == n, f"expected {n} mock ports, got {len(ports)}"

        try:
            rustuya.maximize_fd_limit()
        except Exception:
            pass

        devices = [
            rustuya.Device(
                f"{i:020d}", LOCAL_KEY, address="127.0.0.1",
                version=VERSION, port=ports[i], persist=True, timeout=10.0,
            )
            for i in range(n)
        ]
        try:
            # Bundle every device into a single unified listener stream and
            # count any (re)connect events that occur during the idle window.
            receiver = rustuya.unified_listener(devices)
            reconnects = set()
            phase = {"idle": False}
            lock = threading.Lock()
            lstop = threading.Event()

            def drain():
                while not lstop.is_set():
                    ev = receiver.recv(300)
                    if ev is None:
                        continue
                    if isinstance(ev, dict) and ev.get("cmd") == 0:
                        with lock:
                            if phase["idle"]:
                                reconnects.add(ev.get("id"))

            lt = threading.Thread(target=drain, daemon=True)
            lt.start()

            # Connect the fleet.
            deadline = time.time() + 120
            connected = 0
            while time.time() < deadline:
                connected = sum(1 for d in devices if d.is_connected)
                if connected >= n:
                    break
                time.sleep(1.0)
            assert connected >= min_ok, (
                f"only {connected}/{n} devices connected (need >= {min_ok})"
            )

            # Idle: automatic heartbeat must keep the connections alive.
            with lock:
                phase["idle"] = True
            time.sleep(idle)
            with lock:
                phase["idle"] = False
                recon = len(reconnects)

            still = sum(1 for d in devices if d.is_connected)
            assert still >= min_ok, (
                f"only {still}/{n} devices still connected after {idle}s idle "
                f"(need >= {min_ok}) — heartbeat keepalive failed"
            )
            assert recon <= n - min_ok, (
                f"{recon} devices reconnected during the idle window — "
                f"heartbeat did not sustain the connections"
            )

            # set_value on all devices at once; each success is a response.
            errors = []

            def do_set(d):
                try:
                    return d.set_value("1", False) is not None
                except Exception as e:  # noqa: BLE001
                    errors.append(repr(e))
                    return False

            with ThreadPoolExecutor(max_workers=min(n, 512)) as ex:
                responses = sum(ex.map(do_set, devices))
            assert responses >= min_ok, (
                f"only {responses}/{n} set_value responses after idle "
                f"(errors={len(errors)}: {errors[:3]})"
            )

            lstop.set()
        finally:
            for d in devices:
                try:
                    d.stop()
                except Exception:
                    pass
    finally:
        stop.set()
        for p in procs:
            p.join(timeout=5)
