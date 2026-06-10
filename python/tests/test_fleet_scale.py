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
@pytest.mark.parametrize("nowait", [False, True], ids=["wait", "nowait"])
def test_fleet_keepalive_then_set(nowait):
    """Hold 500 devices through a 30s idle on automatic heartbeat alone, then
    a concurrent set_value on every one, in both response modes.

    Steps: connect 500 devices and bundle them into one ``unified_listener``;
    sit idle for 30s; fire ``set_value`` on all 500 at once.

    What it proves:

    * **Heartbeat keepalive** — the actor's heartbeat (sent every ~7s) sustains
      a full fleet across the idle window; without it the 30s read
      inactivity-timeout would tear each connection down. A reconnect surfaces
      on the unified stream as a fresh "Connection Successful" (cmd 0) event, so
      zero of those during the idle window is the keepalive proof.
    * **set_value response paths** — two modes, parametrized:
        - ``nowait=False`` (default): each ``set_value`` waits for and returns
          the device's response, so all 500 returns are non-None.
        - ``nowait=True``: ``set_value`` is fire-and-forget (returns None
          immediately); the responses instead arrive asynchronously on the
          unified listener, so we count distinct responding devices there. This
          is the only way to observe responses in nowait mode, which is exactly
          why the listener bundle matters here.

    Mocks are split across processes so the harness GIL isn't the bottleneck
    (see module docstring).

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
                nowait=nowait,
            )
            for i in range(n)
        ]
        try:
            # Bundle every device into a single unified listener stream. During
            # the idle window we count (re)connect events (cmd 0); during the
            # post-set "collect" window we count distinct responding devices.
            receiver = rustuya.unified_listener(devices)
            reconnects, responders = set(), set()
            phase = {"name": "connect"}
            lock = threading.Lock()
            lstop = threading.Event()

            def drain():
                while not lstop.is_set():
                    ev = receiver.recv(300)
                    if ev is None or not isinstance(ev, dict):
                        continue
                    did, cmd = ev.get("id"), ev.get("cmd")
                    with lock:
                        if phase["name"] == "idle" and cmd == 0:
                            reconnects.add(did)
                        elif phase["name"] == "collect":
                            responders.add(did)

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
                phase["name"] = "idle"
            time.sleep(idle)
            with lock:
                phase["name"] = "collect"
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

            # set_value on all devices at once.
            errors = []

            def do_set(d):
                try:
                    return d.set_value("1", False)
                except Exception as e:  # noqa: BLE001
                    errors.append(repr(e))
                    return "ERR"

            with ThreadPoolExecutor(max_workers=min(n, 512)) as ex:
                returns = list(ex.map(do_set, devices))
            assert not errors, f"{len(errors)} set_value errors: {errors[:3]}"

            if nowait:
                # Fire-and-forget: every call returns None; the responses arrive
                # asynchronously on the unified listener instead.
                assert all(r is None for r in returns), (
                    "nowait=True set_value must return None (fire-and-forget)"
                )
                time.sleep(5)  # let responses stream in on the listener
                with lock:
                    resp = len(responders)
                assert resp >= min_ok, (
                    f"only {resp}/{n} responses arrived on the unified listener "
                    f"(need >= {min_ok})"
                )
            else:
                # Waited: each call returns the device's response.
                responses = sum(1 for r in returns if r is not None)
                assert responses >= min_ok, (
                    f"only {responses}/{n} set_value responses (need >= {min_ok})"
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
