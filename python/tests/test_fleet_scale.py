"""Fleet-scale tests against the tuyamock emulator.

The mocks are split across separate processes (~``PER`` each) in case the GIL
becomes a bottleneck with many mocks in one process at high device counts — a
harness concern, not a rustuya limit.

Tunables (env): ``RUSTUYA_FLEET_N`` (default 1000), ``RUSTUYA_FLEET_PER``
(mocks per worker process, default 100).
"""

import os
import time
import multiprocessing as mp

import pytest

LOCAL_KEY = "thisisarealkey00"
# Default v3.3 (no session handshake) keeps the fleet path the focus; override
# with RUSTUYA_FLEET_VERSION to exercise the v3.4/v3.5 session-key handshake at
# scale.
VERSION = os.environ.get("RUSTUYA_FLEET_VERSION", "3.3")


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
    # Require a clean 100%: every device must connect.
    min_connected = n

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
    """Connect 500 devices into one unified listener, idle 30s, then set_value all.

    Checks that automatic heartbeat keeps the whole fleet alive across the idle
    window (zero reconnects — a reconnect shows on the stream as a cmd-0
    "Connection Successful"), then exercises both set_value response modes:
    ``nowait=False`` returns each device's response directly; ``nowait=True`` is
    fire-and-forget (returns None) so the responses are counted on the unified
    listener instead.

    Tunables (env): ``RUSTUYA_KEEPALIVE_N`` (500), ``RUSTUYA_KEEPALIVE_PER`` (50),
    ``RUSTUYA_KEEPALIVE_IDLE`` (30s).
    """
    import threading
    from concurrent.futures import ThreadPoolExecutor

    import rustuya  # lazy: keep it out of the spawned workers' import graph

    n = int(os.environ.get("RUSTUYA_KEEPALIVE_N", "500"))
    per = int(os.environ.get("RUSTUYA_KEEPALIVE_PER", "50"))
    idle = int(os.environ.get("RUSTUYA_KEEPALIVE_IDLE", "30"))
    # Require a clean 100%: all connect, all stay connected (zero reconnects),
    # all respond.
    min_ok = n

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
            assert recon == 0, (
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
