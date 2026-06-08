#!/usr/bin/env python3
"""Generate the tinytuya payload parity fixture used by tests/tinytuya_parity.rs.

tinytuya is treated as the *reference* implementation: for every
(version x dev_type x command x data) combination we call
``Device.generate_payload`` and record the command code it sends plus the
JSON payload it produces. The Rust test then feeds the identical inputs to
rustuya's payload generator and asserts the output matches (modulo the
documented KNOWN_DIVERGENCES allowlist on the Rust side).

The wall clock is pinned so the embedded ``t`` field is deterministic and the
fixture is reproducible / diffable in git.

Run from the rustuya repo root with the venv that has tinytuya installed:

    /home/ubuntu/script/modules/tuya/bin/python \
        tests/fixtures/gen_tinytuya_payloads.py

This rewrites tests/fixtures/tinytuya_payloads.json in place.
"""

import json
import os
import time

# --- pin the clock so generate_payload's `t` is deterministic ---------------
FIXED_T = 1700000000
time.time = lambda: float(FIXED_T)  # noqa: E731  (tinytuya calls time.time())

import tinytuya  # noqa: E402  (must come after the time monkeypatch)
from tinytuya.core.XenonDevice import XenonDevice  # noqa: E402

# tinytuya.set_version(3.2) coerces dev_type -> "device22" and calls
# detect_available_dps(), which does live network I/O. We pin version/dev_type
# by direct attribute assignment instead (exactly how the maintainer drives it
# in the REPL), so set_version and the detector are never reached. Stub the
# detector anyway as insurance so no future code path can touch the wire.
XenonDevice.detect_available_dps = lambda self, *a, **k: {}

# A 22-char device id keeps the "device22" code path plausible. The exact value
# is irrelevant as long as the Rust side uses the same string.
DEVID = "01234567890123456789ab"
LOCAL_KEY = "0123456789abcdef"
ADDRESS = "127.0.0.1"  # non-empty, non-"Auto", non-"0.0.0.0" => no network scan

VERSIONS = [3.1, 3.2, 3.3, 3.4, 3.5]
DEV_TYPES = ["default", "device22"]

# (rustuya CommandType variant name, tinytuya command constant)
COMMANDS = [
    ("ApConfig", tinytuya.AP_CONFIG),
    ("Control", tinytuya.CONTROL),
    ("Status", tinytuya.STATUS),
    ("HeartBeat", tinytuya.HEART_BEAT),
    ("DpQuery", tinytuya.DP_QUERY),
    ("ControlNew", tinytuya.CONTROL_NEW),
    ("DpQueryNew", tinytuya.DP_QUERY_NEW),
    ("UpdateDps", tinytuya.UPDATEDPS),
    ("SceneExecute", tinytuya.SCENE_EXECUTE),  # not in payload_dict -> generic
    ("ReqDevInfo", tinytuya.REQ_DEVINFO),      # not in payload_dict -> generic
    ("LanExtStream", tinytuya.LAN_EXT_STREAM),
]


def data_variants(rust_name):
    """The `data` argument variants to exercise per command.

    `None` is always included. UpdateDps takes a dpId list rather than a dps
    map, so its non-None variant is a list. Everything else gets a simple dps
    map.
    """
    if rust_name == "UpdateDps":
        return [None, [1, 5, 7]]
    if rust_name == "LanExtStream":
        # The realistic call: tinytuya splits the body (rawData) and the
        # reqType string into separate args; rustuya's caller merges reqType
        # into the data dict and the protocol hoists it back out (see
        # Device::sub_discover). We record the *rustuya-side* merged dict here;
        # the generator splits it for the tinytuya call below.
        return [{"reqType": "subdev_online_stat_query", "cids": []}]
    return [None, {"1": True, "2": "x"}]


def main():
    # Construct once at 3.1 (a version with no special set_version side effects)
    # and then pin (version, dev_type) by direct attribute assignment per combo,
    # mirroring the maintainer's REPL workflow. This deliberately bypasses
    # set_version() so 3.2 is NOT auto-coerced to device22 and nothing touches
    # the network.
    dev = tinytuya.Device(
        DEVID, address=ADDRESS, local_key=LOCAL_KEY, dev_type="default", version=3.1
    )
    # tinytuya seeds `dps_to_request` to {"1": None} the moment it detects a
    # device22 ("set at least one DPS", XenonDevice.py) — that is what a real
    # device22 `status()` puts in `dps`. Mirror it so the fixture reflects real
    # on-wire behaviour rather than the empty {} you'd get from stubbing out the
    # (network) detect_available_dps bruteforce.
    dev.dps_to_request = {"1": None}

    cases = []
    for version in VERSIONS:
        for dev_type in DEV_TYPES:
            # tinytuya's set_version(3.2) forces dev_type="device22" ("3.2
            # behaves like 3.3 with device22"), so a real v3.2 device is ALWAYS
            # device22 regardless of the requested dev_type. Model that for the
            # tinytuya reference; the recorded `dev_type` below stays the loop
            # value so the test still exercises both rustuya get_protocol inputs.
            tt_dev_type = "device22" if version == 3.2 else dev_type
            dev.version = version
            dev.version_str = f"v{version:.1f}"  # e.g. "v3.2"; keys payload_dict
            dev.dev_type = tt_dev_type
            dev.payload_dict = None  # force rebuild for this (version, dev_type)
            dev.last_dev_type = ""
            for rust_name, cmd_const in COMMANDS:
                for data in data_variants(rust_name):
                    if rust_name == "LanExtStream":
                        # Split the merged dict back into tinytuya's rawData +
                        # reqType params, matching how the real client calls it.
                        body = {k: v for k, v in data.items() if k != "reqType"}
                        msg = dev.generate_payload(
                            cmd_const, rawData=body, reqType=data["reqType"]
                        )
                    else:
                        msg = dev.generate_payload(cmd_const, data=data)
                    payload = json.loads(msg.payload.decode("utf-8"))
                    cases.append(
                        {
                            "version": f"{version:.1f}",
                            "dev_type": dev_type,
                            "command": rust_name,
                            "tinytuya_const": cmd_const,
                            "data": data,
                            "t": FIXED_T,
                            "expected_cmd": msg.cmd,
                            "expected_payload": payload,
                        }
                    )

    out = {
        "_comment": (
            "Auto-generated by gen_tinytuya_payloads.py from tinytuya "
            f"{getattr(tinytuya, 'version', '?')}. tinytuya is the reference; "
            "do not hand-edit. Regenerate with the script."
        ),
        "tinytuya_version": getattr(tinytuya, "version", "?"),
        "device_id": DEVID,
        "fixed_t": FIXED_T,
        "cases": cases,
    }

    out_path = os.path.join(os.path.dirname(__file__), "tinytuya_payloads.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print(f"wrote {len(cases)} cases to {out_path}")


if __name__ == "__main__":
    main()
