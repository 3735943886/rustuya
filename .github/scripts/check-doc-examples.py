#!/usr/bin/env python3
"""Compile the public 0.4 guide examples as no_run doctests."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
guides = ("getting-started.md", "rust-api.md", "discovery.md", "MIGRATING-0.4.md")
with tempfile.TemporaryDirectory(prefix="rustuya-doc-examples-") as directory:
    crate = Path(directory)
    (crate / "src").mkdir()
    (crate / "Cargo.toml").write_text(
        '[package]\nname="rustuya-doc-examples"\nversion="0.0.0"\nedition="2024"\n'
        '[dependencies]\nrustuya={path=' + json.dumps(str(root / "rustuya"))
        + ',features=["tokio"]}\n'
        'tokio={version="1",features=["rt-multi-thread","macros","time"]}\n'
    )
    shutil.copyfile(root / "Cargo.lock", crate / "Cargo.lock")
    (crate / "src/lib.rs").write_text("\n".join(
        f'#[doc = include_str!({json.dumps(str(root / "docs" / guide))})]\n'
        f'pub mod example_{i} {{}}'
        for i, guide in enumerate(guides)
    ))
    env = dict(os.environ)
    env.setdefault("CARGO_TARGET_DIR", str(root / "target"))
    subprocess.run(
        ["cargo", "test", "--offline", "--manifest-path", str(crate / "Cargo.toml"), "--doc"],
        env=env, check=True,
    )
