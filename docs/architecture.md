# Architecture

- Core modules
  - Crypto: [crypto.rs]({{ site.github_url }}/blob/master/src/crypto.rs)
  - Protocol: [protocol/mod.rs]({{ site.github_url }}/blob/master/src/protocol/mod.rs)
  - Device: [device.rs]({{ site.github_url }}/blob/master/src/device.rs)
  - Scanner: [scanner.rs]({{ site.github_url }}/blob/master/src/scanner.rs)
  - Manager: [manager.rs]({{ site.github_url }}/blob/master/src/manager.rs)
  - Runtime: [runtime.rs]({{ site.github_url }}/blob/master/src/runtime.rs)

- Synchronous wrappers
  - The [sync.rs]({{ site.github_url }}/blob/master/src/sync.rs) module bridges the async core into sync APIs.

- Python bindings
  - The [python/src/lib.rs]({{ site.github_url }}/blob/master/python/src/lib.rs) module exposes classes.
