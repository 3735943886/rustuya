---
title: Frequently asked questions for 0.4
---

# Frequently asked questions for 0.4

## Where are the Python and synchronous APIs?

They remain on 0.3.x. Use the [0.3 archive](0.3/index.md), including the
[Python guide](0.3/python-api.md) and [Rust async/sync guide](0.3/rust-api.md).
0.4 currently provides the pure core and Tokio driver.

## Why does `rustuya::Device` no longer compile?

Enable the `tokio` feature and import `rustuya::tokio::Device`. The facade has
no default driver. See [Migrating from 0.3](MIGRATING-0.4.md).

## Why does `query()` return `()` instead of status?

It returns after queuing. Subscribe to `listener()` before sending and consume
`Event::Frame`. Replies and unsolicited updates share that stream. Use
`watch_status()` for the last non-empty frame, or maintain your own merged DPS map.

## Why does discovery find nothing?

Check that the host and devices share an IPv4 broadcast domain, UDP discovery
traffic is allowed, and the correct interface is selected. On multi-interface
hosts, configure the discovery builder's `local_ips`. Discovery does not obtain
local keys; supply your device's key when building a connection.

## Why does connection authentication fail?

Check the local key and protocol version. Inspect `watch_error()` or the error
from `wait_connected()` rather than treating every failure as a network timeout.
Addressless `discover()` uses the version reported by the device.

## Does `Version::Auto` try every version?

No. Without a discovery-resolved version it uses a 3.3 wire profile. Set the
known protocol version or use `discover()`; Auto is not a handshake brute-force scan.

## Does `close()` deliver commands that were just queued?

No. It stops the actor and discards pending commands and partial writes. Observe
the application-level result you need before closing. A successful send only
means the command entered the queue.

## Can I run this on ESP32?

The core supports `no_std + alloc`, but 0.4 does not ship an ESP32/Embassy driver.
See [Architecture](architecture.md) and the [milestones](MILESTONES.md).
