//! Per-device listener stream + multi-device unified listener.

use crate::error::{ERR_STATE, Result};
use crate::protocol::TuyaMessage;
use futures_core::stream::Stream;
use log::warn;
use serde::Serialize;

use super::Device;

impl Device {
    /// Returns a stream of broadcast messages from this device.
    ///
    /// The returned stream holds a strong reference to the device. As long as
    /// the stream is alive (e.g. owned by a spawned task or
    /// [`unified_listener`]), the device's background connection task stays
    /// alive too — even if the caller dropped their original `Device` handle.
    /// To force shutdown, call [`Device::stop`].
    pub fn listener(&self) -> impl Stream<Item = Result<TuyaMessage>> + Send + 'static {
        use tokio::sync::broadcast::error::RecvError;
        let mut rx = self.inner.broadcast_tx.subscribe();
        let device = self.clone();
        let cancel = self.inner.cancel_token.clone();
        async_stream::stream! {
            loop {
                tokio::select! {
                    // Honor explicit stop() while waiting on the broadcast.
                    // Without this branch the listener would only exit when
                    // broadcast_tx is dropped, which requires the very last
                    // Arc<DeviceInner> reference to disappear — and *we* are
                    // holding one of those refs ourselves.
                    () = cancel.cancelled() => break,
                    res = rx.recv() => match res {
                        Ok(msg) => {
                            if !msg.payload.is_empty() {
                                yield Ok(msg);
                            }
                        }
                        Err(RecvError::Lagged(skipped)) => {
                            warn!(
                                "Listener for device {} lagged behind broadcast, skipped {} messages",
                                device.inner.id, skipped
                            );
                            yield Ok(device.error_helper(
                                ERR_STATE,
                                Some(serde_json::json!({
                                    "reason": "listener_lagged",
                                    "skipped": skipped,
                                })),
                            ));
                        }
                        Err(RecvError::Closed) => break,
                    }
                }
            }
        }
    }
}

/// Represents an event from a specific device.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceEvent {
    /// The ID of the device that generated the event.
    pub device_id: String,
    /// The message received from the device.
    pub message: TuyaMessage,
}

/// Merges multiple device listeners into a single stream of events.
pub fn unified_listener(
    devices: Vec<Device>,
) -> impl Stream<Item = Result<DeviceEvent>> + Send + 'static {
    use futures_util::StreamExt;
    use futures_util::stream::select_all;

    let streams = devices.into_iter().map(|device| {
        let device_id = device.id().to_string();
        device
            .listener()
            .map(move |res| match res {
                Ok(message) => Ok(DeviceEvent {
                    device_id: device_id.clone(),
                    message,
                }),
                Err(e) => Err(e),
            })
            .boxed()
    });

    select_all(streams)
}

#[cfg(test)]
mod tests {
    //! Listener subsystem regression baseline.
    //!
    //! These lock in the current behavior of `Device::listener()` and
    //! `unified_listener(Vec<Device>)` so the upcoming UnifiedListener work
    //! has a safety net. Focus areas: lifecycle (no fd / task leaks under
    //! drop/stop), Arc-strong-ref accounting, lagged-broadcast synthetic,
    //! and "the stream stays alive after the caller drops the Device clone"
    //! contract that `unified_listener` relies on.
    //!
    //! No real sockets are bound — messages are injected directly into the
    //! device's broadcast bus via the crate-private `broadcast_tx` field.

    use super::*;
    use crate::Device;
    use crate::protocol::{PREFIX_55AA, TuyaMessage};
    use futures_util::StreamExt;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::timeout;

    fn make_test_device(id: &str) -> Device {
        Device::builder(id, b"0123456789abcdef".to_vec())
            .address("203.0.113.1") // TEST-NET-3 — never actually connects
            .persist(false)
            .build()
    }

    fn make_msg(cmd: u32, payload: &[u8]) -> TuyaMessage {
        TuyaMessage {
            seqno: 0,
            cmd,
            retcode: None,
            payload: payload.to_vec(),
            prefix: PREFIX_55AA,
            iv: None,
        }
    }

    // -------------------------------------------------------------------------
    // Device::listener() lifecycle
    // -------------------------------------------------------------------------

    /// Baseline: injected broadcast messages reach the listener stream.
    #[test]
    fn listener_yields_injected_broadcast() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let device = make_test_device("listener_yields");
            let stream = device.listener();
            tokio::pin!(stream);

            let msg = make_msg(0x0a, b"{\"hello\":\"world\"}");
            let _ = device.inner.broadcast_tx.send(msg.clone());

            let got = timeout(Duration::from_millis(200), stream.next())
                .await
                .expect("listener should yield within 200ms")
                .expect("stream not exhausted")
                .expect("stream yielded Err");
            assert_eq!(got.payload, msg.payload);
        });
    }

    /// Empty-payload broadcasts must be filtered out (existing contract).
    #[test]
    fn listener_filters_empty_payload() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let device = make_test_device("listener_filters");
            let stream = device.listener();
            tokio::pin!(stream);

            let _ = device.inner.broadcast_tx.send(make_msg(0x0a, b""));
            let _ = device.inner.broadcast_tx.send(make_msg(0x0a, b"{\"k\":1}"));

            let got = timeout(Duration::from_millis(200), stream.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            // The empty was dropped; we should see the non-empty one directly.
            assert_eq!(got.payload, b"{\"k\":1}");
        });
    }

    /// stop() must end the stream — without this, the listener could only
    /// exit on the very last Arc<DeviceInner> drop, which itself holds the
    /// stream alive. M2.2 invariant.
    #[test]
    fn listener_exits_on_stop() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let device = make_test_device("listener_exits_on_stop");
            let stream = device.listener();
            tokio::pin!(stream);

            // No messages — stream is parked on rx.recv(). Fire stop and the
            // cancel branch of the select! should win.
            device.fire_stop();

            let res = timeout(Duration::from_millis(500), stream.next()).await;
            match res {
                Ok(None) => {} // stream ended cleanly
                Ok(Some(_)) => panic!("listener yielded an item after stop"),
                Err(_) => panic!("listener did not exit within 500ms of stop()"),
            }
        });
    }

    /// The listener holds a strong Arc<DeviceInner>. Dropping the user-side
    /// Device clone must NOT terminate the stream (the unified_listener
    /// contract depends on this: caller can pass devices by value).
    #[test]
    fn listener_survives_user_device_drop() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let device = make_test_device("listener_survives_drop");
            let weak_inner = Arc::downgrade(&device.inner);
            let stream = device.listener();
            tokio::pin!(stream);

            // Send first while the device clone is alive.
            let _ = device.inner.broadcast_tx.send(make_msg(0x0a, b"a"));

            // Now drop the user's Device clone — the stream's internal clone
            // should keep DeviceInner alive.
            drop(device);
            assert!(
                weak_inner.upgrade().is_some(),
                "stream must keep DeviceInner alive"
            );

            // First message still readable.
            let got = timeout(Duration::from_millis(200), stream.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(got.payload, b"a");

            // Stream is still live — sending via the weak-upgraded inner works.
            let inner = weak_inner.upgrade().expect("inner still alive");
            let _ = inner.broadcast_tx.send(make_msg(0x0a, b"b"));
            drop(inner); // we don't need our extra ref
            let got = timeout(Duration::from_millis(200), stream.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(got.payload, b"b");
        });
    }

    /// Dropping the stream releases exactly the strong Arc<DeviceInner> it
    /// was holding — no Arc cycle, no leak.
    ///
    /// We pre-stop the device and poll until the background connection
    /// task has released its Arc, so the baseline is deterministic.
    /// Otherwise, with the rc.2 single-device jitter skip, the task can
    /// upgrade its Arc *between* the baseline and the post-drop sample
    /// and break the absolute-count assertion (the delta would still be
    /// right, but the test asserts absolute equality).
    #[test]
    fn dropping_stream_releases_arc() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let device = make_test_device("dropping_stream_arc");
            device.fire_stop();
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while Arc::strong_count(&device.inner) > 1 && std::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let baseline = Arc::strong_count(&device.inner);
            assert_eq!(
                baseline, 1,
                "after stop, only the user-held Arc should remain (got {baseline})"
            );

            let stream = device.listener();
            let with_stream = Arc::strong_count(&device.inner);
            assert_eq!(
                with_stream,
                baseline + 1,
                "listener stream must add exactly one Arc"
            );

            drop(stream);
            let after_drop = Arc::strong_count(&device.inner);
            assert_eq!(
                after_drop, baseline,
                "dropping the stream must release its Arc — no cycle, no leak"
            );
        });
    }

    /// Full lifecycle: after stop() and dropping every user handle, all
    /// strong Arcs to DeviceInner are released within bounded time.
    /// Catches a regression where the connection task or a stream task
    /// would keep DeviceInner alive after explicit shutdown.
    #[test]
    fn full_shutdown_releases_all_arcs() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let device = make_test_device("full_shutdown");
            let weak_inner = Arc::downgrade(&device.inner);
            let stream = device.listener();
            drop(stream);

            // Explicit stop fires cancel_token; both the connection task and
            // any remaining stream task observe it and drop their strong refs.
            device.fire_stop();
            drop(device);

            // Poll up to 2s for the background task to notice. (No fixed
            // sleep: tasks usually exit on the next scheduler tick.)
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while weak_inner.upgrade().is_some() && std::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(
                weak_inner.upgrade().is_none(),
                "DeviceInner must be fully released within 2s of stop+drop"
            );
        });
    }

    /// Multiple concurrent listeners on one device all see the same events.
    #[test]
    fn multiple_listeners_fan_out() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let device = make_test_device("listener_fanout");
            let s1 = device.listener();
            let s2 = device.listener();
            let s3 = device.listener();
            tokio::pin!(s1);
            tokio::pin!(s2);
            tokio::pin!(s3);

            let _ = device.inner.broadcast_tx.send(make_msg(0x0a, b"shared"));

            for stream in [&mut s1.as_mut(), &mut s2.as_mut(), &mut s3.as_mut()] {
                let got = timeout(Duration::from_millis(200), stream.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                assert_eq!(got.payload, b"shared");
            }
        });
    }

    /// Stress: 1000 listener spawn/drop cycles must not panic or grow
    /// unboundedly. Catches accidental task accumulation.
    #[test]
    fn listener_cycle_spawn_drop_does_not_leak() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let device = make_test_device("listener_cycle");
            for _ in 0..1000 {
                let stream = device.listener();
                drop(stream);
            }
            // If broadcast_tx accumulated unbounded receivers we'd see
            // memory blow up or a panic from broadcast::Sender. Reaching
            // here = pass. Also verify the device is still functional:
            let stream = device.listener();
            tokio::pin!(stream);
            let _ = device.inner.broadcast_tx.send(make_msg(0x0a, b"alive"));
            let got = timeout(Duration::from_millis(200), stream.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(got.payload, b"alive");
        });
    }

    // -------------------------------------------------------------------------
    // unified_listener(Vec<Device>) — current free-function behavior
    // -------------------------------------------------------------------------

    /// `unified_listener` consumes the Vec but inner clones keep devices
    /// alive — events from any device come through.
    #[test]
    fn unified_listener_yields_events_from_each_device() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let d1 = make_test_device("u_d1");
            let d2 = make_test_device("u_d2");
            // Keep our own clones so we can inject after move.
            let d1_keep = d1.clone();
            let d2_keep = d2.clone();

            let stream = unified_listener(vec![d1, d2]);
            tokio::pin!(stream);

            let _ = d1_keep.inner.broadcast_tx.send(make_msg(0x0a, b"from1"));
            let _ = d2_keep.inner.broadcast_tx.send(make_msg(0x0a, b"from2"));

            let mut seen: Vec<(String, Vec<u8>)> = Vec::new();
            for _ in 0..2 {
                let ev = timeout(Duration::from_millis(500), stream.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                seen.push((ev.device_id, ev.message.payload));
            }
            seen.sort();
            assert_eq!(
                seen,
                vec![
                    ("u_d1".to_string(), b"from1".to_vec()),
                    ("u_d2".to_string(), b"from2".to_vec()),
                ]
            );
        });
    }

    /// Drop the unified stream — both per-device listener tasks should exit.
    /// Verifies no "orphan listener task per device" leak.
    #[test]
    fn dropping_unified_stream_releases_per_device_listeners() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let d1 = make_test_device("u_drop_d1");
            let d2 = make_test_device("u_drop_d2");

            // Stash strong count baseline: 1 (user holds d1) + 1 (background
            // connection task) = 2 for each. Plus whatever the stream
            // captures (1 more per device). After drop, the +1 per stream
            // is released.
            let arc_count_before = Arc::strong_count(&d1.inner);

            let stream = unified_listener(vec![d1.clone(), d2.clone()]);
            let arc_count_during = Arc::strong_count(&d1.inner);
            assert!(
                arc_count_during > arc_count_before,
                "unified_listener should hold a strong ref while alive (before={arc_count_before}, during={arc_count_during})"
            );

            drop(stream);
            // Tokio cooperative drop — give it a yield to actually finalize.
            tokio::task::yield_now().await;

            let arc_count_after = Arc::strong_count(&d1.inner);
            assert!(
                arc_count_after <= arc_count_before,
                "dropping the unified stream must release the ref it held \
                 (before={arc_count_before}, during={arc_count_during}, after={arc_count_after})"
            );
        });
    }

    /// Stop one of the devices in a unified stream — events from the other
    /// still come through. (Current semantics: select_all loses one sub-
    /// stream but the merged stream continues.)
    #[test]
    fn stopping_one_device_does_not_kill_unified_stream() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let d1 = make_test_device("u_stop_d1");
            let d2 = make_test_device("u_stop_d2");
            let d1_keep = d1.clone();
            let d2_keep = d2.clone();

            let stream = unified_listener(vec![d1, d2]);
            tokio::pin!(stream);

            // Stop d1.
            d1_keep.fire_stop();
            tokio::task::yield_now().await;

            // Send from d2 — should still come through.
            let _ = d2_keep.inner.broadcast_tx.send(make_msg(0x0a, b"alive"));

            let ev = timeout(Duration::from_millis(500), stream.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(ev.device_id, "u_stop_d2");
            assert_eq!(ev.message.payload, b"alive");
        });
    }

    // -------------------------------------------------------------------------
    // Compile-time guarantees
    // -------------------------------------------------------------------------

    /// DeviceEvent must be Send + Sync — required for cross-thread fan-in.
    #[test]
    fn device_event_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DeviceEvent>();
    }

    /// The listener stream must be Send + 'static — required for
    /// `tokio::spawn` and use in `select_all`.
    #[allow(dead_code)]
    fn _listener_stream_is_send_static() {
        fn assert_send_static<T: Send + 'static>(_: T) {}
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let device = make_test_device("compile_check");
            assert_send_static(device.listener());
        });
    }

    // -------------------------------------------------------------------------
    // Hard concurrency / deadlock / leak detection
    // -------------------------------------------------------------------------

    /// Many concurrent listener creations across threads on a shared device.
    /// Catches deadlocks or panic from racing broadcast::subscribe().
    /// Wrapped in a global timeout so a deadlock fails the test instead of
    /// hanging CI forever.
    #[test]
    fn concurrent_listener_creation_no_deadlock() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let result = tokio::time::timeout(Duration::from_secs(5), async {
                let device = Arc::new(make_test_device("concurrent_creation"));
                let mut handles = Vec::new();
                for _ in 0..16 {
                    let d = Arc::clone(&device);
                    handles.push(tokio::spawn(async move {
                        // 50 listener spawn/drop iterations per task.
                        for _ in 0..50 {
                            let _stream = d.listener();
                            // Drop happens at scope end.
                        }
                    }));
                }
                for h in handles {
                    h.await.expect("worker task panicked");
                }
            })
            .await;
            assert!(
                result.is_ok(),
                "concurrent listener creation deadlocked or hung > 5s"
            );
        });
    }

    /// Concurrent broadcast send + multiple listeners reading. Stresses the
    /// broadcast channel under realistic fan-out load and ensures no
    /// listener gets stuck (which would manifest as a timeout).
    #[test]
    fn concurrent_publish_and_consume_no_starvation() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let result = tokio::time::timeout(Duration::from_secs(5), async {
                let device = Arc::new(make_test_device("publish_consume"));

                // 4 concurrent consumers.
                let mut consumers = Vec::new();
                for _ in 0..4 {
                    let d = Arc::clone(&device);
                    consumers.push(tokio::spawn(async move {
                        let stream = d.listener();
                        tokio::pin!(stream);
                        let mut count = 0;
                        // Read up to 100 messages or 2s, whichever first.
                        loop {
                            match tokio::time::timeout(Duration::from_millis(50), stream.next())
                                .await
                            {
                                Ok(Some(Ok(_))) => count += 1,
                                Ok(Some(Err(_))) | Ok(None) => break,
                                Err(_) => break, // idle for 50ms => done
                            }
                            if count >= 100 {
                                break;
                            }
                        }
                        count
                    }));
                }

                // 1 publisher firing 100 messages.
                let d_pub = Arc::clone(&device);
                let publisher = tokio::spawn(async move {
                    for i in 0..100u32 {
                        let payload = format!("{{\"n\":{i}}}");
                        let _ = d_pub
                            .inner
                            .broadcast_tx
                            .send(make_msg(0x0a, payload.as_bytes()));
                        // Yield to let consumers drain — without this, a slow
                        // consumer falls behind and broadcast lag synthetic
                        // fires (which is also a valid outcome, just noisier).
                        if i % 10 == 0 {
                            tokio::task::yield_now().await;
                        }
                    }
                });

                publisher.await.unwrap();
                let mut totals = Vec::new();
                for c in consumers {
                    totals.push(c.await.unwrap());
                }
                // Each consumer should have seen at least *some* messages.
                // We don't assert all 100 because of natural broadcast lag
                // behavior under contention, but no consumer should starve.
                for (i, t) in totals.iter().enumerate() {
                    assert!(
                        *t > 0,
                        "consumer {i} saw zero events — likely starved or deadlocked"
                    );
                }
            })
            .await;
            assert!(result.is_ok(), "publish+consume exceeded 5s timeout");
        });
    }

    /// Spawn 100 unified_listener streams in rapid succession, drop each
    /// immediately. Verifies per-device listener bookkeeping doesn't leak
    /// strong refs that pin DeviceInner forever.
    ///
    /// Baseline is taken after stopping the devices (so the background
    /// connection task's Arc has been released and the count is stable);
    /// otherwise the task waking from its initial jitter sleep mid-test
    /// adds a +1 of "noise" that masks any real per-iteration leak.
    #[test]
    fn unified_listener_cycle_does_not_leak_inner_arcs() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let d1 = make_test_device("ul_cycle_d1");
            let d2 = make_test_device("ul_cycle_d2");

            // Stop and wait for the background tasks to release their Arcs,
            // so baseline is deterministic.
            d1.fire_stop();
            d2.fire_stop();
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while (Arc::strong_count(&d1.inner) > 1 || Arc::strong_count(&d2.inner) > 1)
                && std::time::Instant::now() < deadline
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let baseline1 = Arc::strong_count(&d1.inner);
            let baseline2 = Arc::strong_count(&d2.inner);

            // listener() on a stopped device returns a stream that would
            // exit immediately on first poll, but we never poll it — we
            // just construct and drop. The Drop path is what we're
            // exercising.
            for _ in 0..100 {
                let s = unified_listener(vec![d1.clone(), d2.clone()]);
                drop(s);
            }

            let after1 = Arc::strong_count(&d1.inner);
            let after2 = Arc::strong_count(&d2.inner);
            assert_eq!(
                after1, baseline1,
                "d1 strong count grew under 100 unified_listener cycles ({baseline1} -> {after1})"
            );
            assert_eq!(
                after2, baseline2,
                "d2 strong count grew under 100 unified_listener cycles ({baseline2} -> {after2})"
            );
        });
    }

    /// Race: drop the unified stream while the publisher is mid-send.
    /// The send should not panic; the stream should drop cleanly.
    #[test]
    fn drop_unified_stream_during_publish_does_not_panic() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let result = tokio::time::timeout(Duration::from_secs(5), async {
                let device = make_test_device("drop_during_publish");
                let d_pub = device.clone();

                let publisher = tokio::spawn(async move {
                    for i in 0..1000u32 {
                        let payload = format!("{{\"n\":{i}}}");
                        let _ = d_pub
                            .inner
                            .broadcast_tx
                            .send(make_msg(0x0a, payload.as_bytes()));
                        if i % 50 == 0 {
                            tokio::task::yield_now().await;
                        }
                    }
                });

                // Spawn + drop the unified stream rapidly while the
                // publisher is firing.
                for _ in 0..20 {
                    let s = unified_listener(vec![device.clone()]);
                    tokio::task::yield_now().await;
                    drop(s);
                }
                publisher.await.unwrap();
            })
            .await;
            assert!(result.is_ok(), "drop-during-publish deadlocked or panicked");
        });
    }

    // 0.3.0-rc.2: Device::receive() previously swallowed `Lagged(n)` from the
    // broadcast bus and silently waited for the next message — a consumer
    // tracking state changes via every push would never know it had missed
    // any. Lock in the new contract: receive() returns
    // `Err(TuyaError::BroadcastLagged { skipped })` so the caller can react
    // (e.g. re-query state). `Device::listener()` continues to emit a
    // synthetic `listener_lagged` event on the stream, which is the natural
    // shape for a stream.
    //
    // Timing note: this uses `current_thread` runtime so the flood loop
    // holds the only thread end-to-end and the receive() task cannot be
    // preempted mid-flood (which would drain the bus before it overflows).
    // The pre-flood `yield_now` lets receive()'s subscribe complete, and
    // the post-flood `yield_now` hands the thread back so receive() can
    // observe the overflow.
    #[test]
    fn receive_returns_broadcast_lagged_when_consumer_falls_behind() {
        use crate::error::TuyaError;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let device = make_test_device("receive_lagged");
            let recv_task = {
                let d = device.clone();
                tokio::spawn(async move { d.receive().await })
            };
            // Yield so the spawned task runs its subscribe + first await on
            // recv. It will then park waiting for messages.
            tokio::task::yield_now().await;

            // Flood: 200 messages with capacity 128 ⇒ at least 72 dropped.
            // On current_thread runtime the parked task cannot be polled
            // mid-loop, so it sees the post-overflow state when we yield.
            for i in 0..200u32 {
                let payload = format!("{{\"n\":{i}}}");
                let _ = device
                    .inner
                    .broadcast_tx
                    .send(make_msg(0x0a, payload.as_bytes()));
            }

            let result = timeout(Duration::from_millis(500), recv_task)
                .await
                .expect("receive() should return within 500ms once flooded")
                .expect("spawned task panicked");
            match result {
                Err(TuyaError::BroadcastLagged { skipped }) => {
                    assert!(
                        skipped > 0,
                        "Lagged variant must carry a positive skip count"
                    );
                }
                other => panic!(
                    "expected Err(BroadcastLagged), got {other:?} — receive() \
                     regressed to silently swallowing lagged broadcasts"
                ),
            }
        });
    }

    // listener() side of the same property: stream yields a synthetic message
    // with `reason: "listener_lagged"` and `skipped: n`. (We don't assert
    // that the stream keeps yielding after the synthetic — broadcast retains
    // the most-recent CHAN_BROADCAST_CAPACITY messages, so the post-lag
    // yields would be those buffered floods, not a new message we send. The
    // "stream stays alive after a wakeup" property is covered by other
    // tests in this module.)
    #[test]
    fn listener_emits_synthetic_on_lag() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let device = make_test_device("listener_lagged");
            let stream = device.listener();
            tokio::pin!(stream);

            // Flood with 200 messages without consuming any.
            for i in 0..200u32 {
                let payload = format!("{{\"n\":{i}}}");
                let _ = device
                    .inner
                    .broadcast_tx
                    .send(make_msg(0x0a, payload.as_bytes()));
            }

            // First yield must be the synthetic lagged message.
            let got = timeout(Duration::from_millis(500), stream.next())
                .await
                .expect("stream should yield within 500ms")
                .expect("stream not exhausted")
                .expect("stream yielded transport Err");
            let payload_str =
                std::str::from_utf8(&got.payload).expect("synthetic payload must be UTF-8");
            assert!(
                payload_str.contains("listener_lagged"),
                "expected synthetic listener_lagged payload, got {payload_str}"
            );
            assert!(
                payload_str.contains("skipped"),
                "synthetic payload must include `skipped` count, got {payload_str}"
            );
        });
    }
}
