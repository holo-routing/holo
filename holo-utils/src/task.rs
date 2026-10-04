//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use derive_new::new;
use rand::RngExt;
use tokio::sync::mpsc;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::Instant;
use tokio::{task, time};
use tracing::{Instrument, error};

/// A handle which can be used to manipulate the task created by the
/// [`Task::spawn`] and [`Task::spawn_blocking`] functions.
///
/// By default, dropping this handle cancels the task (unless [`Task::detach`]
/// is used).
#[derive(Debug)]
pub struct Task<T> {
    join_handle: task::JoinHandle<T>,
    detached: bool,
}

/// A handle which can be used to manipulate the timeout task created by the
/// [`TimeoutTask::new`] function.
///
/// Dropping this handle cancels the timeout task.
#[derive(Debug)]
pub struct TimeoutTask {
    #[cfg(not(feature = "testing"))]
    inner: TimeoutTaskInner,
}

#[derive(Debug, new)]
struct TimeoutTaskInner {
    _task: Task<()>,
    control: UnboundedSender<Message>,
    next: Arc<Mutex<Instant>>,
}

/// A handle which can be used to manipulate the interval task created by the
/// [`IntervalTask::new`] function.
///
/// Dropping this handle cancels the interval task.
#[derive(Debug)]
pub struct IntervalTask {
    #[cfg(not(feature = "testing"))]
    inner: IntervalTaskInner,
}

#[derive(Debug, new)]
struct IntervalTaskInner {
    _task: Task<()>,
    control: UnboundedSender<Message>,
    next: Arc<Mutex<Instant>>,
}

#[derive(Debug)]
enum Message {
    Reset(Option<Duration>),
}

/// Variant of `tokio::select!` used to receive protocol input messages.
///
/// In deterministic mode, the channels are polled in a fixed order to make
/// message processing reproducible. During normal operation, they are polled
/// in random order so a busy channel can't starve the others.
///
/// The "deterministic" feature is evaluated in the invoking crate, which must
/// declare it.
#[doc(hidden)]
#[macro_export]
macro_rules! __protocol_select {
    ($($arms:tt)*) => {{
        #[cfg(feature = "deterministic")]
        {
            ::tokio::select! {
                biased;
                $($arms)*
            }
        }
        #[cfg(not(feature = "deterministic"))]
        {
            ::tokio::select! {
                $($arms)*
            }
        }
    }};
}

#[doc(inline)]
pub use crate::__protocol_select as protocol_select;

// ===== impl Task =====

impl<T> Task<T> {
    /// Spawns a new asynchronous task, returning a handle for it.
    pub fn spawn<Fut>(future: Fut) -> Task<T>
    where
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        Task {
            join_handle: task::spawn(future),
            detached: false,
        }
    }

    /// Spawns a supervised task that automatically restarts if it panics.
    /// The task will terminate if it completes successfully or returns an
    /// error.
    ///
    /// This is primarily useful for long-running network receive loops that
    /// may be exposed to malformed or malicious input. In such cases, it is
    /// often preferable to discard the offending packet and keep the task
    /// alive, rather than letting a panic bring down the entire routing
    /// instance.
    pub fn spawn_supervised<F, Fut>(spawn_fn: F) -> Task<()>
    where
        F: Fn() -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let join_handle = tokio::spawn(
            async move {
                loop {
                    let worker_task = Task::spawn(spawn_fn());
                    match worker_task.await {
                        Ok(_) => {
                            // Finished without panic.
                            break;
                        }
                        Err(error) if error.is_panic() => {
                            error!("task panicked, restarting...");
                            continue;
                        }
                        Err(error) => {
                            error!(%error, "task failed");
                            break;
                        }
                    }
                }
            }
            .in_current_span(),
        );
        Task {
            join_handle,
            detached: false,
        }
    }

    /// Runs the provided closure on a thread where blocking is acceptable.
    pub fn spawn_blocking<F>(f: F) -> Task<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        Task {
            join_handle: task::spawn_blocking(f),
            detached: false,
        }
    }

    /// Detach the task, meaning it will no longer be canceled if its handle is
    /// dropped.
    pub fn detach(&mut self) {
        self.detached = true;
    }
}

impl<T> Future for Task<T> {
    type Output = Result<T, task::JoinError>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        Pin::new(&mut self.join_handle).poll(cx)
    }
}

impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        if !self.detached {
            self.join_handle.abort();
        }
    }
}

// ===== impl TimeoutTask =====

impl TimeoutTask {
    /// Spawns a new task that will call the provided async closure when the
    /// specified timeout expires.
    ///
    /// Returns a handler that can be used to manipulate the timeout task.
    #[cfg(not(feature = "testing"))]
    pub fn new<F, Fut>(timeout: Duration, cb: F) -> TimeoutTask
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send,
    {
        let (control_tx, mut control_rx) = mpsc::unbounded_channel();

        let next = Instant::now() + timeout;
        let next = Arc::new(Mutex::new(next));
        let next_child = next.clone();

        let task = Task::spawn(
            async move {
                let timeout_fut = tokio::time::sleep(timeout);
                tokio::pin!(timeout_fut);

                loop {
                    tokio::select! {
                        // Timeout has expired.
                        _ = &mut timeout_fut => {
                            (cb)().await;
                            break;
                        }
                        message = control_rx.recv() => {
                            match message {
                                // Timeout has been refreshed/updated.
                                Some(Message::Reset(None)) => {
                                    let next = Instant::now() + timeout;
                                    timeout_fut.as_mut().reset(next);
                                    *next_child.lock().unwrap() = next;
                                },
                                Some(Message::Reset(Some(new_timeout))) => {
                                    let next = Instant::now() + new_timeout;
                                    timeout_fut.as_mut().reset(next);
                                    *next_child.lock().unwrap() = next;
                                },
                                // Timeout has been aborted.
                                None => break,
                            }
                        }
                    }
                }
            }
            .in_current_span(),
        );

        TimeoutTask {
            inner: TimeoutTaskInner::new(task, control_tx, next),
        }
    }

    /// Resets the timeout, regardless if it has already expired or not.
    ///
    /// If a new timeout value isn't specified, the last value will be reused.
    pub fn reset(&mut self, timeout: Option<Duration>) {
        #[cfg(not(feature = "testing"))]
        {
            if self.inner.control.send(Message::Reset(timeout)).is_err() {
                error!("failed to reset timeout");
            }
        }
    }

    /// Returns the remaining time before the timeout expires.
    pub fn remaining(&self) -> Duration {
        #[cfg(not(feature = "testing"))]
        {
            let next = self.inner.next.lock().unwrap();
            next.saturating_duration_since(Instant::now())
        }
        #[cfg(feature = "testing")]
        {
            Duration::ZERO
        }
    }
}

// ===== impl IntervalTask =====

impl IntervalTask {
    /// Spawns a new task that will call the provided async closure whenever the
    /// specified interval timer ticks.
    ///
    /// Returns a handler that can be used to manipulate the interval task.
    #[cfg(not(feature = "testing"))]
    pub fn new<F, Fut>(
        interval: Duration,
        tick_on_start: bool,
        cb: F,
    ) -> IntervalTask
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send,
    {
        IntervalTask::with_jitter(interval, 0, tick_on_start, cb)
    }

    /// Spawns a new task that will call the provided async closure whenever the
    /// specified interval timer ticks, with jitter applied to each period.
    ///
    /// Each period is drawn uniformly from the range
    /// `[interval * (1 - jitter / 100), interval]`, so the jitter only ever
    /// shortens the interval.
    ///
    /// Returns a handler that can be used to manipulate the interval task.
    #[cfg(not(feature = "testing"))]
    pub fn with_jitter<F, Fut>(
        interval: Duration,
        jitter: u8,
        tick_on_start: bool,
        mut cb: F,
    ) -> IntervalTask
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send,
    {
        let (control_tx, mut control_rx) = mpsc::unbounded_channel();

        let start = Instant::now() + jittered(interval, jitter);
        let next = Arc::new(Mutex::new(start));
        let next_child = next.clone();

        let task = Task::spawn(
            async move {
                let mut interval_fut = if tick_on_start {
                    time::interval(interval)
                } else {
                    time::interval_at(start, interval)
                };

                loop {
                    tokio::select! {
                        // Interval timer has ticked.
                        scheduled = interval_fut.tick() => {
                            let next = if jitter == 0 {
                                Instant::now() + interval_fut.period()
                            } else {
                                // Replace the next tick with a jittered one.
                                let period = interval_fut.period();
                                let next = scheduled + jittered(period, jitter);
                                interval_fut.reset_at(next);
                                next
                            };
                            (cb)().await;
                            *next_child.lock().unwrap() = next;
                        }
                        message = control_rx.recv() => {
                            match message {
                                // Interval timer has been updated.
                                Some(Message::Reset(None)) => {
                                    let next = Instant::now() + interval;
                                    interval_fut = time::interval(interval);
                                    *next_child.lock().unwrap() = next;
                                },
                                Some(Message::Reset(Some(new_interval))) => {
                                    let next = Instant::now() + new_interval;
                                    interval_fut = time::interval(new_interval);
                                    *next_child.lock().unwrap() = next;
                                },
                                // Interval timer has been aborted.
                                None => break,
                            }
                        }
                    }
                }
            }
            .in_current_span(),
        );

        IntervalTask {
            inner: IntervalTaskInner::new(task, control_tx, next),
        }
    }

    /// Resets the interval.
    ///
    /// If a new interval value isn't specified, the last value will be reused.
    pub fn reset(&mut self, timeout: Option<Duration>) {
        #[cfg(not(feature = "testing"))]
        {
            if self.inner.control.send(Message::Reset(timeout)).is_err() {
                error!("failed to reset interval");
            }
        }
    }

    /// Returns the remaining time before the next interval tick.
    pub fn remaining(&self) -> Duration {
        #[cfg(not(feature = "testing"))]
        {
            let next = self.inner.next.lock().unwrap();
            next.saturating_duration_since(Instant::now())
        }
        #[cfg(feature = "testing")]
        {
            Duration::ZERO
        }
    }
}

// ===== helper functions =====

// Shortens the interval by a random amount of up to `jitter` percent.
fn jittered(interval: Duration, jitter: u8) -> Duration {
    if jitter == 0 {
        return interval;
    }

    let min = 1.0 - f64::from(jitter.min(100)) / 100.0;
    interval.mul_f64(rand::rng().random_range(min..=1.0))
}
