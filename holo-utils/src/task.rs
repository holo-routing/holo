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
        mut cb: F,
    ) -> IntervalTask
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send,
    {
        let (control_tx, mut control_rx) = mpsc::unbounded_channel();

        let next = Instant::now() + interval;
        let next = Arc::new(Mutex::new(next));
        let next_child = next.clone();

        let task = Task::spawn(
            async move {
                let mut interval_fut = if tick_on_start {
                    time::interval(interval)
                } else {
                    let start = Instant::now() + interval;
                    time::interval_at(start, interval)
                };

                loop {
                    tokio::select! {
                        // Interval timer has ticked.
                        _ = interval_fut.tick() => {
                            let next = Instant::now() + interval;
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
