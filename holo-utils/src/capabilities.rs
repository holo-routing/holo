//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::future::Future;
use std::pin::Pin;

use capctl::caps::CapState;
use tracing::error;

/// Runs the provided closure with elevated capabilities.
pub fn raise<F, R>(cb: F) -> R
where
    F: FnOnce() -> R,
{
    // Raise capabilities.
    let mut caps = CapState::get_current().unwrap();
    caps.effective = caps.permitted;
    if let Err(error) = caps.set_current() {
        error!("failed to update current capabilities: {}", error);
    }

    // Run closure.
    let ret = cb();

    // Drop capabilities.
    caps.effective.clear();
    if let Err(error) = caps.set_current() {
        error!("failed to update current capabilities: {}", error);
    }

    // Return the closure's return value.
    ret
}

/// Runs the provided async closure with elevated capabilities.
pub async fn raise_async<F, R>(cb: F) -> R
where
    F: Fn() -> Pin<Box<dyn Future<Output = R> + Send>>,
{
    // Raise capabilities.
    let mut caps = CapState::get_current().unwrap();
    caps.effective = caps.permitted;
    if let Err(error) = caps.set_current() {
        error!("failed to update current capabilities: {}", error);
    }

    // Run async closure.
    let ret = cb().await;

    // Drop capabilities.
    caps.effective.clear();
    if let Err(error) = caps.set_current() {
        error!("failed to update current capabilities: {}", error);
    }

    // Return the closure's return value.
    ret
}
