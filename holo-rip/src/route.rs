//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::time::Duration;

use bitflags::bitflags;
use holo_protocol::InstanceChannelsTx;
use holo_utils::task::TimeoutTask;
use holo_utils::Sender;
use serde::{Deserialize, Serialize};

use crate::debug::Debug;
use crate::error::MetricError;
use crate::instance::Instance;
use crate::tasks;
use crate::tasks::messages::input::{RouteGcTimeoutMsg, RouteTimeoutMsg};
use crate::version::Version;

#[derive(Debug)]
pub struct Route<V: Version> {
    pub prefix: V::IpNetwork,
    pub ifindex: u32,
    pub source: Option<V::IpAddr>,
    pub nexthop: Option<V::IpAddr>,
    pub metric: Metric,
    pub rcvd_metric: Option<Metric>,
    pub tag: u16,
    pub route_type: RouteType,
    pub flags: RouteFlags,
    pub timeout_task: Option<TimeoutTask>,
    pub garbage_collect_task: Option<TimeoutTask>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Metric(u8);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteType {
    Connected,
    Rip,
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct RouteFlags: u8 {
        const CHANGED = 0x01;
    }
}

// ===== impl Route =====

impl<V> Route<V>
where
    V: Version,
{
    pub(crate) fn new(
        prefix: V::IpNetwork,
        ifindex: u32,
        source: Option<V::IpAddr>,
        metric: Metric,
        tag: u16,
        route_type: RouteType,
    ) -> Self {
        Debug::<V>::RouteCreate(&prefix, &source, &metric).log();

        Route {
            prefix,
            ifindex,
            source,
            nexthop: None,
            metric,
            rcvd_metric: None,
            tag,
            route_type,
            flags: RouteFlags::CHANGED,
            timeout_task: None,
            garbage_collect_task: None,
        }
    }

    pub(crate) fn invalidate(
        &mut self,
        flush_interval: u16,
        instance_channels_tx: &InstanceChannelsTx<Instance<V>>,
    ) {
        Debug::<V>::RouteInvalidate(&self.prefix).log();

        // Uninstall route.
        instance_channels_tx.sb.route_uninstall(self);

        // Set metric to infinite and start GC timeout.
        self.metric.set_infinite();
        self.flags.insert(RouteFlags::CHANGED);
        self.timeout_stop();
        self.garbage_collection_start(
            flush_interval,
            &instance_channels_tx.protocol_input.route_gc_timeout,
        );

        // Signal the output process to trigger an update.
        instance_channels_tx.protocol_input.trigger_update();
    }

    pub(crate) fn timeout_reset(
        &mut self,
        timeout: u16,
        route_timeoutp: &Sender<RouteTimeoutMsg<V>>,
    ) {
        let timeout = Duration::from_secs(timeout.into());

        if let Some(timeout_task) = &mut self.timeout_task {
            // Reset existing timeout task.
            timeout_task.reset(Some(timeout));
        } else {
            // Create new timeout task.
            let timeout_task =
                tasks::route_timeout(self.prefix, timeout, route_timeoutp);
            self.timeout_task = Some(timeout_task);
        }
    }

    fn timeout_stop(&mut self) {
        self.timeout_task = None;
    }

    pub(crate) fn timeout_remaining(&self) -> Option<Duration> {
        self.timeout_task.as_ref().map(TimeoutTask::remaining)
    }

    pub(crate) fn garbage_collection_start(
        &mut self,
        timeout: u16,
        route_gc_timeoutp: &Sender<RouteGcTimeoutMsg<V>>,
    ) {
        let timeout = Duration::from_secs(timeout.into());
        let garbage_collect_task =
            tasks::route_gc_timeout(self.prefix, timeout, route_gc_timeoutp);
        self.garbage_collect_task = Some(garbage_collect_task);
    }

    pub(crate) fn garbage_collection_stop(&mut self) {
        self.garbage_collect_task = None;
    }
}

// ===== impl Metric =====

impl Metric {
    pub const INFINITE: u8 = 16;

    pub(crate) fn new(metric: impl TryInto<u8>) -> Result<Self, MetricError> {
        match metric.try_into() {
            Ok(metric) => {
                // Validate metric.
                if metric == 0 || metric > Self::INFINITE {
                    return Err(MetricError::InvalidValue);
                }

                Ok(Metric(metric))
            }
            Err(_) => Err(MetricError::InvalidValue),
        }
    }

    pub(crate) fn get(&self) -> u8 {
        self.0
    }

    pub(crate) fn add(&mut self, metric: Metric) {
        self.0 = std::cmp::min(self.0 + metric.0, Self::INFINITE);
    }

    pub(crate) fn set_infinite(&mut self) {
        self.0 = Self::INFINITE
    }

    pub(crate) fn is_infinite(&self) -> bool {
        self.0 == Self::INFINITE
    }
}

impl From<u8> for Metric {
    // This function panics on error. It should only be used when the metric has
    // already been previously validated (e.g. by YANG).
    fn from(metric: u8) -> Metric {
        Metric::new(metric).expect("Invalid metric value")
    }
}
