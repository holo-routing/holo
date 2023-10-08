//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use tracing::{debug, debug_span};

use crate::interface::InterfaceUp;
use crate::route::Metric;
use crate::version::Version;

// RIP debug messages.
#[derive(Debug)]
pub enum Debug<'a, V: Version> {
    InstanceCreate,
    InstanceDelete,
    InstanceStart,
    InstanceStop(InstanceInactiveReason),
    InstanceStatusCheck(&'a str),
    InterfaceCreate(&'a str),
    InterfaceDelete(&'a str),
    InterfaceStart(&'a str),
    InterfaceStop(&'a str, InterfaceInactiveReason),
    InitialUpdate,
    UpdateInterval,
    TriggeredUpdate,
    PduRx(
        &'a InterfaceUp<V>,
        &'a V::IpAddr,
        &'a Result<V::Pdu, V::PduDecodeError>,
    ),
    PduTx(&'a InterfaceUp<V>, &'a V::Pdu),
    NbrCreate(&'a V::IpAddr),
    NbrTimeout(&'a V::IpAddr),
    RouteCreate(&'a V::IpNetwork, &'a Option<V::IpAddr>, &'a Metric),
    RouteUpdate(&'a V::IpNetwork, &'a Option<V::IpAddr>, &'a Metric),
    RouteTimeout(&'a V::IpNetwork),
    RouteGcTimeout(&'a V::IpNetwork),
    RouteInvalidate(&'a V::IpNetwork),
}

// Reason why an RIP instance is inactive.
#[derive(Debug)]
pub enum InstanceInactiveReason {
    AdminDown,
}

// Reason why RIP is inactive on an interface.
#[derive(Debug)]
pub enum InterfaceInactiveReason {
    InstanceDown,
    AdminDown,
    OperationalDown,
    MissingIfindex,
    MissingIpAddress,
}

// ===== impl Debug =====

impl<'a, V> Debug<'a, V>
where
    V: Version,
{
    // Log debug message using the tracing API.
    pub(crate) fn log(&self) {
        match self {
            Debug::InstanceCreate
            | Debug::InstanceDelete
            | Debug::InstanceStart => {
                // Parent span(s): rip-instance
                debug!("{}", self);
            }
            Debug::InstanceStop(reason) => {
                // Parent span(s): rip-instance
                debug!(%reason, "{}", self);
            }
            Debug::InstanceStatusCheck(status) => {
                // Parent span(s): rip-instance
                debug!(%status, "{}", self);
            }
            Debug::InterfaceCreate(name)
            | Debug::InterfaceDelete(name)
            | Debug::InterfaceStart(name) => {
                // Parent span(s): rip-instance
                debug_span!("interface", %name).in_scope(|| {
                    debug!("{}", self);
                });
            }
            Debug::InterfaceStop(name, reason) => {
                // Parent span(s): rip-instance
                debug_span!("interface", %name).in_scope(|| {
                    debug!(%reason, "{}", self);
                });
            }
            Debug::InitialUpdate
            | Debug::UpdateInterval
            | Debug::TriggeredUpdate => {
                // Parent span(s): rip-instance
                debug!("{}", self);
            }
            Debug::PduRx(iface, source, pdu) => {
                // Parent span(s): rip-instance
                debug_span!("network").in_scope(|| {
                    debug_span!("input", interface = %iface.core.name, %source)
                        .in_scope(|| {
                            let data = serde_json::to_string(&pdu).unwrap();
                            debug!(%data, "{}", self);
                        });
                });
            }
            Debug::PduTx(iface, pdu) => {
                // Parent span(s): rip-instance
                debug_span!("network").in_scope(|| {
                    debug_span!("output", interface = %iface.core.name)
                        .in_scope(|| {
                            let data = serde_json::to_string(&pdu).unwrap();
                            debug!(%data, "{}", self);
                        });
                });
            }
            Debug::NbrCreate(addr) | Debug::NbrTimeout(addr) => {
                // Parent span(s): rip-instance
                debug!(address = %addr, "{}", self);
            }
            Debug::RouteCreate(prefix, source, metric)
            | Debug::RouteUpdate(prefix, source, metric) => {
                let source = if let Some(source) = source {
                    source.to_string()
                } else {
                    "connected".to_owned()
                };
                // Parent span(s): rip-instance
                debug!(%prefix, %source, metric = %metric.get(), "{}", self);
            }
            Debug::RouteTimeout(prefix)
            | Debug::RouteGcTimeout(prefix)
            | Debug::RouteInvalidate(prefix) => {
                // Parent span(s): rip-instance
                debug!(%prefix, "{}", self);
            }
        }
    }
}

impl<'a, V> std::fmt::Display for Debug<'a, V>
where
    V: Version,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Debug::InstanceCreate => {
                write!(f, "instance created")
            }
            Debug::InstanceDelete => {
                write!(f, "instance deleted")
            }
            Debug::InstanceStart => {
                write!(f, "starting instance")
            }
            Debug::InstanceStop(..) => {
                write!(f, "stopping instance")
            }
            Debug::InstanceStatusCheck(..) => {
                write!(f, "checking instance status")
            }
            Debug::InterfaceCreate(..) => {
                write!(f, "interface created")
            }
            Debug::InterfaceDelete(..) => {
                write!(f, "interface deleted")
            }
            Debug::InterfaceStart(..) => {
                write!(f, "starting interface")
            }
            Debug::InterfaceStop(..) => {
                write!(f, "stopping interface")
            }
            Debug::InitialUpdate => {
                write!(f, "initial update")
            }
            Debug::UpdateInterval => {
                write!(f, "update interval")
            }
            Debug::TriggeredUpdate => {
                write!(f, "triggered update")
            }
            Debug::PduRx(..) | Debug::PduTx(..) => {
                write!(f, "pdu")
            }
            Debug::NbrCreate(..) => {
                write!(f, "neighbor created")
            }
            Debug::NbrTimeout(..) => {
                write!(f, "neighbor timed out")
            }
            Debug::RouteCreate(..) => {
                write!(f, "route created")
            }
            Debug::RouteUpdate(..) => {
                write!(f, "route updated")
            }
            Debug::RouteTimeout(..) => {
                write!(f, "route timed out")
            }
            Debug::RouteGcTimeout(..) => {
                write!(f, "route deleted")
            }
            Debug::RouteInvalidate(..) => {
                write!(f, "route invalidated")
            }
        }
    }
}

// ===== impl InstanceInactiveReason =====

impl std::fmt::Display for InstanceInactiveReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstanceInactiveReason::AdminDown => {
                write!(f, "administrative status down")
            }
        }
    }
}

// ===== impl InterfaceInactiveReason =====

impl std::fmt::Display for InterfaceInactiveReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InterfaceInactiveReason::InstanceDown => {
                write!(f, "RIP instance down")
            }
            InterfaceInactiveReason::AdminDown => {
                write!(f, "administrative status down")
            }
            InterfaceInactiveReason::OperationalDown => {
                write!(f, "operational status down")
            }
            InterfaceInactiveReason::MissingIfindex => {
                write!(f, "missing ifindex")
            }
            InterfaceInactiveReason::MissingIpAddress => {
                write!(f, "missing IP address")
            }
        }
    }
}
