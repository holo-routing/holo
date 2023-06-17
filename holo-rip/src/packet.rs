//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::sync::atomic::AtomicU32;
use std::sync::Arc;

use bytes::BytesMut;
use derive_new::new;
use holo_utils::crypto::CryptoAlgo;
use holo_utils::ip::{IpAddrKind, IpNetworkKind};
use num_derive::FromPrimitive;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::route::Metric;

#[derive(Clone, Copy, Debug, Eq, FromPrimitive, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum Command {
    Request = 1,
    Response = 2,
}

#[derive(Clone, Debug, new)]
#[derive(Deserialize, Serialize)]
pub struct AuthCtx {
    // Authentication key.
    pub key: String,
    // Authentication cryptographic algorithm.
    pub algo: CryptoAlgo,
    // Non-decreasing sequence number (only used for encoding packets).
    pub seqno: Arc<AtomicU32>,
}

// RIP version-specific code.
pub trait PduVersion<
    IpAddr: IpAddrKind,
    IpNetwork: IpNetworkKind<IpAddr>,
    DecodeError: DecodeErrorVersion,
> where
    Self: Send + std::fmt::Debug + Serialize + DeserializeOwned,
{
    type Rte: RteVersion<IpAddr, IpNetwork>;

    // Create new PDU.
    fn new(command: Command, rtes: Vec<Self::Rte>) -> Self;

    // Encode PDU into a bytes buffer.
    fn encode(&self, auth: Option<&AuthCtx>) -> BytesMut;

    // Decode PDU from a bytes buffer.
    fn decode(data: &[u8], auth: Option<&AuthCtx>)
        -> Result<Self, DecodeError>;

    // Return the PDU command.
    fn command(&self) -> Command;

    // Set the PDU command.
    fn set_command(&mut self, command: Command);

    // Return maximum number of RTEs that can fit in the specified MTU size.
    fn max_entries(mtu: u32, auth_algo: Option<CryptoAlgo>) -> usize;

    // Return a reference to the PDU's RTEs.
    fn rtes(&self) -> &Vec<Self::Rte>;

    // Return a mutable reference to the PDU's RTEs.
    fn rtes_mut(&mut self) -> &mut Vec<Self::Rte>;

    // Return list of invalid RTEs.
    fn rte_errors(&mut self) -> Vec<DecodeError>;

    // Return the PDU authentication sequence number.
    fn auth_seqno(&self) -> Option<u32>;

    // Create a request to send the entire routing table.
    fn new_dump_request() -> Self;

    // Return whether the PDU is a request to send the entire routing table.
    fn is_dump_request(&self) -> bool;
}

// RIP version-specific code.
pub trait RteVersion<IpAddr: IpAddrKind, IpNetwork: IpNetworkKind<IpAddr>> {
    type Route: RteRouteVersion<IpAddr, IpNetwork>;

    // Create new route RTE.
    fn new_route(
        prefix: IpNetwork,
        nexthop: Option<IpAddr>,
        metric: Metric,
        tag: u16,
    ) -> Self;

    // Return a reference to the inner route RTE.
    fn as_route(&self) -> Option<&Self::Route>;

    // Return a mutable reference to the inner route RTE.
    fn as_route_mut(&mut self) -> Option<&mut Self::Route>;

    // Return a reference to the inner nexthop RTE.
    fn as_nexthop(&self) -> Option<Option<&IpAddr>>;
}

// RIP version-specific code.
pub trait RteRouteVersion<IpAddr: IpAddrKind, IpNetwork: IpNetworkKind<IpAddr>>
{
    // Return route's prefix.
    fn prefix(&self) -> &IpNetwork;

    // Return route's nexthop.
    fn nexthop(&self) -> Option<&IpAddr>;

    // Return route's metric.
    fn metric(&self) -> Metric;

    // Set route's metric.
    fn set_metric(&mut self, metric: Metric);

    // Return route's tag.
    fn tag(&self) -> u16;
}

// RIP version-specific code.
pub trait DecodeErrorVersion:
    std::error::Error + Send + Serialize + DeserializeOwned
{
}
