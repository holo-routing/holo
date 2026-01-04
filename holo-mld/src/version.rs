use holo_utils::protocol::Protocol;

use crate::northbound::NorthboundVersion;

pub trait Version
where
    Self: 'static
        + Send
        + Sync
        + Clone
        + Default
        + Eq
        + PartialEq
        + std::fmt::Debug
        + NorthboundVersion<Self>,
{
    const PROTOCOL: Protocol;
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct Mldv1();

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct Mldv2();

impl Version for Mldv1 {
    const PROTOCOL: Protocol = Protocol::MLDV1;
}

impl Version for Mldv2 {
    const PROTOCOL: Protocol = Protocol::MLDV2;
}
