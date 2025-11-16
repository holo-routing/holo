//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

pub mod auth;
pub mod consts;
pub mod error;
pub mod pdu;
pub mod subtlvs;
pub mod tlv;

use bytes::{Buf, BufMut, Bytes, BytesMut, TryGetError};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

// Represent an IS-IS level, or a combination of both of them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum LevelType {
    L1,
    L2,
    All,
}

// An iterator over the IS-IS levels defined by a `LevelType`.
pub struct LevelTypeIterator {
    level_type: LevelType,
    idx: usize,
}

// Represents a single IS-IS level.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum LevelNumber {
    L1 = 1,
    L2 = 2,
}

// Container for storing separate values for level 1 and level 2.
#[derive(Clone, Debug, Default)]
pub struct Levels<T> {
    pub l1: T,
    pub l2: T,
}

// Represents an IS-IS Area Address.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct AreaAddr(SmallVec<[u8; 13]>);

// Represents an IS-IS System ID.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct SystemId([u8; 6]);

// Represents an IS-IS LAN ID.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct LanId {
    pub system_id: SystemId,
    pub pseudonode: u8,
}

// Represents an IS-IS LSP ID.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct LspId {
    pub system_id: SystemId,
    pub pseudonode: u8,
    pub fragment: u8,
}

// ===== impl LevelType =====

impl LevelType {
    pub(crate) fn intersects(&self, level: impl Into<LevelType>) -> bool {
        let level = level.into();
        match self {
            LevelType::L1 => matches!(level, LevelType::L1 | LevelType::All),
            LevelType::L2 => matches!(level, LevelType::L2 | LevelType::All),
            LevelType::All => true,
        }
    }

    pub(crate) fn intersection(
        &self,
        level: impl Into<LevelType>,
    ) -> Option<LevelType> {
        let level = level.into();
        match (self, level) {
            (LevelType::L1, LevelType::L1) => Some(LevelType::L1),
            (LevelType::L2, LevelType::L2) => Some(LevelType::L2),
            (LevelType::All, _) => Some(level),
            (_, LevelType::All) => Some(*self),
            _ => None,
        }
    }

    pub(crate) fn union(&self, level: impl Into<LevelType>) -> LevelType {
        let level = level.into();
        match (self, level) {
            (LevelType::L1, LevelType::L1) => LevelType::L1,
            (LevelType::L2, LevelType::L2) => LevelType::L2,
            (LevelType::L1, LevelType::L2) | (LevelType::L2, LevelType::L1) => {
                LevelType::All
            }
            (LevelType::All, _) | (_, LevelType::All) => LevelType::All,
        }
    }
}

impl From<LevelNumber> for LevelType {
    fn from(level: LevelNumber) -> LevelType {
        match level {
            LevelNumber::L1 => LevelType::L1,
            LevelNumber::L2 => LevelType::L2,
        }
    }
}

impl From<&LevelNumber> for LevelType {
    fn from(level: &LevelNumber) -> LevelType {
        match level {
            LevelNumber::L1 => LevelType::L1,
            LevelNumber::L2 => LevelType::L2,
        }
    }
}

impl IntoIterator for LevelType {
    type Item = LevelNumber;
    type IntoIter = LevelTypeIterator;

    fn into_iter(self) -> Self::IntoIter {
        LevelTypeIterator::new(self)
    }
}

// ===== impl LevelTypeIterator =====

impl LevelTypeIterator {
    const LEVELS: [LevelNumber; 2] = [LevelNumber::L1, LevelNumber::L2];

    fn new(level_type: LevelType) -> Self {
        Self { level_type, idx: 0 }
    }
}

impl Iterator for LevelTypeIterator {
    type Item = LevelNumber;

    fn next(&mut self) -> Option<Self::Item> {
        while self.idx < Self::LEVELS.len() {
            let level = Self::LEVELS[self.idx];
            self.idx += 1;

            if self.level_type.intersects(level) {
                return Some(level);
            }
        }
        None
    }
}

// ===== impl LevelNumber =====

impl std::fmt::Display for LevelNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", *self as u8)
    }
}

impl From<LevelType> for LevelNumber {
    fn from(level_type: LevelType) -> LevelNumber {
        match level_type {
            LevelType::L1 => LevelNumber::L1,
            LevelType::L2 => LevelNumber::L2,
            LevelType::All => unreachable!(),
        }
    }
}

impl From<&LevelType> for LevelNumber {
    fn from(level_type: &LevelType) -> LevelNumber {
        match level_type {
            LevelType::L1 => LevelNumber::L1,
            LevelType::L2 => LevelNumber::L2,
            LevelType::All => unreachable!(),
        }
    }
}

// ===== impl Levels =====

impl<T> Levels<T> {
    pub(crate) fn get(&self, level: impl Into<LevelNumber>) -> &T {
        let level = level.into();
        match level {
            LevelNumber::L1 => &self.l1,
            LevelNumber::L2 => &self.l2,
        }
    }

    pub(crate) fn get_mut(&mut self, level: impl Into<LevelNumber>) -> &mut T {
        let level = level.into();
        match level {
            LevelNumber::L1 => &mut self.l1,
            LevelNumber::L2 => &mut self.l2,
        }
    }
}

// ===== impl AreaAddr =====

impl AreaAddr {
    pub const MAX_LEN: u8 = 13;

    pub(crate) fn new(bytes: SmallVec<[u8; 13]>) -> Self {
        AreaAddr(bytes)
    }
}

impl AsRef<[u8]> for AreaAddr {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8]> for AreaAddr {
    fn from(bytes: &[u8]) -> AreaAddr {
        AreaAddr(SmallVec::from_slice(bytes))
    }
}

// ===== impl SystemId =====

impl SystemId {
    pub(crate) fn decode(buf: &mut Bytes) -> Result<Self, TryGetError> {
        let mut system_id = [0; 6];
        buf.try_copy_to_slice(&mut system_id)?;
        Ok(SystemId(system_id))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        buf.put_slice(&self.0);
    }
}

impl AsRef<[u8]> for SystemId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; 6]> for SystemId {
    fn as_ref(&self) -> &[u8; 6] {
        &self.0
    }
}

impl From<[u8; 6]> for SystemId {
    fn from(bytes: [u8; 6]) -> SystemId {
        SystemId(bytes)
    }
}

// ===== impl LanId =====

impl LanId {
    pub(crate) fn decode(buf: &mut Bytes) -> Result<Self, TryGetError> {
        let mut bytes = [0; 7];
        buf.try_copy_to_slice(&mut bytes)?;
        Ok(Self::from(bytes))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        self.system_id.encode(buf);
        buf.put_u8(self.pseudonode);
    }

    pub(crate) const fn is_pseudonode(&self) -> bool {
        self.pseudonode != 0
    }
}

impl From<[u8; 7]> for LanId {
    fn from(bytes: [u8; 7]) -> LanId {
        LanId {
            system_id: SystemId::from([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
            ]),
            pseudonode: bytes[6],
        }
    }
}

impl From<(SystemId, u8)> for LanId {
    fn from(components: (SystemId, u8)) -> LanId {
        LanId {
            system_id: components.0,
            pseudonode: components.1,
        }
    }
}

// ===== impl LspId =====

impl LspId {
    pub(crate) fn decode(buf: &mut Bytes) -> Result<Self, TryGetError> {
        let mut bytes = [0; 8];
        buf.try_copy_to_slice(&mut bytes)?;
        Ok(Self::from(bytes))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        self.system_id.encode(buf);
        buf.put_u8(self.pseudonode);
        buf.put_u8(self.fragment);
    }

    pub(crate) const fn is_pseudonode(&self) -> bool {
        self.pseudonode != 0
    }
}

impl From<[u8; 8]> for LspId {
    fn from(bytes: [u8; 8]) -> LspId {
        LspId {
            system_id: SystemId::from([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
            ]),
            pseudonode: bytes[6],
            fragment: bytes[7],
        }
    }
}

impl From<(SystemId, u8, u8)> for LspId {
    fn from(components: (SystemId, u8, u8)) -> LspId {
        LspId {
            system_id: components.0,
            pseudonode: components.1,
            fragment: components.2,
        }
    }
}

impl From<(LanId, u8)> for LspId {
    fn from(components: (LanId, u8)) -> LspId {
        LspId {
            system_id: components.0.system_id,
            pseudonode: components.0.pseudonode,
            fragment: components.1,
        }
    }
}
