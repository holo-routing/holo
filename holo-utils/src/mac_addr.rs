//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::str::FromStr;

use serde::{Deserialize, Serialize};

// 48-bit MAC address (IEEE EUI-48 format).
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct MacAddr([u8; 6]);

// ===== impl MacAddr =====

impl MacAddr {
    pub const LENGTH: usize = 6;
    pub const BROADCAST: Self = Self([0xff; 6]);

    pub fn as_bytes(&self) -> [u8; 6] {
        self.0
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(bytes: [u8; 6]) -> Self {
        MacAddr(bytes)
    }
}

impl std::fmt::Display for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5],
        ))
    }
}

/// Error type for MAC address parsing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseMacAddrError;

impl std::fmt::Display for ParseMacAddrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid MAC address format")
    }
}

impl std::error::Error for ParseMacAddrError {}

impl FromStr for MacAddr {
    type Err = ParseMacAddrError;

    /// Parse a MAC address from a string.
    ///
    /// Accepts formats:
    /// - Colon-separated: "aa:bb:cc:dd:ee:ff"
    /// - Hyphen-separated: "aa-bb-cc-dd-ee-ff"
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = if s.contains(':') {
            s.split(':').collect()
        } else if s.contains('-') {
            s.split('-').collect()
        } else {
            return Err(ParseMacAddrError);
        };

        if parts.len() != 6 {
            return Err(ParseMacAddrError);
        }

        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            bytes[i] =
                u8::from_str_radix(part, 16).map_err(|_| ParseMacAddrError)?;
        }

        Ok(MacAddr(bytes))
    }
}
