//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::{Duration, Instant};

use base64::Engine;

use crate::{ToYang, TryFromYang};

/// `timer-value-seconds16`: Duration in seconds, capped at u16::MAX.
#[derive(Clone, Copy, Debug)]
pub struct TimerValueSecs16(pub Duration);

/// `timer-value-seconds32`: Duration in seconds, capped at u32::MAX.
#[derive(Clone, Copy, Debug)]
pub struct TimerValueSecs32(pub Duration);

/// `timer-value-milliseconds`: Duration in milliseconds, capped at u32::MAX.
#[derive(Clone, Copy, Debug)]
pub struct TimerValueMillis(pub Duration);

/// `timeticks`: elapsed time in 10ms units, u32 range.
#[derive(Clone, Copy, Debug)]
pub struct Timeticks(pub Instant);

/// `timeticks64`: elapsed time in 10ms units, u64 range.
#[derive(Clone, Copy, Debug)]
pub struct Timeticks64(pub Instant);

/// `binary`: byte sequence with base64 encoding.
#[derive(Clone, Debug)]
pub struct Base64String(pub Vec<u8>);

/// Borrowed variant of [`Base64String`].
#[derive(Clone, Copy, Debug)]
pub struct Base64Str<'a>(pub &'a [u8]);

/// `hex-string`: byte sequence with colon-separated hex encoding.
#[derive(Clone, Debug)]
pub struct HexString(pub Vec<u8>);

/// Borrowed variant of [`HexString`].
#[derive(Clone, Copy, Debug)]
pub struct HexStr<'a>(pub &'a [u8]);

// ===== impl {integer, bool} =====

macro_rules! impl_yang_numeric {
    ($($t:ty),*) => {$(
        impl ToYang for $t {
            fn to_yang(&self) -> Cow<'static, str> {
                Cow::Owned(self.to_string())
            }
        }
        impl TryFromYang for $t {
            fn try_from_yang(value: &str) -> Option<Self> {
                value.parse().ok()
            }
        }
    )*};
}

impl_yang_numeric!(u8, u16, u32, u64, i8, i16, i32, i64, bool);

// ===== impl f32 =====

impl ToYang for f32 {
    fn to_yang(&self) -> Cow<'static, str> {
        let bits = self.to_bits();
        let exponent = ((bits >> 23) & 0xFF) as i32 - 127;
        let fraction = bits & 0x7FFFFF;
        let fraction_hex = format!("{fraction:06x}");
        let exponent_str = if exponent >= 0 {
            format!("p+{exponent}")
        } else {
            format!("p{exponent}")
        };
        Cow::Owned(format!("0x1.{fraction_hex}{exponent_str}"))
    }
}

// ===== impl IpAddr =====

impl ToYang for IpAddr {
    fn to_yang(&self) -> Cow<'static, str> {
        Cow::Owned(self.to_string())
    }
}

impl TryFromYang for IpAddr {
    fn try_from_yang(value: &str) -> Option<Self> {
        IpAddr::from_str(value).ok()
    }
}

// ===== impl Ipv4Addr =====

impl ToYang for Ipv4Addr {
    fn to_yang(&self) -> Cow<'static, str> {
        Cow::Owned(self.to_string())
    }
}

impl TryFromYang for Ipv4Addr {
    fn try_from_yang(value: &str) -> Option<Self> {
        Ipv4Addr::from_str(value).ok()
    }
}

// ===== impl Ipv6Addr =====

impl ToYang for Ipv6Addr {
    fn to_yang(&self) -> Cow<'static, str> {
        Cow::Owned(self.to_string())
    }
}

impl TryFromYang for Ipv6Addr {
    fn try_from_yang(value: &str) -> Option<Self> {
        Ipv6Addr::from_str(value).ok()
    }
}

// ===== impl ipnetwork::IpNetwork =====

impl ToYang for ipnetwork::IpNetwork {
    fn to_yang(&self) -> Cow<'static, str> {
        Cow::Owned(self.to_string())
    }
}

impl TryFromYang for ipnetwork::IpNetwork {
    fn try_from_yang(value: &str) -> Option<Self> {
        ipnetwork::IpNetwork::from_str(value).ok()
    }
}

// ===== impl ipnetwork::Ipv4Network =====

impl ToYang for ipnetwork::Ipv4Network {
    fn to_yang(&self) -> Cow<'static, str> {
        Cow::Owned(self.to_string())
    }
}

impl TryFromYang for ipnetwork::Ipv4Network {
    fn try_from_yang(value: &str) -> Option<Self> {
        ipnetwork::Ipv4Network::from_str(value).ok()
    }
}

// ===== impl ipnetwork::Ipv6Network =====

impl ToYang for ipnetwork::Ipv6Network {
    fn to_yang(&self) -> Cow<'static, str> {
        Cow::Owned(self.to_string())
    }
}

impl TryFromYang for ipnetwork::Ipv6Network {
    fn try_from_yang(value: &str) -> Option<Self> {
        ipnetwork::Ipv6Network::from_str(value).ok()
    }
}

// ===== impl chrono::DateTime =====

impl ToYang for chrono::DateTime<chrono::Utc> {
    fn to_yang(&self) -> Cow<'static, str> {
        Cow::Owned(self.to_rfc3339())
    }
}

impl TryFromYang for chrono::DateTime<chrono::Utc> {
    fn try_from_yang(value: &str) -> Option<Self> {
        chrono::DateTime::parse_from_rfc3339(value)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc))
    }
}

// ===== impl TimerValueSecs16 =====

impl ToYang for TimerValueSecs16 {
    fn to_yang(&self) -> Cow<'static, str> {
        let remaining = self.0.as_secs();
        // Round up to 1 if less than one second.
        let remaining = if remaining == 0 { 1 } else { remaining };
        let remaining = u16::try_from(remaining).unwrap_or(u16::MAX);
        Cow::Owned(remaining.to_string())
    }
}

// ===== impl TimerValueSecs32 =====

impl ToYang for TimerValueSecs32 {
    fn to_yang(&self) -> Cow<'static, str> {
        let remaining = self.0.as_secs();
        // Round up to 1 if less than one second.
        let remaining = if remaining == 0 { 1 } else { remaining };
        let remaining = u32::try_from(remaining).unwrap_or(u32::MAX);
        Cow::Owned(remaining.to_string())
    }
}

// ===== impl TimerValueMillis =====

impl ToYang for TimerValueMillis {
    fn to_yang(&self) -> Cow<'static, str> {
        let remaining = self.0.as_millis();
        // Round up to 1 if less than one millisecond.
        let remaining = if remaining == 0 { 1 } else { remaining };
        let remaining = u32::try_from(remaining).unwrap_or(u32::MAX);
        Cow::Owned(remaining.to_string())
    }
}

// ===== impl Timeticks =====

impl ToYang for Timeticks {
    fn to_yang(&self) -> Cow<'static, str> {
        let uptime = Instant::now() - self.0;
        let uptime = u32::try_from(uptime.as_millis() / 10).unwrap_or(u32::MAX);
        Cow::Owned(uptime.to_string())
    }
}

// ===== impl Timeticks64 =====

impl ToYang for Timeticks64 {
    fn to_yang(&self) -> Cow<'static, str> {
        let uptime = Instant::now() - self.0;
        let uptime = u64::try_from(uptime.as_millis() / 10).unwrap_or(u64::MAX);
        Cow::Owned(uptime.to_string())
    }
}

// ===== impl Base64String =====

impl ToYang for Base64String {
    fn to_yang(&self) -> Cow<'static, str> {
        Base64Str(self.0.as_ref()).to_yang()
    }
}

impl TryFromYang for Base64String {
    fn try_from_yang(value: &str) -> Option<Self> {
        base64::engine::general_purpose::STANDARD
            .decode(value)
            .ok()
            .map(Base64String)
    }
}

// ===== impl Base64Str =====

impl ToYang for Base64Str<'_> {
    fn to_yang(&self) -> Cow<'static, str> {
        Cow::Owned(base64::engine::general_purpose::STANDARD.encode(self.0))
    }
}

// ===== impl HexString =====

impl ToYang for HexString {
    fn to_yang(&self) -> Cow<'static, str> {
        HexStr(self.0.as_ref()).to_yang()
    }
}

// ===== impl HexStr =====

impl ToYang for HexStr<'_> {
    fn to_yang(&self) -> Cow<'static, str> {
        Cow::Owned(
            self.0
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(":"),
        )
    }
}
