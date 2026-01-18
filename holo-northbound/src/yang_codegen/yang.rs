//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::time::{Duration, Instant};

use base64::Engine;
use itertools::Itertools;

pub fn binary_to_yang(value: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(value)
}

pub fn hex_string_to_yang(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).join(":")
}

pub fn timer_secs16_to_yang(timer: Cow<'_, Duration>) -> String {
    let remaining = timer.as_secs();
    // Round up the remaining time to 1 in case it's less than one second.
    let remaining = if remaining == 0 { 1 } else { remaining };
    let remaining = u16::try_from(remaining).unwrap_or(u16::MAX);
    remaining.to_string()
}

pub fn timer_secs32_to_yang(timer: Cow<'_, Duration>) -> String {
    let remaining = timer.as_secs();
    // Round up the remaining time to 1 in case it's less than one second.
    let remaining = if remaining == 0 { 1 } else { remaining };
    let remaining = u32::try_from(remaining).unwrap_or(u32::MAX);
    remaining.to_string()
}

pub fn timer_millis_to_yang(timer: Cow<'_, Duration>) -> String {
    let remaining = timer.as_millis();
    // Round up the remaining time to 1 in case it's less than one millisecond.
    let remaining = if remaining == 0 { 1 } else { remaining };
    let remaining = u32::try_from(remaining).unwrap_or(u32::MAX);
    remaining.to_string()
}

pub fn timeticks_to_yang(timeticks: Cow<'_, Instant>) -> String {
    let uptime = Instant::now() - *timeticks;
    let uptime = u32::try_from(uptime.as_millis() / 10).unwrap_or(u32::MAX);
    uptime.to_string()
}

pub fn timeticks64_to_yang(timeticks: Cow<'_, Instant>) -> String {
    let uptime = Instant::now() - *timeticks;
    let uptime = u64::try_from(uptime.as_millis() / 10).unwrap_or(u64::MAX);
    uptime.to_string()
}

pub fn bandwidth_ieee_float32_to_yang(value: &f32) -> String {
    // Get the binary representation of the float value.
    let bits = value.to_bits();

    // Extract the sign bit, exponent, and fraction.
    let _sign = (bits >> 31) & 0x1;
    let exponent = ((bits >> 23) & 0xFF) as i32 - 127;
    let fraction = bits & 0x7FFFFF;

    // Normalize the fraction by adding the leading 1.
    let mut fraction_hex = format!("{fraction:x}");

    // Ensure 6 digits in hexadecimal.
    while fraction_hex.len() < 6 {
        fraction_hex = format!("0{fraction_hex}");
    }

    // Format the exponent as a signed decimal.
    let exponent_str = if exponent >= 0 {
        format!("p+{exponent}")
    } else {
        format!("p{exponent}")
    };

    // Build the final string.
    format!("0x1.{fraction_hex}{exponent_str}")
}

pub fn fletcher_checksum16_to_yang(cksum: u16) -> String {
    format!("{cksum:#06x}")
}
