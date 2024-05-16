//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

/// Defines a conversion from one type to another, where the result is capped
/// at the maximum bound of the target type if the input value exceeds this
/// bound.
pub trait SaturatingFrom<T>: Sized {
    /// Converts a value of type `T` to the implementing type with saturation.
    fn saturating_from(value: T) -> Self;
}

/// Defines a conversion into another type using the `SaturatingFrom` trait.
pub trait SaturatingInto<T>: Sized {
    /// Converts the implementing type into a value of type `T` with saturation.
    fn saturating_into(self) -> T;
}

// ===== impl SaturatingFrom =====

impl SaturatingFrom<u64> for u16 {
    fn saturating_from(value: u64) -> Self {
        u16::try_from(value).unwrap_or(u16::MAX)
    }
}

impl SaturatingFrom<u64> for u32 {
    fn saturating_from(value: u64) -> Self {
        u32::try_from(value).unwrap_or(u32::MAX)
    }
}

impl SaturatingFrom<usize> for u16 {
    fn saturating_from(value: usize) -> Self {
        u16::try_from(value).unwrap_or(u16::MAX)
    }
}

impl SaturatingFrom<usize> for u32 {
    fn saturating_from(value: usize) -> Self {
        u32::try_from(value).unwrap_or(u32::MAX)
    }
}

// ===== impl SaturatingInto =====

impl<T, U> SaturatingInto<U> for T
where
    U: SaturatingFrom<T>,
{
    fn saturating_into(self) -> U {
        U::saturating_from(self)
    }
}
