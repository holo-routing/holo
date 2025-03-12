//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

pub trait OptionExt<T> {
    /// Returns the `Option` value when not in testing mode, and `None` in
    /// testing mode.
    fn ignore_in_testing(self) -> Option<T>;

    /// Returns `None` in testing mode if the given condition is true.
    /// Otherwise, returns the original `Option` value.
    fn ignore_in_testing_if(self, condition: bool) -> Option<T>;

    /// Returns the `Option` value only in testing mode, and `None` when not in
    /// testing mode.
    fn only_in_testing(self) -> Option<T>;
}

impl<T> OptionExt<T> for Option<T> {
    fn ignore_in_testing(self) -> Option<T> {
        #[cfg(not(feature = "testing"))]
        {
            self
        }
        #[cfg(feature = "testing")]
        {
            None
        }
    }

    #[allow(unused_variables)]
    fn ignore_in_testing_if(self, condition: bool) -> Option<T> {
        #[cfg(not(feature = "testing"))]
        {
            self
        }
        #[cfg(feature = "testing")]
        {
            if condition { None } else { self }
        }
    }

    fn only_in_testing(self) -> Option<T> {
        #[cfg(feature = "testing")]
        {
            self
        }
        #[cfg(not(feature = "testing"))]
        {
            None
        }
    }
}
