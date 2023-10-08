//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

pub mod grpc;

use yang2::data::{DataFormat, DataTree};

use crate::error::Error;

type StdError = Box<dyn std::error::Error + Send + Sync + 'static>;

pub trait Client: Send + std::fmt::Debug {
    // Connect to the Holo daemon.
    fn connect(dest: &'static str) -> Result<Self, StdError>
    where
        Self: Sized;

    // Retrieve and load all supported YANG modules.
    fn load_modules(&mut self, yang_ctx: &mut yang2::context::Context);

    // Get the running configuration.
    fn get_running_config(&mut self) -> DataTree;

    // Validate the provided candidate configuration.
    fn validate_candidate(&mut self, candidate: &DataTree)
        -> Result<(), Error>;

    // Commit the provided candidate configuration.
    fn commit_candidate(
        &mut self,
        running: &DataTree,
        candidate: &DataTree,
        comment: Option<String>,
    ) -> Result<(), Error>;

    // Get state data.
    fn get_state(
        &mut self,
        xpath: Option<String>,
        format: DataFormat,
    ) -> Result<String, Error>;
}
