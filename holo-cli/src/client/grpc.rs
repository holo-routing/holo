//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_yang as yang;
use holo_yang::YANG_CTX;
use proto::northbound_client::NorthboundClient;
use yang2::data::{
    Data, DataDiffFlags, DataFormat, DataParserFlags, DataPrinterFlags,
    DataTree, DataValidationFlags,
};

use crate::client::Client;
use crate::error::Error;

pub mod proto {
    tonic::include_proto!("holo");
}

type StdError = Box<dyn std::error::Error + Send + Sync + 'static>;

// The order of the fields in this struct is important. They must be ordered
// such that when `Client` is dropped the client is dropped before the runtime.
// Not doing this will result in a deadlock when dropped. Rust drops struct
// fields in declaration order.
#[derive(Debug)]
pub struct GrpcClient {
    client: NorthboundClient<tonic::transport::Channel>,
    runtime: tokio::runtime::Runtime,
}

// ===== impl GrpcClient =====

impl GrpcClient {
    fn rpc_sync_capabilities(
        &mut self,
    ) -> Result<tonic::Response<proto::CapabilitiesResponse>, tonic::Status>
    {
        let request = tonic::Request::new(proto::CapabilitiesRequest {});
        self.runtime.block_on(self.client.capabilities(request))
    }

    fn rpc_sync_get(
        &mut self,
        request: proto::GetRequest,
    ) -> Result<tonic::Response<proto::GetResponse>, tonic::Status> {
        let request = tonic::Request::new(request);
        self.runtime.block_on(self.client.get(request))
    }

    fn rpc_sync_commit(
        &mut self,
        request: proto::CommitRequest,
    ) -> Result<tonic::Response<proto::CommitResponse>, tonic::Status> {
        let request = tonic::Request::new(request);
        self.runtime.block_on(self.client.commit(request))
    }

    fn rpc_sync_validate(
        &mut self,
        request: proto::ValidateRequest,
    ) -> Result<tonic::Response<proto::ValidateResponse>, tonic::Status> {
        let request = tonic::Request::new(request);
        self.runtime.block_on(self.client.validate(request))
    }
}

impl Client for GrpcClient {
    fn connect(dest: &'static str) -> Result<Self, StdError> {
        // Initialize tokio runtime.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to obtain a new runtime object");

        // Connect to holod.
        let client = runtime.block_on(NorthboundClient::connect(dest))?;

        Ok(GrpcClient { client, runtime })
    }

    fn load_modules(&mut self, yang_ctx: &mut yang2::context::Context) {
        // Retrieve the set of capabilities supported by the daemon.
        let capabilities = self
            .rpc_sync_capabilities()
            .expect("Failed to parse gRPC Capabilities() response");

        // Load YANG modules dynamically.
        for module in capabilities.into_inner().supported_modules {
            yang::load_module(yang_ctx, &module.name);
        }
    }

    fn get_running_config(&mut self) -> DataTree {
        let data_str = self
            .rpc_sync_get(proto::GetRequest {
                r#type: proto::get_request::DataType::Config as i32,
                encoding: proto::Encoding::Xml as i32,
                path: String::new(),
            })
            .expect("Failed to parse gRPC Get() response")
            .into_inner()
            .data
            .unwrap();

        let yang_ctx = YANG_CTX.get().unwrap();
        DataTree::parse_string(
            yang_ctx,
            &data_str.data,
            DataFormat::XML,
            DataParserFlags::empty(),
            DataValidationFlags::PRESENT | DataValidationFlags::NO_STATE,
        )
        .expect("Failed to parse data tree")
    }

    fn validate_candidate(
        &mut self,
        candidate: &DataTree,
    ) -> Result<(), Error> {
        let config = {
            let encoding = proto::Encoding::Xml as i32;
            let data = candidate
                .print_string(DataFormat::XML, DataPrinterFlags::WITH_SIBLINGS)
                .expect("Failed to encode data tree")
                .unwrap_or_default();

            Some(proto::DataTree { encoding, data })
        };

        self.rpc_sync_validate(proto::ValidateRequest { config })
            .map_err(Error::Backend)?;

        Ok(())
    }

    fn commit_candidate(
        &mut self,
        running: &DataTree,
        candidate: &DataTree,
        comment: Option<String>,
    ) -> Result<(), Error> {
        let operation = proto::commit_request::Operation::Change as i32;
        let config = {
            let encoding = proto::Encoding::Xml as i32;
            let diff = running
                .diff(candidate, DataDiffFlags::DEFAULTS)
                .expect("Failed to compare configurations");
            let data = diff
                .print_string(DataFormat::XML, DataPrinterFlags::WITH_SIBLINGS)
                .expect("Failed to encode data diff")
                .unwrap_or_default();

            Some(proto::DataTree { encoding, data })
        };

        self.rpc_sync_commit(proto::CommitRequest {
            operation,
            config,
            comment: comment.unwrap_or_default(),
            confirmed_timeout: 0,
        })
        .map_err(Error::Backend)?;

        Ok(())
    }

    fn get_state(
        &mut self,
        xpath: Option<String>,
        format: DataFormat,
    ) -> Result<String, Error> {
        let data_str = self
            .rpc_sync_get(proto::GetRequest {
                r#type: proto::get_request::DataType::State as i32,
                encoding: proto::Encoding::from(format) as i32,
                path: xpath.unwrap_or_default(),
            })
            .map_err(Error::Backend)?
            .into_inner()
            .data
            .unwrap();

        Ok(data_str.data)
    }
}

// ===== From/TryFrom conversion methods =====

impl From<DataFormat> for proto::Encoding {
    fn from(format: DataFormat) -> proto::Encoding {
        match format {
            DataFormat::JSON => proto::Encoding::Json,
            DataFormat::XML => proto::Encoding::Xml,
            DataFormat::LYB => proto::Encoding::Lyb,
        }
    }
}
