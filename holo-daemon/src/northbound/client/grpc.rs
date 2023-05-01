//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::convert::TryFrom;
use std::pin::Pin;
use std::time::SystemTime;

use futures::Stream;
use holo_utils::Sender;
use holo_yang::YANG_CTX;
use tokio::sync::oneshot;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tracing::{debug, debug_span, trace};
use yang2::data::{
    Data, DataFormat, DataOperation, DataParserFlags, DataPrinterFlags,
    DataTree, DataValidationFlags,
};

use crate::northbound::client::api;
use crate::{config, northbound};

mod proto {
    #![allow(clippy::all)]
    tonic::include_proto!("holo");
    pub use northbound_server::{Northbound, NorthboundServer};
}

struct NorthboundService {
    request_tx: Sender<api::client::Request>,
}

// ===== impl proto::Northbound =====

#[tonic::async_trait]
impl proto::Northbound for NorthboundService {
    async fn capabilities(
        &self,
        grpc_request: Request<proto::CapabilitiesRequest>,
    ) -> Result<Response<proto::CapabilitiesResponse>, Status> {
        let yang_ctx = YANG_CTX.get().unwrap();
        let grpc_request = grpc_request.into_inner();
        debug_span!("northbound").in_scope(|| {
            debug_span!("client", name = "grpc").in_scope(|| {
                debug!("received Capabilities() request");
                trace!("{:?}", grpc_request);
            });
        });

        // Fill-in version.
        let version = env!("CARGO_PKG_VERSION").to_string();

        // Fill-in supported YANG modules.
        let supported_modules = yang_ctx
            .modules(true)
            .filter(|module| module.is_implemented())
            .map(|module| proto::ModuleData {
                name: module.name().to_owned(),
                organization: module
                    .organization()
                    .unwrap_or_default()
                    .to_owned(),
                revision: module.revision().unwrap_or_default().to_owned(),
            })
            .collect();

        // Fill-in supported data encodings.
        let supported_encodings =
            vec![proto::Encoding::Json as i32, proto::Encoding::Xml as i32];

        let reply = proto::CapabilitiesResponse {
            version,
            supported_modules,
            supported_encodings,
        };

        Ok(Response::new(reply))
    }

    async fn get(
        &self,
        grpc_request: Request<proto::GetRequest>,
    ) -> Result<Response<proto::GetResponse>, Status> {
        let grpc_request = grpc_request.into_inner();
        debug_span!("northbound").in_scope(|| {
            debug_span!("client", name = "grpc").in_scope(|| {
                debug!("received Get() request");
                trace!("{:?}", grpc_request);
            });
        });

        // Create oneshot channel to receive response back from the northbound.
        let (responder_tx, responder_rx) = oneshot::channel();

        // Convert and relay gRPC request to the northbound.
        let data_type = api::DataType::try_from(grpc_request.r#type)?;
        let encoding = proto::Encoding::from_i32(grpc_request.encoding)
            .ok_or_else(|| Status::invalid_argument("Invalid data encoding"))?;
        let path = (!grpc_request.path.is_empty()).then_some(grpc_request.path);
        let nb_request = api::client::Request::Get(api::client::GetRequest {
            data_type,
            path,
            responder: responder_tx,
        });
        self.request_tx.send(nb_request).await.unwrap();

        // Receive response from the northbound.
        let nb_response = responder_rx.await.unwrap()?;

        // Convert and relay northbound response to the gRPC client.
        let data = nb_response
            .dtree
            .print_string(
                DataFormat::from(encoding),
                DataPrinterFlags::WITH_SIBLINGS,
            )
            .map_err(|error| Status::internal(error.to_string()))?
            .unwrap_or_default();
        let grpc_response = proto::GetResponse {
            timestamp: get_timestamp(),
            data: Some(proto::DataTree {
                encoding: encoding as i32,
                data,
            }),
        };
        Ok(Response::new(grpc_response))
    }

    async fn commit(
        &self,
        grpc_request: Request<proto::CommitRequest>,
    ) -> Result<Response<proto::CommitResponse>, Status> {
        let yang_ctx = YANG_CTX.get().unwrap();
        let grpc_request = grpc_request.into_inner();
        debug_span!("northbound").in_scope(|| {
            debug_span!("client", name = "grpc").in_scope(|| {
                debug!("received Commit() request");
                trace!("{:?}", grpc_request);
            });
        });

        // Create oneshot channel to receive response back from the northbound.
        let (responder_tx, responder_rx) = oneshot::channel();

        // Convert and relay gRPC request to the northbound.
        let config_tree = grpc_request.config.ok_or_else(|| {
            Status::invalid_argument("Missing 'config' field")
        })?;
        let encoding = proto::Encoding::from_i32(config_tree.encoding)
            .ok_or_else(|| Status::invalid_argument("Invalid data encoding"))?;
        let operation = api::CommitOperation::try_from(grpc_request.operation)?;
        let config = DataTree::parse_string(
            yang_ctx,
            &config_tree.data,
            DataFormat::from(encoding),
            DataParserFlags::empty(),
            DataValidationFlags::NO_STATE,
        )
        .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let nb_request =
            api::client::Request::Commit(api::client::CommitRequest {
                operation,
                config,
                confirmed_timeout: grpc_request.confirmed_timeout,
                responder: responder_tx,
            });
        self.request_tx.send(nb_request).await.unwrap();

        // Receive response from the northbound.
        let nb_response = responder_rx.await.unwrap()?;

        // Prepare and send response to the gRPC client.
        let grpc_response = proto::CommitResponse {
            transaction_id: nb_response.transaction_id,
        };
        Ok(Response::new(grpc_response))
    }

    async fn execute(
        &self,
        grpc_request: Request<proto::ExecuteRequest>,
    ) -> Result<Response<proto::ExecuteResponse>, Status> {
        let yang_ctx = YANG_CTX.get().unwrap();
        let grpc_request = grpc_request.into_inner();
        debug_span!("northbound").in_scope(|| {
            debug_span!("client", name = "grpc").in_scope(|| {
                debug!("received Execute() request");
                trace!("{:?}", grpc_request);
            });
        });

        // Create oneshot channel to receive response back from the northbound.
        let (responder_tx, responder_rx) = oneshot::channel();

        // Convert and relay gRPC request to the northbound.
        let data = grpc_request
            .data
            .ok_or_else(|| Status::invalid_argument("Missing 'data' field"))?;
        let encoding = proto::Encoding::from_i32(data.encoding)
            .ok_or_else(|| Status::invalid_argument("Invalid data encoding"))?;
        let data = DataTree::parse_op_string(
            yang_ctx,
            &data.data,
            DataFormat::from(encoding),
            DataOperation::RpcYang,
        )
        .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let nb_request =
            api::client::Request::Execute(api::client::ExecuteRequest {
                data,
                responder: responder_tx,
            });
        self.request_tx.send(nb_request).await.unwrap();

        // Receive response from the northbound.
        let nb_response = responder_rx.await.unwrap()?;

        // Convert and relay northbound response to the gRPC client.
        let data = nb_response
            .data
            .print_string(
                DataFormat::from(encoding),
                DataPrinterFlags::WITH_SIBLINGS,
            )
            .map_err(|error| Status::internal(error.to_string()))?
            .unwrap_or_default();
        let grpc_response = proto::ExecuteResponse {
            data: Some(proto::DataTree {
                encoding: encoding as i32,
                data,
            }),
        };
        Ok(Response::new(grpc_response))
    }

    type ListTransactionsStream = Pin<
        Box<
            dyn Stream<Item = Result<proto::ListTransactionsResponse, Status>>
                + Send,
        >,
    >;

    async fn list_transactions(
        &self,
        grpc_request: Request<proto::ListTransactionsRequest>,
    ) -> Result<Response<Self::ListTransactionsStream>, Status> {
        let grpc_request = grpc_request.into_inner();
        debug_span!("northbound").in_scope(|| {
            debug_span!("client", name = "grpc").in_scope(|| {
                debug!("received GetTransaction() request");
                trace!("{:?}", grpc_request);
            });
        });

        // Create oneshot channel to receive response back from the northbound.
        let (responder_tx, responder_rx) = oneshot::channel();

        // Convert and relay gRPC request to the northbound.
        let nb_request = api::client::Request::ListTransactions(
            api::client::ListTransactionsRequest {
                responder: responder_tx,
            },
        );
        self.request_tx.send(nb_request).await.unwrap();

        // Receive response from the northbound.
        let nb_response = responder_rx.await.unwrap()?;

        // Convert and relay northbound response to the gRPC client.
        let transactions =
            nb_response.transactions.into_iter().map(|transaction| {
                Ok(proto::ListTransactionsResponse {
                    id: transaction.id,
                    date: transaction.date.to_string(),
                })
            });

        Ok(Response::new(Box::pin(futures::stream::iter(transactions))))
    }

    async fn get_transaction(
        &self,
        grpc_request: Request<proto::GetTransactionRequest>,
    ) -> Result<Response<proto::GetTransactionResponse>, Status> {
        let grpc_request = grpc_request.into_inner();
        debug_span!("northbound").in_scope(|| {
            debug_span!("client", name = "grpc").in_scope(|| {
                debug!("received Execute() request");
                trace!("{:?}", grpc_request);
            });
        });

        // Create oneshot channel to receive response back from the northbound.
        let (responder_tx, responder_rx) = oneshot::channel();

        // Convert and relay gRPC request to the northbound.
        let nb_request = api::client::Request::GetTransaction(
            api::client::GetTransactionRequest {
                transaction_id: grpc_request.transaction_id,
                responder: responder_tx,
            },
        );
        self.request_tx.send(nb_request).await.unwrap();

        // Receive response from the northbound.
        let nb_response = responder_rx.await.unwrap()?;

        // Convert and relay northbound response to the gRPC client.
        let encoding = proto::Encoding::from_i32(grpc_request.encoding)
            .ok_or_else(|| Status::invalid_argument("Invalid data encoding"))?;
        let config = nb_response
            .dtree
            .print_string(
                DataFormat::from(encoding),
                DataPrinterFlags::WITH_SIBLINGS,
            )
            .map_err(|error| Status::internal(error.to_string()))?
            .unwrap_or_default();
        let grpc_response = proto::GetTransactionResponse {
            config: Some(proto::DataTree {
                encoding: encoding as i32,
                data: config,
            }),
        };
        Ok(Response::new(grpc_response))
    }
}

// ===== impl Status =====

impl From<northbound::Error> for Status {
    fn from(error: northbound::Error) -> Status {
        match error {
            northbound::Error::YangInvalidPath(..)
            | northbound::Error::YangInvalidData(..) => {
                Status::invalid_argument(error.to_string())
            }
            northbound::Error::YangInternal(..) => {
                Status::internal(error.to_string())
            }
            northbound::Error::TransactionValidation(..) => {
                Status::invalid_argument(error.to_string())
            }
            northbound::Error::TransactionPreparation(..) => {
                Status::resource_exhausted(error.to_string())
            }
            northbound::Error::RollbackLogUnavailable => {
                Status::internal(error.to_string())
            }
            northbound::Error::TransactionIdNotFound(..) => {
                Status::invalid_argument(error.to_string())
            }
        }
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

impl From<proto::Encoding> for DataFormat {
    fn from(encoding: proto::Encoding) -> DataFormat {
        match encoding {
            proto::Encoding::Json => DataFormat::JSON,
            proto::Encoding::Xml => DataFormat::XML,
            proto::Encoding::Lyb => DataFormat::LYB,
        }
    }
}

impl TryFrom<i32> for api::DataType {
    type Error = Status;

    fn try_from(data_type: i32) -> Result<Self, Self::Error> {
        match proto::get_request::DataType::from_i32(data_type) {
            Some(proto::get_request::DataType::All) => Ok(api::DataType::All),
            Some(proto::get_request::DataType::Config) => {
                Ok(api::DataType::Configuration)
            }
            Some(proto::get_request::DataType::State) => {
                Ok(api::DataType::State)
            }
            None => Err(Status::invalid_argument("Invalid data type")),
        }
    }
}

impl TryFrom<i32> for api::CommitOperation {
    type Error = Status;

    fn try_from(data_type: i32) -> Result<Self, Self::Error> {
        match proto::commit_request::Operation::from_i32(data_type) {
            Some(proto::commit_request::Operation::Merge) => {
                Ok(api::CommitOperation::Merge)
            }
            Some(proto::commit_request::Operation::Replace) => {
                Ok(api::CommitOperation::Replace)
            }
            Some(proto::commit_request::Operation::Change) => {
                Ok(api::CommitOperation::Change)
            }
            None => Err(Status::invalid_argument("Invalid commit operation")),
        }
    }
}

// ===== global functions =====

fn get_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("System time before UNIX EPOCH!")
        .as_secs() as i64
}

pub(crate) fn start(
    config: &config::Grpc,
    request_tx: Sender<api::client::Request>,
) {
    let address = config
        .address
        .parse()
        .expect("Failed to parse gRPC server address");

    tokio::spawn(async move {
        let service = NorthboundService { request_tx };
        Server::builder()
            .add_service(proto::NorthboundServer::new(service))
            .serve(address)
            .await
            .expect("Failed to start gRPC service");
    });
}
