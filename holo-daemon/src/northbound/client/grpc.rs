//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::pin::Pin;
use std::time::SystemTime;

use futures::Stream;
use holo_utils::Sender;
use holo_yang::YANG_CTX;
use tokio::sync::oneshot;
use tonic::transport::{Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
use tracing::{debug, debug_span, error, trace};
use yang3::data::{
    Data, DataDiff, DataFormat, DataOperation, DataParserFlags,
    DataPrinterFlags, DataTree, DataValidationFlags,
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
        let encoding = proto::Encoding::try_from(grpc_request.encoding)
            .map_err(|_| Status::invalid_argument("Invalid data encoding"))?;
        let with_defaults = grpc_request.with_defaults;
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
        let mut printer_flags = DataPrinterFlags::WITH_SIBLINGS;
        if with_defaults {
            printer_flags.insert(DataPrinterFlags::WD_ALL);
        }
        let data = nb_response
            .dtree
            .print_string(DataFormat::from(encoding), printer_flags)
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

    async fn validate(
        &self,
        grpc_request: Request<proto::ValidateRequest>,
    ) -> Result<Response<proto::ValidateResponse>, Status> {
        let yang_ctx = YANG_CTX.get().unwrap();
        let grpc_request = grpc_request.into_inner();
        debug_span!("northbound").in_scope(|| {
            debug_span!("client", name = "grpc").in_scope(|| {
                debug!("received Validate() request");
                trace!("{:?}", grpc_request);
            });
        });

        // Create oneshot channel to receive response back from the northbound.
        let (responder_tx, responder_rx) = oneshot::channel();

        // Convert and relay gRPC request to the northbound.
        let config_tree = grpc_request.config.ok_or_else(|| {
            Status::invalid_argument("Missing 'config' field")
        })?;
        let encoding = proto::Encoding::try_from(config_tree.encoding)
            .map_err(|_| Status::invalid_argument("Invalid data encoding"))?;
        let config = DataTree::parse_string(
            yang_ctx,
            &config_tree.data,
            DataFormat::from(encoding),
            DataParserFlags::empty(),
            DataValidationFlags::NO_STATE,
        )
        .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let nb_request =
            api::client::Request::Validate(api::client::ValidateRequest {
                config,
                responder: responder_tx,
            });
        self.request_tx.send(nb_request).await.unwrap();

        // Receive response from the northbound.
        let _nb_response = responder_rx.await.unwrap()?;

        // Prepare and send response to the gRPC client.
        let grpc_response = proto::ValidateResponse {};
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
        let encoding = proto::Encoding::try_from(config_tree.encoding)
            .map_err(|_| Status::invalid_argument("Invalid data encoding"))?;
        let operation =
            proto::commit_request::Operation::try_from(grpc_request.operation)
                .map_err(|_| {
                    Status::invalid_argument("Invalid commit operation")
                })?;
        let config = match operation {
            proto::commit_request::Operation::Merge => {
                let config = DataTree::parse_string(
                    yang_ctx,
                    &config_tree.data,
                    DataFormat::from(encoding),
                    DataParserFlags::empty(),
                    DataValidationFlags::NO_STATE,
                )
                .map_err(|error| Status::invalid_argument(error.to_string()))?;
                api::CommitConfiguration::Merge(config)
            }
            proto::commit_request::Operation::Replace => {
                let config = DataTree::parse_string(
                    yang_ctx,
                    &config_tree.data,
                    DataFormat::from(encoding),
                    DataParserFlags::empty(),
                    DataValidationFlags::NO_STATE,
                )
                .map_err(|error| Status::invalid_argument(error.to_string()))?;
                api::CommitConfiguration::Replace(config)
            }
            proto::commit_request::Operation::Change => {
                let diff = DataDiff::parse_string(
                    yang_ctx,
                    &config_tree.data,
                    DataFormat::from(encoding),
                    DataParserFlags::NO_VALIDATION,
                    DataValidationFlags::NO_STATE
                        | DataValidationFlags::PRESENT,
                )
                .map_err(|error| Status::invalid_argument(error.to_string()))?;
                api::CommitConfiguration::Change(diff)
            }
        };

        let nb_request =
            api::client::Request::Commit(api::client::CommitRequest {
                config,
                comment: grpc_request.comment,
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
        let encoding = proto::Encoding::try_from(data.encoding)
            .map_err(|_| Status::invalid_argument("Invalid data encoding"))?;
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
                    comment: transaction.comment,
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
        let encoding = proto::Encoding::try_from(grpc_request.encoding)
            .map_err(|_| Status::invalid_argument("Invalid data encoding"))?;
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
            northbound::Error::TransactionIdNotFound(..) => {
                Status::invalid_argument(error.to_string())
            }
            northbound::Error::Get(..) => {
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
        match proto::get_request::DataType::try_from(data_type) {
            Ok(proto::get_request::DataType::All) => Ok(api::DataType::All),
            Ok(proto::get_request::DataType::Config) => {
                Ok(api::DataType::Configuration)
            }
            Ok(proto::get_request::DataType::State) => Ok(api::DataType::State),
            Err(_) => Err(Status::invalid_argument("Invalid data type")),
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
    let service = NorthboundService { request_tx };

    let server = Server::builder();
    let mut server = match config.tls.enabled {
        true => {
            let cert = match std::fs::read(&config.tls.certificate) {
                Ok(value) => value,
                Err(error) => {
                    error!(%error, "failed to read TLS certificate");
                    return;
                }
            };
            let key = match std::fs::read(&config.tls.key) {
                Ok(value) => value,
                Err(error) => {
                    error!(%error, "failed to read TLS key");
                    return;
                }
            };

            let identity = tonic::transport::Identity::from_pem(cert, key);
            server
                .tls_config(ServerTlsConfig::new().identity(identity))
                .expect("Failed to setup gRPC TLS")
        }
        false => server,
    };

    tokio::spawn(async move {
        server
            .add_service(
                proto::NorthboundServer::new(service)
                    .max_encoding_message_size(usize::MAX)
                    .max_decoding_message_size(usize::MAX),
            )
            .serve(address)
            .await
            .expect("Failed to start gRPC service");
    });
}
