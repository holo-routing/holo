//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::error::Error as _;
use std::net::SocketAddr;
use std::os::fd::AsFd;
use std::path::{Path as FsPath, PathBuf};
use std::pin::Pin;
use std::time::SystemTime;

use futures::Stream;
use holo_northbound::{Path, PathElem};
use holo_utils::auth::Users;
use holo_utils::task::Task;
use holo_yang::{YANG_CTX, YANG_FEATURES};
use nix::sys::stat::{Mode, fchmod};
use nix::unistd::{Uid, User};
use tokio::net::UnixListener;
use tokio::sync::mpsc::Sender;
use tokio::sync::{mpsc, oneshot, watch};
use tokio_stream::wrappers::{UnboundedReceiverStream, UnixListenerStream};
use tonic::metadata::MetadataMap;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::server::{Router, UdsConnectInfo};
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
use tracing::{trace, trace_span};
use yang5::data::{
    Data, DataDiff, DataFormat, DataOperation, DataParserFlags,
    DataPrinterFlags, DataTree, DataValidationFlags,
};
use yang5::schema::{SchemaOutputFormat, SchemaPrinterFlags};

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

// Authenticates northbound clients against the configured local users.
#[derive(Clone, Debug)]
pub(crate) struct Authenticator {
    users: watch::Receiver<Users>,
    unix: bool,
}

// User name a request was authenticated with.
#[derive(Clone, Debug)]
struct AuthenticatedUser(String);

// Where a server accepts connections.
#[derive(Debug)]
pub(crate) enum Listener {
    Tcp(SocketAddr),
    Unix(PathBuf),
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
        trace_span!("northbound").in_scope(|| {
            trace_span!("client", name = "grpc").in_scope(|| {
                trace!(data = ?grpc_request, "received Capabilities() request");
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
                supported_features: YANG_FEATURES
                    .get(&module.name())
                    .map(|features| {
                        features
                            .iter()
                            .map(|feature| (*feature).to_owned())
                            .collect()
                    })
                    .unwrap_or_default(),
            })
            .collect();

        // Fill-in supported data encodings.
        let supported_encodings = vec![
            proto::Encoding::Json as i32,
            proto::Encoding::Xml as i32,
            proto::Encoding::Lyb as i32,
        ];

        let reply = proto::CapabilitiesResponse {
            version,
            supported_modules,
            supported_encodings,
        };

        Ok(Response::new(reply))
    }

    async fn get_schema(
        &self,
        grpc_request: Request<proto::GetSchemaRequest>,
    ) -> Result<Response<proto::GetSchemaResponse>, Status> {
        let grpc_request = grpc_request.into_inner();
        trace_span!("northbound").in_scope(|| {
            trace_span!("client", name = "grpc").in_scope(|| {
                trace!(data = ?grpc_request, "received GetSchema() request");
            });
        });

        // Lookup schema module.
        let yang_ctx = YANG_CTX.get().unwrap();
        let module_name = grpc_request.module_name;
        let module_rev = get_optional_string(grpc_request.module_revision);
        let submodule_name = get_optional_string(grpc_request.submodule_name);
        let submodule_rev =
            get_optional_string(grpc_request.submodule_revision);
        let format = proto::SchemaFormat::try_from(grpc_request.format)
            .map_err(|_| Status::invalid_argument("Invalid schema format"))?;

        // Get module.
        let module = match module_rev {
            Some(module_rev) => {
                yang_ctx.get_module(&module_name, Some(&module_rev))
            }
            None => yang_ctx.get_module_latest(&module_name),
        }
        .ok_or_else(|| Status::not_found("YANG module not found"))?;

        let data = match submodule_name {
            Some(submodule_name) => {
                // Get submodule.
                let submodule = match submodule_rev {
                    Some(submodule_rev) => module
                        .get_submodule(&submodule_name, Some(&submodule_rev)),
                    None => module.get_submodule_latest(&submodule_name),
                }
                .ok_or_else(|| Status::not_found("YANG submodule not found"))?;

                // Print submodule data based on the requested format.
                submodule
                    .print_string(format.into(), SchemaPrinterFlags::empty())
                    .expect("Failed to print YANG submodule")
            }
            None => {
                // Print module data based on the requested format.
                module
                    .print_string(format.into(), SchemaPrinterFlags::empty())
                    .expect("Failed to print YANG module")
            }
        };

        // Return schema data to the gRPC client.
        let grpc_response = proto::GetSchemaResponse { data };
        Ok(Response::new(grpc_response))
    }

    async fn get_state(
        &self,
        grpc_request: Request<proto::GetStateRequest>,
    ) -> Result<Response<proto::GetStateResponse>, Status> {
        let grpc_request = grpc_request.into_inner();
        trace_span!("northbound").in_scope(|| {
            trace_span!("client", name = "grpc").in_scope(|| {
                trace!(data = ?grpc_request, "received GetState() request");
            });
        });

        // Create oneshot channel to receive response back from the northbound.
        let (responder_tx, responder_rx) = oneshot::channel();

        // Convert and relay gRPC request to the northbound.
        let encoding = proto::Encoding::try_from(grpc_request.encoding)
            .map_err(|_| Status::invalid_argument("Invalid data encoding"))?;
        let with_defaults = grpc_request.with_defaults;
        let path = grpc_request.path.map(Path::from);
        let nb_request =
            api::client::Request::GetState(api::client::GetStateRequest {
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
        let data = data_tree_init(&nb_response.dtree, encoding, printer_flags)?;
        let grpc_response = proto::GetStateResponse {
            timestamp: get_timestamp(),
            data: Some(data),
        };
        Ok(Response::new(grpc_response))
    }

    async fn get_config(
        &self,
        grpc_request: Request<proto::GetConfigRequest>,
    ) -> Result<Response<proto::GetConfigResponse>, Status> {
        let grpc_request = grpc_request.into_inner();
        trace_span!("northbound").in_scope(|| {
            trace_span!("client", name = "grpc").in_scope(|| {
                trace!(data = ?grpc_request, "received GetConfig() request");
            });
        });

        // Create oneshot channel to receive response back from the northbound.
        let (responder_tx, responder_rx) = oneshot::channel();

        // Convert and relay gRPC request to the northbound.
        let encoding = proto::Encoding::try_from(grpc_request.encoding)
            .map_err(|_| Status::invalid_argument("Invalid data encoding"))?;
        let with_defaults = grpc_request.with_defaults;
        let path = grpc_request.path.map(Path::from);
        let nb_request =
            api::client::Request::GetConfig(api::client::GetConfigRequest {
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
        let data = data_tree_init(&nb_response.dtree, encoding, printer_flags)?;
        let grpc_response = proto::GetConfigResponse {
            timestamp: get_timestamp(),
            data: Some(data),
        };
        Ok(Response::new(grpc_response))
    }

    async fn validate(
        &self,
        grpc_request: Request<proto::ValidateRequest>,
    ) -> Result<Response<proto::ValidateResponse>, Status> {
        let grpc_request = grpc_request.into_inner();
        trace_span!("northbound").in_scope(|| {
            trace_span!("client", name = "grpc").in_scope(|| {
                trace!(data = ?grpc_request, "received Validate() request");
            });
        });

        // Create oneshot channel to receive response back from the northbound.
        let (responder_tx, responder_rx) = oneshot::channel();

        // Convert and relay gRPC request to the northbound.
        let config = grpc_request.config.ok_or_else(|| {
            Status::invalid_argument("Missing 'config' field")
        })?;
        let config = data_tree_get(&config)?;
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
        let author = request_author(&grpc_request);
        let grpc_request = grpc_request.into_inner();
        trace_span!("northbound").in_scope(|| {
            trace_span!("client", name = "grpc").in_scope(|| {
                trace!(data = ?grpc_request, "received Commit() request");
            });
        });

        // Create oneshot channel to receive response back from the northbound.
        let (responder_tx, responder_rx) = oneshot::channel();

        // Convert and relay gRPC request to the northbound.
        let config = grpc_request.config.ok_or_else(|| {
            Status::invalid_argument("Missing 'config' field")
        })?;
        let operation =
            proto::commit_request::Operation::try_from(grpc_request.operation)
                .map_err(|_| {
                    Status::invalid_argument("Invalid commit operation")
                })?;
        let config = match operation {
            proto::commit_request::Operation::Merge => {
                let config = data_tree_get(&config)?;
                api::CommitConfiguration::Merge(config)
            }
            proto::commit_request::Operation::Replace => {
                let config = data_tree_get(&config)?;
                api::CommitConfiguration::Replace(config)
            }
            proto::commit_request::Operation::Change => {
                let diff = data_diff_get(&config)?;
                api::CommitConfiguration::Change(diff)
            }
        };

        let nb_request =
            api::client::Request::Commit(api::client::CommitRequest {
                config,
                author,
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
        let grpc_request = grpc_request.into_inner();
        trace_span!("northbound").in_scope(|| {
            trace_span!("client", name = "grpc").in_scope(|| {
                trace!(data = ?grpc_request, "received Execute() request");
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
        let data = rpc_get(&data)?;
        let nb_request =
            api::client::Request::Execute(api::client::ExecuteRequest {
                data,
                responder: responder_tx,
            });
        self.request_tx.send(nb_request).await.unwrap();

        // Receive response from the northbound.
        let nb_response = responder_rx.await.unwrap()?;

        // Convert and relay northbound response to the gRPC client.
        let printer_flags = DataPrinterFlags::WITH_SIBLINGS;
        let data = data_tree_init(&nb_response.data, encoding, printer_flags)?;
        let grpc_response = proto::ExecuteResponse { data: Some(data) };
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
        trace_span!("northbound").in_scope(|| {
            trace_span!("client", name = "grpc").in_scope(|| {
                trace!(data = ?grpc_request, "received GetTransaction() request");
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
                    author: transaction.author,
                    comment: transaction.comment,
                })
            });

        Ok(Response::new(Box::pin(futures::stream::iter(transactions))))
    }

    async fn get_transaction(
        &self,
        grpc_request: Request<proto::GetTransactionRequest>,
    ) -> Result<Response<proto::GetTransactionResponse>, Status> {
        let grpc_request = grpc_request.into_inner();
        trace_span!("northbound").in_scope(|| {
            trace_span!("client", name = "grpc").in_scope(|| {
                trace!(data = ?grpc_request, "received Execute() request");
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
        let printer_flags = DataPrinterFlags::WITH_SIBLINGS;
        let config =
            data_tree_init(&nb_response.dtree, encoding, printer_flags)?;
        let grpc_response = proto::GetTransactionResponse {
            config: Some(config),
        };
        Ok(Response::new(grpc_response))
    }

    type SubscribeStream =
        Pin<Box<dyn Stream<Item = Result<proto::Notification, Status>> + Send>>;

    async fn subscribe(
        &self,
        grpc_request: Request<proto::SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let grpc_request = grpc_request.into_inner();
        trace_span!("northbound").in_scope(|| {
            trace_span!("client", name = "grpc").in_scope(|| {
                trace!(data = ?grpc_request, "received Subscribe() request");
            });
        });

        let encoding = proto::Encoding::try_from(grpc_request.encoding)
            .map_err(|_| Status::invalid_argument("Invalid data encoding"))?;
        let path = get_optional_string(grpc_request.path);

        // Create channel for receiving notifications from the daemon.
        let (tx, rx) = mpsc::unbounded_channel();

        // Register subscription with the daemon.
        let nb_request =
            api::client::Request::Subscribe(api::client::SubscribeRequest {
                path,
                tx,
            });
        self.request_tx.send(nb_request).await.unwrap();

        // Convert internal notifications to gRPC format.
        let stream = UnboundedReceiverStream::new(rx);
        let output = futures::StreamExt::map(stream, move |notification| {
            let printer_flags = DataPrinterFlags::WITH_SIBLINGS;
            let data =
                data_tree_init(&notification.data, encoding, printer_flags)?;
            Ok(proto::Notification {
                timestamp: get_timestamp(),
                module_path: notification.path,
                data: Some(data),
            })
        });

        Ok(Response::new(Box::pin(output)))
    }
}

// ===== impl Authenticator =====

impl Authenticator {
    pub(crate) fn new(
        users: watch::Receiver<Users>,
        listener: &Listener,
    ) -> Authenticator {
        let unix = matches!(listener, Listener::Unix(_));

        Authenticator { users, unix }
    }

    // Rejects the request unless it carries the credentials of a configured
    // user.
    pub(crate) fn intercept(
        &self,
        mut request: Request<()>,
    ) -> Result<Request<()>, Status> {
        if let Some(user) = self.authenticate(request.metadata())? {
            request.extensions_mut().insert(AuthenticatedUser(user));
        }

        Ok(request)
    }

    fn authenticate(
        &self,
        metadata: &MetadataMap,
    ) -> Result<Option<String>, Status> {
        // The socket's file permissions already decide who may connect, and
        // the peer's identity comes from the kernel, so no password is asked
        // for.
        if self.unix {
            return Ok(None);
        }

        let Some((username, password)) = credentials(metadata) else {
            return Err(Status::unauthenticated("missing credentials"));
        };

        // The same error covers an unknown user and a wrong password, so that
        // valid user names can't be harvested.
        let users = self.users.borrow().clone();
        if !users
            .get(username)
            .is_some_and(|user| user.verify_password(password))
        {
            return Err(Status::unauthenticated("invalid credentials"));
        }

        Ok(Some(username.to_owned()))
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
                Status::not_found(error.to_string())
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

impl From<proto::SchemaFormat> for SchemaOutputFormat {
    fn from(format: proto::SchemaFormat) -> SchemaOutputFormat {
        match format {
            proto::SchemaFormat::Yang => SchemaOutputFormat::YANG,
            proto::SchemaFormat::Yin => SchemaOutputFormat::YIN,
        }
    }
}

impl From<proto::Path> for Path {
    fn from(path: proto::Path) -> Self {
        Path {
            elems: path.elem.into_iter().map(PathElem::from).collect(),
        }
    }
}

impl From<proto::PathElem> for PathElem {
    fn from(elem: proto::PathElem) -> Self {
        PathElem {
            name: elem.name,
            keys: elem.key,
        }
    }
}

// ===== helper functions =====

fn read_pem(path: &str, name: &str) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("failed to read the {name} {path}: {error}");
            std::process::exit(1);
        }
    }
}

fn credentials(metadata: &MetadataMap) -> Option<(&str, &str)> {
    let username = metadata.get("username")?.to_str().ok()?;
    let password = metadata.get("password")?.to_str().ok()?;

    Some((username, password))
}

fn get_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("System time before UNIX EPOCH!")
        .as_secs() as i64
}

fn get_optional_string(data: String) -> Option<String> {
    if data.is_empty() { None } else { Some(data) }
}

fn data_tree_init(
    dtree: &DataTree<'static>,
    encoding: proto::Encoding,
    printer_flags: DataPrinterFlags,
) -> Result<proto::DataTree, Status> {
    let data_format = DataFormat::from(encoding);
    let data = match data_format {
        DataFormat::JSON | DataFormat::XML => {
            let string = dtree
                .print_string(data_format, printer_flags)
                .map_err(|error| Status::internal(error.to_string()))?;
            proto::data_tree::Data::DataString(string)
        }
        DataFormat::LYB => {
            let bytes = dtree
                .print_bytes(data_format, printer_flags)
                .map_err(|error| Status::internal(error.to_string()))?;
            proto::data_tree::Data::DataBytes(bytes)
        }
    };

    Ok(proto::DataTree {
        encoding: encoding as i32,
        data: Some(data),
    })
}

fn data_tree_get(
    data_tree: &proto::DataTree,
) -> Result<DataTree<'static>, Status> {
    let yang_ctx = YANG_CTX.get().unwrap();
    let encoding = proto::Encoding::try_from(data_tree.encoding)
        .map_err(|_| Status::invalid_argument("Invalid data encoding"))?;
    let data_format = DataFormat::from(encoding);
    let parser_flags = DataParserFlags::STRICT;
    let validation_flags = DataValidationFlags::NO_STATE;
    let data = data_tree
        .data
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("Missing 'data' field"))?;
    match data {
        proto::data_tree::Data::DataString(data) => DataTree::parse_string(
            yang_ctx,
            data,
            data_format,
            parser_flags,
            validation_flags,
        ),
        proto::data_tree::Data::DataBytes(data) => DataTree::parse_string(
            yang_ctx,
            data,
            data_format,
            parser_flags,
            validation_flags,
        ),
    }
    .map_err(|error| Status::invalid_argument(error.to_string()))
}

fn data_diff_get(
    data_tree: &proto::DataTree,
) -> Result<DataDiff<'static>, Status> {
    let yang_ctx = YANG_CTX.get().unwrap();
    let encoding = proto::Encoding::try_from(data_tree.encoding)
        .map_err(|_| Status::invalid_argument("Invalid data encoding"))?;
    let data_format = DataFormat::from(encoding);
    let parser_flags = DataParserFlags::NO_VALIDATION | DataParserFlags::STRICT;
    let validation_flags =
        DataValidationFlags::NO_STATE | DataValidationFlags::PRESENT;
    let data = data_tree
        .data
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("Missing 'data' field"))?;
    match data {
        proto::data_tree::Data::DataString(data) => DataDiff::parse_string(
            yang_ctx,
            data,
            data_format,
            parser_flags,
            validation_flags,
        ),
        proto::data_tree::Data::DataBytes(data) => DataDiff::parse_string(
            yang_ctx,
            data,
            data_format,
            parser_flags,
            validation_flags,
        ),
    }
    .map_err(|error| Status::invalid_argument(error.to_string()))
}

fn rpc_get(data_tree: &proto::DataTree) -> Result<DataTree<'static>, Status> {
    let yang_ctx = YANG_CTX.get().unwrap();
    let encoding = proto::Encoding::try_from(data_tree.encoding)
        .map_err(|_| Status::invalid_argument("Invalid data encoding"))?;
    let data_format = DataFormat::from(encoding);
    let data = data_tree
        .data
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("Missing 'data' field"))?;
    match data {
        proto::data_tree::Data::DataString(data) => DataTree::parse_op_string(
            yang_ctx,
            data,
            data_format,
            DataParserFlags::STRICT,
            DataOperation::RpcYang,
        ),
        proto::data_tree::Data::DataBytes(data) => DataTree::parse_op_string(
            yang_ctx,
            data,
            data_format,
            DataParserFlags::STRICT,
            DataOperation::RpcYang,
        ),
    }
    .map_err(|error| Status::invalid_argument(error.to_string()))
}

// Binds the Unix socket, restricting it to the user and group holod runs as.
fn unix_listener(path: &FsPath) -> std::io::Result<UnixListenerStream> {
    // A socket left behind by a previous run would make the bind fail.
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            return Err(error);
        }
        _ => {}
    }

    let listener = UnixListener::bind(path)?;
    // Add the write access left out by the umask.
    fchmod(listener.as_fd(), Mode::from_bits_truncate(0o660))?;

    Ok(UnixListenerStream::new(listener))
}

// ===== global functions =====

// Identifies who issued a request.
//
// A Unix socket carries the peer's credentials, so its user comes from the
// kernel and is prefixed with "unix:". A remote request is attributed to the
// user it authenticated as, qualified by the address it came from.
pub(crate) fn request_author<T>(request: &Request<T>) -> String {
    const UNKNOWN: &str = "unknown";

    if let Some(info) = request.extensions().get::<UdsConnectInfo>() {
        let user = match info.peer_cred {
            Some(cred) => {
                let uid = Uid::from_raw(cred.uid());
                User::from_uid(uid)
                    .ok()
                    .flatten()
                    .map(|user| user.name)
                    .unwrap_or_else(|| format!("uid:{uid}"))
            }
            None => UNKNOWN.to_owned(),
        };
        return format!("unix:{user}");
    }

    let user = request
        .extensions()
        .get::<AuthenticatedUser>()
        .map(|user| user.0.as_str())
        .unwrap_or(UNKNOWN);
    match request.remote_addr() {
        Some(address) => format!("{user}@{}", address.ip()),
        None => user.to_owned(),
    }
}

// Sets up the listener and the server for the given address.
//
// An address starting with a slash is taken as the path of a Unix socket,
// which is protected by its file permissions. A TCP address requires TLS, as
// credentials would otherwise cross the network in the clear.
pub(crate) fn server_init(
    name: &str,
    address: &str,
    tls: &config::Tls,
) -> (Listener, Server) {
    let listener = match address.starts_with('/') {
        true => Listener::Unix(PathBuf::from(address)),
        false => match address.parse::<SocketAddr>() {
            Ok(address) => Listener::Tcp(address),
            Err(error) => {
                eprintln!("failed to parse the {name} server address: {error}");
                std::process::exit(1);
            }
        },
    };

    let server = Server::builder();
    let server = match &listener {
        Listener::Tcp(_) => {
            let cert = read_pem(&tls.certificate, "TLS certificate");
            let key = read_pem(&tls.key, "TLS key");
            let identity = Identity::from_pem(cert, key);
            let tls_config = ServerTlsConfig::new().identity(identity);
            match server.tls_config(tls_config) {
                Ok(server) => server,
                Err(error) => {
                    eprintln!("failed to setup {name} TLS: {error}");
                    std::process::exit(1);
                }
            }
        }
        Listener::Unix(_) => server,
    };

    (listener, server)
}

// Binds the listener and serves requests, terminating the daemon on failure.
pub(crate) async fn serve(name: &str, listener: Listener, router: Router) {
    let result = match &listener {
        Listener::Tcp(address) => router.serve(*address).await,
        Listener::Unix(path) => match unix_listener(path) {
            Ok(incoming) => router.serve_with_incoming(incoming).await,
            Err(error) => {
                eprintln!(
                    "failed to bind the {name} socket {}: {error}",
                    path.display()
                );
                std::process::exit(1);
            }
        },
    };
    if let Err(error) = result {
        let address = match &listener {
            Listener::Tcp(address) => address.to_string(),
            Listener::Unix(path) => path.display().to_string(),
        };
        let mut message =
            format!("failed to start the {name} service on {address}: {error}");
        let mut source = error.source();
        while let Some(error) = source {
            message += &format!(": {error}");
            source = error.source();
        }
        eprintln!("{message}");
        std::process::exit(1);
    }
}

pub(crate) fn start(
    config: &config::Grpc,
    request_tx: Sender<api::client::Request>,
    users: watch::Receiver<Users>,
) -> Vec<Task<()>> {
    config
        .address
        .iter()
        .map(|address| {
            let (listener, mut server) =
                server_init("gRPC", address, &config.tls);
            let auth = Authenticator::new(users.clone(), &listener);
            let service = NorthboundService {
                request_tx: request_tx.clone(),
            };
            let router = server.add_service(InterceptedService::new(
                proto::NorthboundServer::new(service)
                    .max_encoding_message_size(usize::MAX)
                    .max_decoding_message_size(usize::MAX),
                move |request| auth.intercept(request),
            ));

            Task::spawn(async move {
                serve("gRPC", listener, router).await;
            })
        })
        .collect()
}
