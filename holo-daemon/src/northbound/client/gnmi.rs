//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::time::SystemTime;

use holo_utils::Sender;
use holo_yang::YANG_CTX;
use itertools::join;
use tokio::sync::oneshot;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Server, ServerTlsConfig};
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, debug_span, error, trace};
use yang2::data::{Data, DataFormat, DataPrinterFlags, DataTree};
use yang2::schema::SchemaNodeKind;

use crate::config;
use crate::northbound::client::api;

const GNMI_VERSION: &str = "0.8.1";

mod proto {
    #![allow(clippy::all)]
    tonic::include_proto!("gnmi");
    pub use g_nmi_server::{GNmi, GNmiServer};
}

mod gnmi_ext {
    #![allow(clippy::all)]
    tonic::include_proto!("gnmi_ext");
}

struct GNmiService {
    request_tx: Sender<api::client::Request>,
}

// ===== impl proto::Northbound =====

#[tonic::async_trait]
impl proto::GNmi for GNmiService {
    type SubscribeStream =
        ReceiverStream<Result<proto::SubscribeResponse, Status>>;

    async fn capabilities(
        &self,
        grpc_request: Request<proto::CapabilityRequest>,
    ) -> Result<Response<proto::CapabilityResponse>, Status> {
        let yang_ctx = YANG_CTX.get().unwrap();
        let grpc_request = grpc_request.into_inner();
        debug_span!("northbound").in_scope(|| {
            debug_span!("client", name = "grpc").in_scope(|| {
                debug!("received Capabilities() request");
                trace!("{:?}", grpc_request);
            });
        });

        // Fill-in supported YANG modules.
        let supported_models = yang_ctx
            .modules(true)
            .filter(|module| module.is_implemented())
            .map(|module| proto::ModelData {
                name: module.name().to_owned(),
                organization: module
                    .organization()
                    .unwrap_or_default()
                    .to_owned(),
                version: module.revision().unwrap_or_default().to_owned(),
            })
            .collect();

        // Fill-in supported data encodings.
        let supported_encodings = vec![
            proto::Encoding::Proto as i32,
            proto::Encoding::JsonIetf as i32,
        ];

        let reply = proto::CapabilityResponse {
            g_nmi_version: GNMI_VERSION.to_owned(),
            supported_models,
            supported_encodings,
            extension: Default::default(),
        };

        Ok(Response::new(reply))
    }

    async fn get(
        &self,
        grpc_request: Request<proto::GetRequest>,
    ) -> Result<Response<proto::GetResponse>, Status> {
        let grpc_request = grpc_request.into_inner();
        debug_span!("northbound").in_scope(|| {
            debug_span!("client", name = "gnmi").in_scope(|| {
                debug!("received Get() request");
                trace!("{:?}", grpc_request);
            });
        });

        // Get data type.
        let data_type =
            match proto::get_request::DataType::from_i32(grpc_request.r#type) {
                Some(proto::get_request::DataType::All) => api::DataType::All,
                Some(proto::get_request::DataType::Config) => {
                    api::DataType::Configuration
                }
                Some(
                    proto::get_request::DataType::State
                    | proto::get_request::DataType::Operational,
                ) => api::DataType::State,
                None => {
                    return Err(Status::invalid_argument("Invalid data type"))
                }
            };

        // Get encoding type.
        let encoding = match proto::Encoding::from_i32(grpc_request.encoding) {
            Some(proto::Encoding::Proto) => proto::Encoding::Proto,
            Some(proto::Encoding::JsonIetf) => proto::Encoding::JsonIetf,
            _ => return Err(Status::invalid_argument("Invalid data encoding")),
        };

        // Convert and relay gNMI request to the northbound.
        let mut notification = vec![];
        for entry in grpc_request.path {
            let mut path = "/".to_owned();
            if let Some(prefix) = &grpc_request.prefix {
                path.push_str(&prefix.to_string());
            }
            path.push_str(&entry.to_string());

            // Create oneshot channel to receive response back from the
            // northbound.
            let (responder_tx, responder_rx) = oneshot::channel();
            let nb_request = api::client::GetRequest {
                data_type,
                path: Some(path),
                responder: responder_tx,
            };
            let nb_request = api::client::Request::Get(nb_request);
            self.request_tx.send(nb_request).await.unwrap();

            // Receive response from the northbound.
            let nb_response = responder_rx.await.unwrap()?;

            // Fill-in update message.
            let models = &grpc_request.use_models;
            let update = match encoding {
                proto::Encoding::Proto => {
                    self.gen_update_proto(nb_response.dtree, models)
                }
                proto::Encoding::JsonIetf => {
                    self.gen_update_ietf_json(nb_response.dtree, models)
                }
                _ => unreachable!(),
            };

            // Fill-in gNMI response for this path.
            notification.push(proto::Notification {
                timestamp: get_timestamp(),
                prefix: None,
                update,
                delete: Default::default(),
                atomic: false,
            });
        }

        // Convert and relay northbound response to the gNMI client.
        #[allow(deprecated)]
        let grpc_response = proto::GetResponse {
            notification,
            error: None,
            extension: Default::default(),
        };
        Ok(Response::new(grpc_response))
    }

    async fn set(
        &self,
        grpc_request: Request<proto::SetRequest>,
    ) -> Result<Response<proto::SetResponse>, Status> {
        let yang_ctx = YANG_CTX.get().unwrap();
        let grpc_request = grpc_request.into_inner();
        debug_span!("northbound").in_scope(|| {
            debug_span!("client", name = "gnmi").in_scope(|| {
                debug!("received Set() request");
                trace!("{:?}", grpc_request);
            });
        });

        // Create candidate configuration.
        let mut candidate = if !grpc_request.replace.is_empty() {
            DataTree::new(yang_ctx)
        } else {
            self.get_running().await?
        };

        // Create oneshot channel to receive response back from the northbound.
        let (responder_tx, responder_rx) = oneshot::channel();

        // Paths to be deleted from the data tree.
        for entry in grpc_request.delete {
            let mut path = "/".to_owned();
            if let Some(prefix) = &grpc_request.prefix {
                path.push_str(&prefix.to_string());
            }
            path.push_str(&entry.to_string());

            // Edit candidate configuration.
            candidate.remove(&path).unwrap();
        }

        // Updates specifying elements to updated.
        for entry in grpc_request.replace.into_iter().chain(grpc_request.update)
        {
            let mut path = "/".to_owned();
            if let Some(prefix) = &grpc_request.prefix {
                path.push_str(&prefix.to_string());
            }
            if let Some(entry) = entry.path {
                path.push_str(&entry.to_string());
            }

            let value = entry.val.and_then(|val| val.into_opt_string());

            // Edit candidate configuration.
            let snode = yang_ctx
                .find_path(&path)
                .map_err(|error| Status::invalid_argument(error.to_string()))?;
            if matches!(
                snode.kind(),
                SchemaNodeKind::Leaf | SchemaNodeKind::LeafList
            ) {
                candidate.new_path(&path, value.as_deref(), false).map_err(
                    |error| Status::invalid_argument(error.to_string()),
                )?;
            } else {
                // TODO: parse subtree and merge onto candidate.
            }
        }

        // Convert and relay gNMI request to the northbound.
        let nb_request = api::client::CommitRequest {
            operation: api::CommitOperation::Replace,
            config: candidate,
            comment: Default::default(),
            confirmed_timeout: 0,
            responder: responder_tx,
        };
        let nb_request = api::client::Request::Commit(nb_request);
        self.request_tx.send(nb_request).await.unwrap();

        // Receive response from the northbound.
        let _nb_response = responder_rx.await.unwrap()?;

        // Prepare and send response to the gNMI client.
        #[allow(deprecated)]
        let reply = proto::SetResponse {
            prefix: grpc_request.prefix,
            // TODO: fill updated/removed paths.
            response: Default::default(),
            message: None,
            timestamp: get_timestamp(),
            extension: Default::default(),
        };
        Ok(Response::new(reply))
    }

    async fn subscribe(
        &self,
        _request: Request<Streaming<proto::SubscribeRequest>>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        // TODO: not implemented yet.
        Err(Status::internal("unsupported RPC".to_owned()))
    }
}

impl GNmiService {
    fn gen_update_ietf_json(
        &self,
        dtree: DataTree,
        _models: &[proto::ModelData],
    ) -> Vec<proto::Update> {
        dtree
            .reference()
            .unwrap()
            .inclusive_siblings()
            .map(|dnode| {
                let snode = dnode.schema();

                // Data node's path.
                #[allow(deprecated)]
                let path = proto::Path {
                    element: vec![],
                    origin: snode.module().name().to_owned(),
                    elem: dnode
                        .inclusive_ancestors()
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .map(|dnode| proto::PathElem {
                            name: dnode.schema().name().to_owned(),
                            key: dnode
                                .list_keys()
                                .map(|dnode| {
                                    (
                                        dnode.schema().name().to_owned(),
                                        dnode.value_canonical().unwrap(),
                                    )
                                })
                                .collect(),
                        })
                        .collect(),
                    target: String::new(),
                };

                // Data node's value.
                // TODO: filter by "use_models".
                let val = dnode
                    .print_string(
                        DataFormat::JSON,
                        DataPrinterFlags::WITH_SIBLINGS,
                    )
                    .unwrap()
                    .unwrap_or_default();
                let val = proto::TypedValue {
                    value: Some(proto::typed_value::Value::JsonIetfVal(
                        val.into_bytes(),
                    )),
                };

                #[allow(deprecated)]
                proto::Update {
                    path: Some(path),
                    value: None,
                    val: Some(val),
                    duplicates: 0,
                }
            })
            .collect()
    }

    fn gen_update_proto(
        &self,
        dtree: DataTree,
        _models: &[proto::ModelData],
    ) -> Vec<proto::Update> {
        dtree
            .traverse()
            .filter(|dnode| !dnode.schema().is_schema_only())
            .filter(|dnode| !dnode.schema().is_np_container())
            .filter(|dnode| !dnode.schema().is_list_key())
            .map(|dnode| {
                let snode = dnode.schema();

                // TODO: filter by "use_models".

                // Data node's path.
                #[allow(deprecated)]
                let path = proto::Path {
                    element: vec![],
                    origin: snode.module().name().to_owned(),
                    elem: dnode
                        .inclusive_ancestors()
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .map(|dnode| proto::PathElem {
                            name: dnode.schema().name().to_owned(),
                            key: dnode
                                .list_keys()
                                .map(|dnode| {
                                    (
                                        dnode.schema().name().to_owned(),
                                        dnode.value_canonical().unwrap(),
                                    )
                                })
                                .collect(),
                        })
                        .collect(),
                    target: String::new(),
                };
                // Data node's value.
                // TODO: use other types.
                let val = dnode.value_canonical().map(|v| proto::TypedValue {
                    value: Some(proto::typed_value::Value::StringVal(v)),
                });

                #[allow(deprecated)]
                proto::Update {
                    path: Some(path),
                    value: None,
                    val,
                    duplicates: 0,
                }
            })
            .collect()
    }

    async fn get_running(&self) -> Result<DataTree, Status> {
        // Create oneshot channel to receive response back from the northbound.
        let (responder_tx, responder_rx) = oneshot::channel();

        // Send request to the northbound.
        let nb_request = api::client::GetRequest {
            data_type: api::DataType::Configuration,
            path: None,
            responder: responder_tx,
        };
        let nb_request = api::client::Request::Get(nb_request);
        self.request_tx.send(nb_request).await.unwrap();

        // Receive response from the northbound.
        let nb_response = responder_rx.await.unwrap()?;
        Ok(nb_response.dtree)
    }
}

// ===== Display methods =====

impl std::fmt::Display for proto::Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let path = join(
            self.elem.iter().map(|pelm| {
                if pelm.key.is_empty() {
                    pelm.name.to_owned()
                } else {
                    let keys = join(
                        pelm.key
                            .iter()
                            .map(|(key, value)| format!("[{key}=\"{value}\"]")),
                        "",
                    );
                    format!("{}{}", pelm.name, keys)
                }
            }),
            "/",
        );

        write!(f, "{}", path)
    }
}

impl proto::TypedValue {
    fn into_opt_string(self) -> Option<String> {
        use proto::typed_value::Value;

        self.value.and_then(|value| {
            match value {
                Value::StringVal(v) => Some(v),
                Value::IntVal(v) => Some(v.to_string()),
                Value::UintVal(v) => Some(v.to_string()),
                Value::BoolVal(v) => Some(if v {
                    "true".to_owned()
                } else {
                    "false".to_owned()
                }),
                Value::JsonVal(v) | Value::JsonIetfVal(v) => {
                    String::from_utf8(v).ok()
                }
                // TODO: support other data types.
                _ => None,
            }
        })
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
    config: &config::Gnmi,
    request_tx: Sender<api::client::Request>,
) {
    let address = config
        .address
        .parse()
        .expect("Failed to parse gNMI server address");
    let service = GNmiService { request_tx };

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
                .expect("Failed to setup gNMI TLS")
        }
        false => server,
    };

    tokio::spawn(async move {
        server
            .add_service(proto::GNmiServer::new(service))
            .serve(address)
            .await
            .expect("Failed to start gNMI service");
    });
}
