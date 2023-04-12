//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::{Receiver, Sender};

use crate::bfd;
use crate::ip::AddressFamily;
use crate::sr::SrCfg;

// Useful type definition(s).
pub type IbusReceiver = Receiver<IbusMsg>;
pub type IbusSender = Sender<IbusMsg>;

// Ibus message for communication among the different Holo components.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum IbusMsg {
    // Segment Routing configuration change.
    SrCfgEvent {
        event: SrCfgEventMsg,
        sr_config: Arc<SrCfg>,
    },
    // BFD peer registration.
    BfdSessionReg {
        sess_key: bfd::SessionKey,
        client_id: bfd::ClientId,
        client_config: Option<bfd::ClientCfg>,
    },
    // BFD peer unregistration.
    BfdSessionUnreg {
        sess_key: bfd::SessionKey,
        client_id: bfd::ClientId,
    },
    // BFD peer state update.
    BfdStateUpd {
        sess_key: bfd::SessionKey,
        state: bfd::State,
    },
}

// Type of Segment Routing configuration change.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum SrCfgEventMsg {
    LabelRangeUpdate,
    PrefixSidUpdate(AddressFamily),
}
