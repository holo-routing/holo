//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;

use holo_yang::{ToYang, TryFromYang};
use num_traits::FromPrimitive;

use crate::neighbor::{PeerType, fsm};
use crate::northbound::configuration::{
    InstanceTraceOption, NeighborTraceOption, PrivateAsRemove,
};
use crate::packet::consts::{
    AddPathMode, AsPathSegmentType, CapabilityCode, CeaseSubcode, ErrorCode,
    FsmErrorSubcode, MessageHeaderErrorSubcode, OpenMessageErrorSubcode,
    RouteRefreshErrorSubcode, Safi, UpdateMessageErrorSubcode,
};
use crate::packet::message::NotificationMsg;
use crate::rib::{RouteIneligibleReason, RouteOrigin, RouteRejectReason};

// ===== ToYang implementations =====

impl ToYang for Safi {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            Safi::Unicast => "unicast-safi".into(),
            Safi::Multicast => "multicast-safi".into(),
            Safi::LabeledUnicast => "labeled-unicast-safi".into(),
            Safi::MulticastVpn => "multicast-vpn-safi".into(),
            Safi::Pseudowire => "pseudowire-safi".into(),
            Safi::TunnelEncap => "tunnel-encap-safi".into(),
            Safi::McastVpls => "mcast-vpls-safi".into(),
            Safi::Tunnel => "tunnel-safi".into(),
            Safi::Vpls => "vpls-safi".into(),
            Safi::Mdt => "mdt-safi".into(),
            Safi::V4OverV6 => "v4-over-v6-safi".into(),
            Safi::V6OverV4 => "v6-over-v4-safi".into(),
            Safi::L1VpnAutoDiscovery => "l1-vpn-auto-discovery-safi".into(),
            Safi::Evpn => "evpn-safi".into(),
            Safi::BgpLs => "bgp-ls-safi".into(),
            Safi::BgpLsVpn => "bgp-ls-vpn-safi".into(),
            Safi::SrTe => "sr-te-safi".into(),
            Safi::SdWanCapabilities => "sd-wan-capabilities-safi".into(),
            Safi::LabeledVpn => "labeled-vpn-safi".into(),
            Safi::MulticastMplsVpn => "multicast-mpls-vpn-safi".into(),
            Safi::RouteTarget => "route-target-safi".into(),
            Safi::Ipv4FlowSpec => "ipv4-flow-spec-safi".into(),
            Safi::Vpnv4FlowSpec => "vpnv4-flow-spec-safi".into(),
            Safi::VpnAutoDiscovery => "vpn-auto-discovery-safi".into(),
        }
    }
}

impl ToYang for AddPathMode {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            AddPathMode::Receive => "receive".into(),
            AddPathMode::Send => "send".into(),
            AddPathMode::ReceiveSend => "receive-send".into(),
        }
    }
}

impl ToYang for CapabilityCode {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            CapabilityCode::MultiProtocol => "iana-bgp-types:mp-bgp".into(),
            CapabilityCode::FourOctetAsNumber => "iana-bgp-types:asn32".into(),
            CapabilityCode::AddPath => "holo-bgp:add-paths".into(),
            CapabilityCode::RouteRefresh => {
                "iana-bgp-types:route-refresh".into()
            }
            CapabilityCode::EnhancedRouteRefresh => {
                "holo-bgp:enhanced-route-refresh".into()
            }
        }
    }
}

impl ToYang for NotificationMsg {
    fn to_yang(&self) -> Cow<'static, str> {
        let Some(error_code) = ErrorCode::from_u8(self.error_code) else {
            return "holo-bgp:unknown-error".into();
        };
        let identity = match error_code {
            ErrorCode::MessageHeaderError => {
                use MessageHeaderErrorSubcode as ErrorSubcode;
                match ErrorSubcode::from_u8(self.error_subcode) {
                    Some(ErrorSubcode::Unspecific) => {
                        "message-header-unspecific"
                    }
                    Some(ErrorSubcode::ConnectionNotSynchronized) => {
                        "message-header-connection-not-synchronized"
                    }
                    Some(ErrorSubcode::BadMessageLength) => {
                        "message-header-bad-message-length"
                    }
                    Some(ErrorSubcode::BadMessageType) => {
                        "message-header-bad-message-type"
                    }
                    None => "message-header-error",
                }
            }
            ErrorCode::OpenMessageError => {
                use OpenMessageErrorSubcode as ErrorSubcode;
                match ErrorSubcode::from_u8(self.error_subcode) {
                    Some(ErrorSubcode::Unspecific) => "open-message-unspecific",
                    Some(ErrorSubcode::UnsupportedVersionNumber) => {
                        "open-unsupported-version-number"
                    }
                    Some(ErrorSubcode::BadPeerAs) => "open-bad-peer-as",
                    Some(ErrorSubcode::BadBgpIdentifier) => "open-bad-bgp-id",
                    Some(ErrorSubcode::UnsupportedOptParam) => {
                        "open-unsupported-optional-parameter"
                    }
                    Some(ErrorSubcode::UnacceptableHoldTime) => {
                        "open-unacceptable-hold-time"
                    }
                    Some(ErrorSubcode::UnsupportedCapability) => {
                        "open-unsupported-capability"
                    }
                    Some(ErrorSubcode::RoleMismatch) => "open-role-mismatch",
                    None => "open-message-error",
                }
            }
            ErrorCode::UpdateMessageError => {
                use UpdateMessageErrorSubcode as ErrorSubcode;
                match ErrorSubcode::from_u8(self.error_subcode) {
                    Some(ErrorSubcode::Unspecific) => "update-unspecific",
                    Some(ErrorSubcode::MalformedAttributeList) => {
                        "update-malformed-attribute-list"
                    }
                    Some(ErrorSubcode::UnrecognizedWellKnownAttribute) => {
                        "update-unrecognized-well-known-attribute"
                    }
                    Some(ErrorSubcode::MissingWellKnownAttribute) => {
                        "update-missing-well-known-attribute"
                    }
                    Some(ErrorSubcode::AttributeFlagsError) => {
                        "update-attribute-flags-error"
                    }
                    Some(ErrorSubcode::AttributeLengthError) => {
                        "update-attribute-length-error"
                    }
                    Some(ErrorSubcode::InvalidOriginAttribute) => {
                        "update-invalid-origin-attribute"
                    }
                    Some(ErrorSubcode::InvalidNexthopAttribute) => {
                        "update-invalid-next-hop-attribute"
                    }
                    Some(ErrorSubcode::OptionalAttributeError) => {
                        "open-optional-attribute-error"
                    }
                    Some(ErrorSubcode::InvalidNetworkField) => {
                        "open-invalid-network-field"
                    }
                    Some(ErrorSubcode::MalformedAsPath) => {
                        "open-malformed-as-path"
                    }
                    None => "update-message-error",
                }
            }
            ErrorCode::HoldTimerExpired => "hold-timer-expired-error",
            ErrorCode::FiniteStateMachineError => {
                use FsmErrorSubcode as ErrorSubcode;
                match ErrorSubcode::from_u8(self.error_subcode) {
                    Some(ErrorSubcode::UnexpectedMessageInOpenSent) => {
                        "fsm-error-unexpected-in-opensent"
                    }
                    Some(ErrorSubcode::UnexpectedMessageInOpenConfirm) => {
                        "fsm-error-unexpected-in-openconfirm"
                    }
                    Some(ErrorSubcode::UnexpectedMessageInEstablished) => {
                        "fsm-error-unexpected-in-established"
                    }
                    None => "fsm-error",
                }
            }
            ErrorCode::Cease => {
                use CeaseSubcode as ErrorSubcode;
                match ErrorSubcode::from_u8(self.error_subcode) {
                    Some(ErrorSubcode::MaximumNumberofPrefixesReached) => {
                        "cease-max-prefixes"
                    }
                    Some(ErrorSubcode::AdministrativeShutdown) => {
                        "cease-admin-shutdown"
                    }
                    Some(ErrorSubcode::PeerDeConfigured) => {
                        "cease-peer-deconfigured"
                    }
                    Some(ErrorSubcode::AdministrativeReset) => {
                        "cease-admin-reset"
                    }
                    Some(ErrorSubcode::ConnectionRejected) => {
                        "cease-connection-rejected"
                    }
                    Some(ErrorSubcode::OtherConfigurationChange) => {
                        "cease-other-configuration-change"
                    }
                    Some(ErrorSubcode::ConnectionCollisionResolution) => {
                        "cease-connection-collision"
                    }
                    Some(ErrorSubcode::OutOfResources) => {
                        "cease-out-of-resources"
                    }
                    Some(ErrorSubcode::HardReset) => "cease-hard-reset",
                    Some(ErrorSubcode::BfdDown) => "cease-bfd-down",
                    None => "cease",
                }
            }
            ErrorCode::RouteRefreshMessageError => {
                use RouteRefreshErrorSubcode as ErrorSubcode;
                match ErrorSubcode::from_u8(self.error_subcode) {
                    Some(ErrorSubcode::InvalidMessageLength) => {
                        "route-refresh-invalid-message-length"
                    }
                    None => "route-refresh-message-error",
                }
            }
        };
        format!("iana-bgp-notification:{identity}").into()
    }
}

impl ToYang for fsm::State {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            fsm::State::Idle => "idle".into(),
            fsm::State::Connect => "connect".into(),
            fsm::State::Active => "active".into(),
            fsm::State::OpenSent => "opensent".into(),
            fsm::State::OpenConfirm => "openconfirm".into(),
            fsm::State::Established => "established".into(),
        }
    }
}

impl ToYang for PeerType {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            PeerType::Internal => "internal".into(),
            PeerType::External => "external".into(),
        }
    }
}

impl ToYang for AsPathSegmentType {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            AsPathSegmentType::Set => "iana-bgp-types:as-set".into(),
            AsPathSegmentType::Sequence => "iana-bgp-types:as-sequence".into(),
            AsPathSegmentType::ConfedSequence => {
                "iana-bgp-types:as-confed-sequence".into()
            }
            AsPathSegmentType::ConfedSet => {
                "iana-bgp-types:as-confed-set".into()
            }
        }
    }
}

impl ToYang for RouteOrigin {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            RouteOrigin::Neighbor { remote_addr, .. } => {
                remote_addr.to_string().into()
            }
            RouteOrigin::Protocol(protocol) => protocol.to_yang(),
        }
    }
}

impl ToYang for RouteIneligibleReason {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            RouteIneligibleReason::ClusterLoop => {
                "iana-bgp-rib-types:ineligible-cluster-loop".into()
            }
            RouteIneligibleReason::AsLoop => {
                "iana-bgp-rib-types:ineligible-as-loop".into()
            }
            RouteIneligibleReason::Originator => {
                "iana-bgp-rib-types:ineligible-originator".into()
            }
            RouteIneligibleReason::Confed => {
                "iana-bgp-rib-types:ineligible-confed".into()
            }
            RouteIneligibleReason::Unresolvable => {
                "holo-bgp:ineligible-unresolvable".into()
            }
        }
    }
}

impl ToYang for RouteRejectReason {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            RouteRejectReason::LocalPrefLower => {
                "iana-bgp-rib-types:local-pref-lower".into()
            }
            RouteRejectReason::AsPathLonger => {
                "iana-bgp-rib-types:as-path-longer".into()
            }
            RouteRejectReason::OriginTypeHigher => {
                "iana-bgp-rib-types:origin-type-higher".into()
            }
            RouteRejectReason::MedHigher => {
                "iana-bgp-rib-types:med-higher".into()
            }
            RouteRejectReason::PreferExternal => {
                "iana-bgp-rib-types:prefer-external".into()
            }
            RouteRejectReason::NexthopCostHigher => {
                "iana-bgp-rib-types:nexthop-cost-higher".into()
            }
            RouteRejectReason::HigherRouterId => {
                "iana-bgp-rib-types:higher-router-id".into()
            }
            RouteRejectReason::HigherPeerAddress => {
                "iana-bgp-rib-types:higher-peer-address".into()
            }
            RouteRejectReason::RejectedImportPolicy => {
                "iana-bgp-rib-types:rejected-import-policy".into()
            }
        }
    }
}

// ===== TryFromYang implementations =====

impl TryFromYang for PrivateAsRemove {
    fn try_from_yang(value: &str) -> Option<PrivateAsRemove> {
        match value {
            "iana-bgp-types:private-as-remove-all" => {
                Some(PrivateAsRemove::RemoveAll)
            }
            "iana-bgp-types:private-as-replace-all" => {
                Some(PrivateAsRemove::ReplaceAll)
            }
            _ => None,
        }
    }
}

impl TryFromYang for InstanceTraceOption {
    fn try_from_yang(value: &str) -> Option<InstanceTraceOption> {
        match value {
            "events" => Some(InstanceTraceOption::Events),
            "internal-bus" => Some(InstanceTraceOption::InternalBus),
            "nexthop-tracking" => Some(InstanceTraceOption::Nht),
            "packets-all" => Some(InstanceTraceOption::PacketsAll),
            "packets-open" => Some(InstanceTraceOption::PacketsOpen),
            "packets-update" => Some(InstanceTraceOption::PacketsUpdate),
            "packets-notification" => {
                Some(InstanceTraceOption::PacketsNotification)
            }
            "packets-keepalive" => Some(InstanceTraceOption::PacketsKeepalive),
            "packets-refresh" => Some(InstanceTraceOption::PacketsRefresh),
            "route" => Some(InstanceTraceOption::Route),
            _ => None,
        }
    }
}

impl TryFromYang for NeighborTraceOption {
    fn try_from_yang(value: &str) -> Option<NeighborTraceOption> {
        match value {
            "events" => Some(NeighborTraceOption::Events),
            "packets-all" => Some(NeighborTraceOption::PacketsAll),
            "packets-open" => Some(NeighborTraceOption::PacketsOpen),
            "packets-update" => Some(NeighborTraceOption::PacketsUpdate),
            "packets-notification" => {
                Some(NeighborTraceOption::PacketsNotification)
            }
            "packets-keepalive" => Some(NeighborTraceOption::PacketsKeepalive),
            "packets-refresh" => Some(NeighborTraceOption::PacketsRefresh),
            _ => None,
        }
    }
}
