//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::fmt::Write;

use holo_yang::{ToYang, ToYangBits, TryFromYang};

use crate::area::AreaType;
use crate::error::InterfaceCfgError;
use crate::gr::GrExitReason;
use crate::interface::{InterfaceType, ism};
use crate::lsdb::LsaLogReason;
use crate::neighbor::nsm;
use crate::packet::PacketType;
use crate::packet::error::LsaValidationError;
use crate::packet::tlv::{
    AdjSidFlags, GrReason, PrefixSidFlags, RouterInfoCaps,
};
use crate::spf::SpfLogType;
use crate::{ospfv2, ospfv3, spf};

// ===== ToYang implementations =====

impl ToYang for PacketType {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            PacketType::Hello => "hello".into(),
            PacketType::DbDesc => "database-description".into(),
            PacketType::LsRequest => "link-state-request".into(),
            PacketType::LsUpdate => "link-state-update".into(),
            PacketType::LsAck => "link-state-ack".into(),
        }
    }
}

impl ToYang for ism::State {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            ism::State::Down => "down".into(),
            ism::State::Loopback => "loopback".into(),
            ism::State::Waiting => "waiting".into(),
            ism::State::PointToPoint => "point-to-point".into(),
            ism::State::DrOther => "dr-other".into(),
            ism::State::Backup => "bdr".into(),
            ism::State::Dr => "dr".into(),
        }
    }
}

impl ToYang for nsm::State {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            nsm::State::Down => "down".into(),
            nsm::State::Attempt => "attempt".into(),
            nsm::State::Init => "init".into(),
            nsm::State::TwoWay => "2-way".into(),
            nsm::State::ExStart => "exstart".into(),
            nsm::State::Exchange => "exchange".into(),
            nsm::State::Loading => "loading".into(),
            nsm::State::Full => "full".into(),
        }
    }
}

impl ToYang for spf::fsm::State {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            spf::fsm::State::Quiet => "quiet".into(),
            spf::fsm::State::ShortWait => "short-wait".into(),
            spf::fsm::State::LongWait => "long-wait".into(),
        }
    }
}

impl ToYang for LsaLogReason {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            LsaLogReason::Refresh => "lsa-refresh".into(),
            LsaLogReason::ContentChange => "lsa-content-change".into(),
            LsaLogReason::Purge => "lsa-purge".into(),
        }
    }
}

impl ToYang for SpfLogType {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            SpfLogType::Full => "full".into(),
            SpfLogType::Intra => "intra".into(),
            SpfLogType::Inter => "inter".into(),
            SpfLogType::External => "external".into(),
        }
    }
}

impl ToYang for InterfaceCfgError {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            InterfaceCfgError::AfBitClear => "option-mismatch".into(),
            InterfaceCfgError::AreaIdMismatch(..) => "area-mismatch".into(),
            InterfaceCfgError::HelloMaskMismatch(..) => {
                "net-mask-mismatch".into()
            }
            InterfaceCfgError::HelloIntervalMismatch(..) => {
                "hello-interval-mismatch".into()
            }
            InterfaceCfgError::DeadIntervalMismatch(..) => {
                "dead-interval-mismatch".into()
            }
            InterfaceCfgError::ExternalRoutingCapabilityMismatch(..) => {
                "option-mismatch".into()
            }
            InterfaceCfgError::MtuMismatch(..) => "mtu-mismatch".into(),
            InterfaceCfgError::DuplicateRouterId(..) => {
                "duplicate-router-id".into()
            }
        }
    }
}

impl ToYang for LsaValidationError {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            LsaValidationError::InvalidChecksum => "invalid-checksum".into(),
            LsaValidationError::InvalidLsaAge => "invalid-age".into(),
            LsaValidationError::InvalidLsaSeqNo => "invalid-seq-num".into(),
            LsaValidationError::Ospfv2RouterLsaIdMismatch => {
                "ospfv2-router-lsa-id-mismatch".into()
            }
        }
    }
}

impl ToYangBits for RouterInfoCaps {
    fn to_yang_bits(&self) -> Vec<&'static str> {
        let mut options = vec![];
        if self.contains(RouterInfoCaps::GR) {
            options.push("graceful-restart");
        }
        if self.contains(RouterInfoCaps::GR_HELPER) {
            options.push("graceful-restart-helper");
        }
        if self.contains(RouterInfoCaps::STUB_ROUTER) {
            options.push("stub-router");
        }
        if self.contains(RouterInfoCaps::TE) {
            options.push("traffic-engineering");
        }
        if self.contains(RouterInfoCaps::P2P_LAN) {
            options.push("p2p-over-lan");
        }
        if self.contains(RouterInfoCaps::EXPERIMENTAL_TE) {
            options.push("experimental-te");
        }

        options
    }
}

impl ToYangBits for PrefixSidFlags {
    fn to_yang_bits(&self) -> Vec<&'static str> {
        let mut flags = vec![];

        if self.contains(PrefixSidFlags::NP) {
            flags.push("ietf-ospf-sr-mpls:np-flag");
        }
        if self.contains(PrefixSidFlags::M) {
            flags.push("ietf-ospf-sr-mpls:m-flag");
        }
        if self.contains(PrefixSidFlags::E) {
            flags.push("ietf-ospf-sr-mpls:e-flag");
        }
        if self.contains(PrefixSidFlags::V) {
            flags.push("ietf-ospf-sr-mpls:v-flag");
        }
        if self.contains(PrefixSidFlags::L) {
            flags.push("ietf-ospf-sr-mpls:l-flag");
        }

        flags
    }
}

impl ToYangBits for AdjSidFlags {
    fn to_yang_bits(&self) -> Vec<&'static str> {
        let mut flags = vec![];

        if self.contains(AdjSidFlags::B) {
            flags.push("ietf-ospf-sr-mpls:b-flag");
        }
        if self.contains(AdjSidFlags::V) {
            flags.push("ietf-ospf-sr-mpls:vi-flag");
        }
        if self.contains(AdjSidFlags::L) {
            flags.push("ietf-ospf-sr-mpls:lo-flag");
        }
        if self.contains(AdjSidFlags::G) {
            flags.push("ietf-ospf-sr-mpls:g-flag");
        }
        if self.contains(AdjSidFlags::P) {
            flags.push("ietf-ospf-sr-mpls:p-flag");
        }

        flags
    }
}

impl ToYang for GrReason {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            GrReason::Unknown => "unknown".into(),
            GrReason::SoftwareRestart => "software-restart".into(),
            GrReason::SoftwareUpgrade => "software-upgrade".into(),
            GrReason::ControlProcessorSwitchover => {
                "control-processor-switchover".into()
            }
        }
    }
}

impl ToYang for GrExitReason {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            GrExitReason::Completed => "completed".into(),
            GrExitReason::TimedOut => "timed-out".into(),
            GrExitReason::TopologyChanged => "topology-changed".into(),
        }
    }
}

impl ToYang for ospfv2::packet::lsa::LsaAsExternalFlags {
    fn to_yang(&self) -> Cow<'static, str> {
        use ospfv2::packet::lsa::LsaAsExternalFlags;

        let mut bits = String::new();
        if self.contains(LsaAsExternalFlags::E) {
            write!(bits, "E").unwrap();
        }

        bits.into()
    }
}

impl ToYangBits for ospfv2::packet::Options {
    fn to_yang_bits(&self) -> Vec<&'static str> {
        use ospfv2::packet::Options;

        let mut options = vec![];
        if self.contains(Options::E) {
            options.push("v2-e-bit");
        }
        if self.contains(Options::MC) {
            options.push("mc-bit");
        }
        if self.contains(Options::NP) {
            options.push("v2-p-bit");
        }
        if self.contains(Options::DC) {
            options.push("v2-dc-bit");
        }
        if self.contains(Options::O) {
            options.push("o-bit");
        }

        options
    }
}

impl ToYang for ospfv2::packet::lsa::LsaType {
    fn to_yang(&self) -> Cow<'static, str> {
        use ospfv2::packet::lsa::LsaTypeCode;

        match self.type_code() {
            Some(LsaTypeCode::Router) => "ospfv2-router-lsa".into(),
            Some(LsaTypeCode::Network) => "ospfv2-network-lsa".into(),
            Some(LsaTypeCode::SummaryNetwork) => {
                "ospfv2-network-summary-lsa".into()
            }
            Some(LsaTypeCode::SummaryRouter) => {
                "ospfv2-asbr-summary-lsa".into()
            }
            Some(LsaTypeCode::AsExternal) => "ospfv2-as-external-lsa".into(),
            Some(LsaTypeCode::OpaqueLink) => {
                "ospfv2-link-scope-opaque-lsa".into()
            }
            Some(LsaTypeCode::OpaqueArea) => {
                "ospfv2-area-scope-opaque-lsa".into()
            }
            Some(LsaTypeCode::OpaqueAs) => "ospfv2-as-scope-opaque-lsa".into(),
            None => "ospfv2-unknown-lsa-type".into(),
        }
    }
}

impl ToYangBits for ospfv2::packet::lsa::LsaRouterFlags {
    fn to_yang_bits(&self) -> Vec<&'static str> {
        use ospfv2::packet::lsa::LsaRouterFlags;

        let mut flags = vec![];
        if self.contains(LsaRouterFlags::B) {
            flags.push("abr-bit");
        }
        if self.contains(LsaRouterFlags::E) {
            flags.push("asbr-bit");
        }
        if self.contains(LsaRouterFlags::V) {
            flags.push("vlink-end-bit");
        }
        if self.contains(LsaRouterFlags::NT) {
            flags.push("nssa-bit");
        }

        flags
    }
}

impl ToYang for ospfv2::packet::lsa::LsaRouterLinkType {
    fn to_yang(&self) -> Cow<'static, str> {
        use ospfv2::packet::lsa::LsaRouterLinkType;

        match self {
            LsaRouterLinkType::PointToPoint => "point-to-point-link".into(),
            LsaRouterLinkType::TransitNetwork => "transit-network-link".into(),
            LsaRouterLinkType::StubNetwork => "stub-network-link".into(),
            LsaRouterLinkType::VirtualLink => "virtual-link".into(),
        }
    }
}

impl ToYang for ospfv2::packet::lsa_opaque::ExtPrefixRouteType {
    fn to_yang(&self) -> Cow<'static, str> {
        use ospfv2::packet::lsa_opaque::ExtPrefixRouteType;

        match self {
            ExtPrefixRouteType::Unspecified => "unspecified".into(),
            ExtPrefixRouteType::IntraArea => "intra-area".into(),
            ExtPrefixRouteType::InterArea => "inter-area".into(),
            ExtPrefixRouteType::AsExternal => "external".into(),
            ExtPrefixRouteType::NssaExternal => "nssa".into(),
        }
    }
}

impl ToYangBits for ospfv2::packet::lsa_opaque::LsaExtPrefixFlags {
    fn to_yang_bits(&self) -> Vec<&'static str> {
        use ospfv2::packet::lsa_opaque::LsaExtPrefixFlags;

        let mut flags = vec![];
        if self.contains(LsaExtPrefixFlags::A) {
            flags.push("a-flag");
        }
        if self.contains(LsaExtPrefixFlags::N) {
            flags.push("node-flag");
        }

        flags
    }
}

impl ToYang for ospfv3::packet::lsa::LsaType {
    fn to_yang(&self) -> Cow<'static, str> {
        use ospfv3::packet::lsa::LsaFunctionCode;

        match self.function_code() {
            Some(LsaFunctionCode::Router) => "ospfv3-router-lsa".into(),
            Some(LsaFunctionCode::Network) => "ospfv3-network-lsa".into(),
            Some(LsaFunctionCode::InterAreaPrefix) => {
                "ospfv3-inter-area-prefix-lsa".into()
            }
            Some(LsaFunctionCode::InterAreaRouter) => {
                "ospfv3-inter-area-router-lsa".into()
            }
            Some(LsaFunctionCode::AsExternal) => {
                "ospfv3-external-lsa-type".into()
            }
            Some(LsaFunctionCode::Link) => "ospfv3-link-lsa".into(),
            Some(LsaFunctionCode::IntraAreaPrefix) => {
                "ospfv3-intra-area-prefix-lsa".into()
            }
            Some(LsaFunctionCode::RouterInfo) => {
                "ospfv3-router-information-lsa".into()
            }
            Some(LsaFunctionCode::Grace) => "holo-ospf:ospfv3-grace-lsa".into(),
            Some(LsaFunctionCode::ExtRouter) => {
                "ietf-ospfv3-extended-lsa:ospfv3-e-router-lsa".into()
            }
            Some(LsaFunctionCode::ExtNetwork) => {
                "ietf-ospfv3-extended-lsa:ospfv3-e-network-lsa".into()
            }
            Some(LsaFunctionCode::ExtInterAreaPrefix) => {
                "ietf-ospfv3-extended-lsa:ospfv3-e-inter-area-prefix-lsa".into()
            }
            Some(LsaFunctionCode::ExtInterAreaRouter) => {
                "ietf-ospfv3-extended-lsa:ospfv3-e-inter-area-router-lsa".into()
            }
            Some(LsaFunctionCode::ExtAsExternal) => {
                "ietf-ospfv3-extended-lsa:ospfv3-e-external-lsa-type".into()
            }
            Some(LsaFunctionCode::ExtLink) => {
                "ietf-ospfv3-extended-lsa:ospfv3-e-link-lsa".into()
            }
            Some(LsaFunctionCode::ExtIntraAreaPrefix) => {
                "ietf-ospfv3-extended-lsa:ospfv3-e-intra-area-prefix-lsa".into()
            }
            None => "ospfv3-unknown-lsa-type".into(),
        }
    }
}

impl ToYangBits for ospfv3::packet::lsa::LsaRouterFlags {
    fn to_yang_bits(&self) -> Vec<&'static str> {
        use ospfv3::packet::lsa::LsaRouterFlags;

        let mut flags = vec![];
        if self.contains(LsaRouterFlags::B) {
            flags.push("ietf-ospf:abr-bit");
        }
        if self.contains(LsaRouterFlags::E) {
            flags.push("ietf-ospf:asbr-bit");
        }
        if self.contains(LsaRouterFlags::V) {
            flags.push("ietf-ospf:vlink-end-bit");
        }
        if self.contains(LsaRouterFlags::NT) {
            flags.push("ietf-ospf:nssa-bit");
        }

        flags
    }
}

impl ToYang for ospfv3::packet::lsa::LsaRouterLinkType {
    fn to_yang(&self) -> Cow<'static, str> {
        use ospfv3::packet::lsa::LsaRouterLinkType;

        match self {
            LsaRouterLinkType::PointToPoint => "point-to-point-link".into(),
            LsaRouterLinkType::TransitNetwork => "transit-network-link".into(),
            LsaRouterLinkType::VirtualLink => "virtual-link".into(),
        }
    }
}

impl ToYang for ospfv3::packet::lsa::LsaAsExternalFlags {
    fn to_yang(&self) -> Cow<'static, str> {
        use ospfv3::packet::lsa::LsaAsExternalFlags;

        let mut bits = Vec::new();
        if self.contains(LsaAsExternalFlags::E) {
            bits.push("E");
        }
        if self.contains(LsaAsExternalFlags::F) {
            bits.push("F");
        }
        if self.contains(LsaAsExternalFlags::T) {
            bits.push("T");
        }

        bits.join(" ").into()
    }
}

impl ToYangBits for ospfv3::packet::lsa::LsaAsExternalFlags {
    fn to_yang_bits(&self) -> Vec<&'static str> {
        use ospfv3::packet::lsa::LsaAsExternalFlags;

        let mut options = vec![];
        if self.contains(LsaAsExternalFlags::E) {
            options.push("ietf-ospfv3-extended-lsa:e-bit");
        }

        options
    }
}

impl ToYangBits for ospfv3::packet::Options {
    fn to_yang_bits(&self) -> Vec<&'static str> {
        use ospfv3::packet::Options;

        let mut options = vec![];
        if self.contains(Options::V6) {
            options.push("ietf-ospf:v6-bit");
        }
        if self.contains(Options::E) {
            options.push("ietf-ospf:e-bit");
        }
        if self.contains(Options::N) {
            options.push("ietf-ospf:n-bit");
        }
        if self.contains(Options::R) {
            options.push("ietf-ospf:r-bit");
        }
        if self.contains(Options::DC) {
            options.push("ietf-ospf:dc-bit");
        }
        if self.contains(Options::AF) {
            options.push("ietf-ospf:af-bit");
        }

        options
    }
}

impl ToYangBits for ospfv3::packet::lsa::PrefixOptions {
    fn to_yang_bits(&self) -> Vec<&'static str> {
        use ospfv3::packet::lsa::PrefixOptions;

        let mut options = vec![];
        if self.contains(PrefixOptions::NU) {
            options.push("nu-bit");
        }
        if self.contains(PrefixOptions::LA) {
            options.push("la-bit");
        }
        if self.contains(PrefixOptions::P) {
            options.push("p-bit");
        }
        if self.contains(PrefixOptions::DN) {
            options.push("dn-bit");
        }

        options
    }
}

// ===== TryFromYang implementations =====

impl TryFromYang for AreaType {
    fn try_from_yang(value: &str) -> Option<AreaType> {
        match value {
            "ietf-ospf:normal-area" => Some(AreaType::Normal),
            "ietf-ospf:stub-area" => Some(AreaType::Stub),
            "ietf-ospf:nssa-area" => Some(AreaType::Nssa),
            _ => None,
        }
    }
}

impl TryFromYang for InterfaceType {
    fn try_from_yang(value: &str) -> Option<InterfaceType> {
        match value {
            "broadcast" => Some(InterfaceType::Broadcast),
            "non-broadcast" => Some(InterfaceType::NonBroadcast),
            "point-to-multipoint" => Some(InterfaceType::PointToMultipoint),
            "point-to-point" => Some(InterfaceType::PointToPoint),
            _ => None,
        }
    }
}
