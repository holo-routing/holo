//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::fmt::Write;

use holo_yang::{ToYang, ToYangBits, TryFromYang};

use crate::area::AreaType;
use crate::error::InterfaceCfgError;
use crate::gr::GrExitReason;
use crate::interface::{ism, InterfaceType};
use crate::lsdb::LsaLogReason;
use crate::neighbor::nsm;
use crate::packet::error::LsaValidationError;
use crate::packet::tlv::{
    AdjSidFlags, GrReason, PrefixSidFlags, RouterInfoCaps,
};
use crate::packet::PacketType;
use crate::route::PathType;
use crate::spf::SpfLogType;
use crate::{ospfv2, ospfv3, spf};

// ===== ToYang implementations =====

impl ToYang for PacketType {
    fn to_yang(&self) -> String {
        match self {
            PacketType::Hello => "hello".to_owned(),
            PacketType::DbDesc => "database-description".to_owned(),
            PacketType::LsRequest => "link-state-request".to_owned(),
            PacketType::LsUpdate => "link-state-update".to_owned(),
            PacketType::LsAck => "link-state-ack".to_owned(),
        }
    }
}

impl ToYang for ism::State {
    fn to_yang(&self) -> String {
        match self {
            ism::State::Down => "down".to_owned(),
            ism::State::Loopback => "loopback".to_owned(),
            ism::State::Waiting => "waiting".to_owned(),
            ism::State::PointToPoint => "point-to-point".to_owned(),
            ism::State::DrOther => "dr-other".to_owned(),
            ism::State::Backup => "bdr".to_owned(),
            ism::State::Dr => "dr".to_owned(),
        }
    }
}

impl ToYang for nsm::State {
    fn to_yang(&self) -> String {
        match self {
            nsm::State::Down => "down".to_owned(),
            nsm::State::Attempt => "attempt".to_owned(),
            nsm::State::Init => "init".to_owned(),
            nsm::State::TwoWay => "2-way".to_owned(),
            nsm::State::ExStart => "exstart".to_owned(),
            nsm::State::Exchange => "exchange".to_owned(),
            nsm::State::Loading => "loading".to_owned(),
            nsm::State::Full => "full".to_owned(),
        }
    }
}

impl ToYang for spf::fsm::State {
    fn to_yang(&self) -> String {
        match self {
            spf::fsm::State::Quiet => "quiet".to_owned(),
            spf::fsm::State::ShortWait => "short-wait".to_owned(),
            spf::fsm::State::LongWait => "long-wait".to_owned(),
        }
    }
}

impl ToYang for LsaLogReason {
    fn to_yang(&self) -> String {
        match self {
            LsaLogReason::Refresh => "lsa-refresh".to_owned(),
            LsaLogReason::ContentChange => "lsa-content-change".to_owned(),
            LsaLogReason::Purge => "lsa-purge".to_owned(),
        }
    }
}

impl ToYang for SpfLogType {
    fn to_yang(&self) -> String {
        match self {
            SpfLogType::Full => "full".to_owned(),
            SpfLogType::Intra => "intra".to_owned(),
            SpfLogType::Inter => "inter".to_owned(),
            SpfLogType::External => "external".to_owned(),
        }
    }
}

impl ToYang for PathType {
    fn to_yang(&self) -> String {
        match self {
            PathType::IntraArea => "intra-area".to_owned(),
            PathType::InterArea => "inter-area".to_owned(),
            PathType::Type1External => "external-1".to_owned(),
            PathType::Type2External => "external-2".to_owned(),
        }
    }
}

impl ToYang for InterfaceCfgError {
    fn to_yang(&self) -> String {
        match self {
            InterfaceCfgError::AfBitClear => "option-mismatch".to_owned(),
            InterfaceCfgError::AreaIdMismatch(..) => "area-mismatch".to_owned(),
            InterfaceCfgError::HelloMaskMismatch(..) => {
                "net-mask-mismatch".to_owned()
            }
            InterfaceCfgError::HelloIntervalMismatch(..) => {
                "hello-interval-mismatch".to_owned()
            }
            InterfaceCfgError::DeadIntervalMismatch(..) => {
                "dead-interval-mismatch".to_owned()
            }
            InterfaceCfgError::ExternalRoutingCapabilityMismatch(..) => {
                "option-mismatch".to_owned()
            }
            InterfaceCfgError::MtuMismatch(..) => "mtu-mismatch".to_owned(),
            InterfaceCfgError::DuplicateRouterId(..) => {
                "duplicate-router-id".to_owned()
            }
        }
    }
}

impl ToYang for LsaValidationError {
    fn to_yang(&self) -> String {
        match self {
            LsaValidationError::InvalidChecksum => {
                "invalid-checksum".to_owned()
            }
            LsaValidationError::InvalidLsaAge => "invalid-age".to_owned(),
            LsaValidationError::InvalidLsaSeqNo => "invalid-seq-num".to_owned(),
            LsaValidationError::Ospfv2RouterLsaIdMismatch => {
                "ospfv2-router-lsa-id-mismatch".to_owned()
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
            flags.push("ietf-ospf-sr:np-bit");
        }
        if self.contains(PrefixSidFlags::M) {
            flags.push("ietf-ospf-sr:m-bit");
        }
        if self.contains(PrefixSidFlags::E) {
            flags.push("ietf-ospf-sr:e-bit");
        }
        if self.contains(PrefixSidFlags::V) {
            flags.push("ietf-ospf-sr:v-bit");
        }
        if self.contains(PrefixSidFlags::L) {
            flags.push("ietf-ospf-sr:l-bit");
        }

        flags
    }
}

impl ToYangBits for AdjSidFlags {
    fn to_yang_bits(&self) -> Vec<&'static str> {
        let mut flags = vec![];

        if self.contains(AdjSidFlags::B) {
            flags.push("ietf-ospf-sr:b-bit");
        }
        if self.contains(AdjSidFlags::V) {
            flags.push("ietf-ospf-sr:vi-bit");
        }
        if self.contains(AdjSidFlags::L) {
            flags.push("ietf-ospf-sr:lo-bit");
        }
        if self.contains(AdjSidFlags::G) {
            flags.push("ietf-ospf-sr:g-bit");
        }
        if self.contains(AdjSidFlags::P) {
            flags.push("ietf-ospf-sr:p-bit");
        }

        flags
    }
}

impl ToYang for GrReason {
    fn to_yang(&self) -> String {
        match self {
            GrReason::Unknown => "unknown".to_owned(),
            GrReason::SoftwareRestart => "software-restart".to_owned(),
            GrReason::SoftwareUpgrade => "software-upgrade".to_owned(),
            GrReason::ControlProcessorSwitchover => {
                "control-processor-switchover".to_owned()
            }
        }
    }
}

impl ToYang for GrExitReason {
    fn to_yang(&self) -> String {
        match self {
            GrExitReason::Completed => "completed".to_owned(),
            GrExitReason::TimedOut => "timed-out".to_owned(),
            GrExitReason::TopologyChanged => "topology-changed".to_owned(),
        }
    }
}

impl ToYang for ospfv2::packet::lsa::LsaAsExternalFlags {
    fn to_yang(&self) -> String {
        use ospfv2::packet::lsa::LsaAsExternalFlags;

        let mut bits = String::new();
        if self.contains(LsaAsExternalFlags::E) {
            write!(bits, "E").unwrap();
        }

        bits
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
    fn to_yang(&self) -> String {
        use ospfv2::packet::lsa::LsaTypeCode;

        match self.type_code() {
            Some(LsaTypeCode::Router) => "ospfv2-router-lsa".to_owned(),
            Some(LsaTypeCode::Network) => "ospfv2-network-lsa".to_owned(),
            Some(LsaTypeCode::SummaryNetwork) => {
                "ospfv2-network-summary-lsa".to_owned()
            }
            Some(LsaTypeCode::SummaryRouter) => {
                "ospfv2-asbr-summary-lsa".to_owned()
            }
            Some(LsaTypeCode::AsExternal) => {
                "ospfv2-as-external-lsa".to_owned()
            }
            Some(LsaTypeCode::OpaqueLink) => {
                "ospfv2-link-scope-opaque-lsa".to_owned()
            }
            Some(LsaTypeCode::OpaqueArea) => {
                "ospfv2-area-scope-opaque-lsa".to_owned()
            }
            Some(LsaTypeCode::OpaqueAs) => {
                "ospfv2-as-scope-opaque-lsa".to_owned()
            }
            None => "ospfv2-unknown-lsa-type".to_owned(),
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
    fn to_yang(&self) -> String {
        use ospfv2::packet::lsa::LsaRouterLinkType;

        match self {
            LsaRouterLinkType::PointToPoint => "point-to-point-link".to_owned(),
            LsaRouterLinkType::TransitNetwork => {
                "transit-network-link".to_owned()
            }
            LsaRouterLinkType::StubNetwork => "stub-network-link".to_owned(),
            LsaRouterLinkType::VirtualLink => "virtual-link".to_owned(),
        }
    }
}

impl ToYang for ospfv2::packet::lsa_opaque::ExtPrefixRouteType {
    fn to_yang(&self) -> String {
        use ospfv2::packet::lsa_opaque::ExtPrefixRouteType;

        match self {
            ExtPrefixRouteType::Unspecified => "unspecified".to_owned(),
            ExtPrefixRouteType::IntraArea => "intra-area".to_owned(),
            ExtPrefixRouteType::InterArea => "inter-area".to_owned(),
            ExtPrefixRouteType::AsExternal => "external".to_owned(),
            ExtPrefixRouteType::NssaExternal => "nssa".to_owned(),
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
    fn to_yang(&self) -> String {
        use ospfv3::packet::lsa::LsaFunctionCode;

        match self.function_code() {
            Some(LsaFunctionCode::Router) => "ospfv3-router-lsa".to_owned(),
            Some(LsaFunctionCode::Network) => "ospfv3-network-lsa".to_owned(),
            Some(LsaFunctionCode::InterAreaPrefix) => {
                "ospfv3-inter-area-prefix-lsa".to_owned()
            }
            Some(LsaFunctionCode::InterAreaRouter) => {
                "ospfv3-inter-area-router-lsa".to_owned()
            }
            Some(LsaFunctionCode::AsExternal) => {
                "ospfv3-external-lsa-type".to_owned()
            }
            Some(LsaFunctionCode::Link) => "ospfv3-link-lsa".to_owned(),
            Some(LsaFunctionCode::IntraAreaPrefix) => {
                "ospfv3-intra-area-prefix-lsa".to_owned()
            }
            Some(LsaFunctionCode::RouterInfo) => {
                "ospfv3-router-information-lsa".to_owned()
            }
            Some(LsaFunctionCode::Grace) => {
                "holo-ospf:ospfv3-grace-lsa".to_owned()
            }
            Some(LsaFunctionCode::ExtRouter) => {
                "ietf-ospfv3-extended-lsa:ospfv3-e-router-lsa".to_owned()
            }
            Some(LsaFunctionCode::ExtNetwork) => {
                "ietf-ospfv3-extended-lsa:ospfv3-e-network-lsa".to_owned()
            }
            Some(LsaFunctionCode::ExtInterAreaPrefix) => {
                "ietf-ospfv3-extended-lsa:ospfv3-e-inter-area-prefix-lsa"
                    .to_owned()
            }
            Some(LsaFunctionCode::ExtInterAreaRouter) => {
                "ietf-ospfv3-extended-lsa:ospfv3-e-inter-area-router-lsa"
                    .to_owned()
            }
            Some(LsaFunctionCode::ExtAsExternal) => {
                "ietf-ospfv3-extended-lsa:ospfv3-e-external-lsa-type".to_owned()
            }
            Some(LsaFunctionCode::ExtLink) => {
                "ietf-ospfv3-extended-lsa:ospfv3-e-link-lsa".to_owned()
            }
            Some(LsaFunctionCode::ExtIntraAreaPrefix) => {
                "ietf-ospfv3-extended-lsa:ospfv3-e-intra-area-prefix-lsa"
                    .to_owned()
            }
            None => "ospfv3-unknown-lsa-type".to_owned(),
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
    fn to_yang(&self) -> String {
        use ospfv3::packet::lsa::LsaRouterLinkType;

        match self {
            LsaRouterLinkType::PointToPoint => "point-to-point-link".to_owned(),
            LsaRouterLinkType::TransitNetwork => {
                "transit-network-link".to_owned()
            }
            LsaRouterLinkType::VirtualLink => "virtual-link".to_owned(),
        }
    }
}

impl ToYang for ospfv3::packet::lsa::LsaAsExternalFlags {
    fn to_yang(&self) -> String {
        use ospfv3::packet::lsa::LsaAsExternalFlags;

        let mut bits = String::new();
        if self.contains(LsaAsExternalFlags::E) {
            write!(bits, "E").unwrap();
        }
        if self.contains(LsaAsExternalFlags::F) {
            write!(bits, "F").unwrap();
        }
        if self.contains(LsaAsExternalFlags::T) {
            write!(bits, "T").unwrap();
        }

        bits
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
