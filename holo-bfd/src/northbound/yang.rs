//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;

use holo_yang::ToYang;

use crate::packet::DiagnosticCode;

// ===== ToYang implementations =====

impl ToYang for DiagnosticCode {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            DiagnosticCode::Nothing => "none".into(),
            DiagnosticCode::TimeExpired => "control-expiry".into(),
            DiagnosticCode::EchoFailed => "echo-failed".into(),
            DiagnosticCode::NbrDown => "neighbor-down".into(),
            DiagnosticCode::FwdPlaneReset => "forwarding-reset".into(),
            DiagnosticCode::PathDown => "path-down".into(),
            DiagnosticCode::ConcatPathDown => "concatenated-path-down".into(),
            DiagnosticCode::AdminDown => "admin-down".into(),
            DiagnosticCode::RevConcatPathDown => "reverse-concatenated-path-down".into(),
            DiagnosticCode::MisConnectivity => "mis-connectivity-defect".into(),
        }
    }
}
