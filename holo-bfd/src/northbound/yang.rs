//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use holo_yang::ToYang;

use crate::packet::DiagnosticCode;

// ===== ToYang implementations =====

impl ToYang for DiagnosticCode {
    fn to_yang(&self) -> String {
        match self {
            DiagnosticCode::Nothing => "none".to_owned(),
            DiagnosticCode::TimeExpired => "control-expiry".to_owned(),
            DiagnosticCode::EchoFailed => "echo-failed".to_owned(),
            DiagnosticCode::NbrDown => "neighbor-down".to_owned(),
            DiagnosticCode::FwdPlaneReset => "forwarding-reset".to_owned(),
            DiagnosticCode::PathDown => "path-down".to_owned(),
            DiagnosticCode::ConcatPathDown => {
                "concatenated-path-down".to_owned()
            }
            DiagnosticCode::AdminDown => "admin-down".to_owned(),
            DiagnosticCode::RevConcatPathDown => {
                "reverse-concatenated-path-down".to_owned()
            }
            DiagnosticCode::MisConnectivity => {
                "mis-connectivity-defect".to_owned()
            }
        }
    }
}
