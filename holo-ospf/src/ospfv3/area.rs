//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use crate::area::{Area, AreaType, AreaVersion, OptionsLocation};
use crate::ospfv3::packet::Options;
use crate::version::Ospfv3;

#[derive(Debug, Default)]
pub struct AreaState {
    // Next inter-area LSA IDs.
    pub next_type3_lsa_id: u32,
    pub next_type4_lsa_id: u32,
}

// ===== impl Ospfv3 =====

impl AreaVersion<Self> for Ospfv3 {
    type State = AreaState;

    fn area_options(area: &Area<Self>, _location: OptionsLocation) -> Options {
        let mut options = Options::R | Options::V6 | Options::AF;

        if area.config.area_type == AreaType::Normal {
            options.insert(Options::E);
        }

        options
    }
}
