//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::Arc;

use serde::{Deserialize, Serializer};
use yang3::data::{
    Data, DataFormat, DataParserFlags, DataPrinterFlags, DataTree,
    DataValidationFlags,
};

use crate::YANG_CTX;

// Serialize YANG data tree to JSON.
pub fn serialize<S>(dtree: &DataTree<'static>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let data = dtree
        .print_string(
            DataFormat::JSON,
            DataPrinterFlags::WITH_SIBLINGS
                | DataPrinterFlags::SHRINK
                | DataPrinterFlags::WD_TRIM,
        )
        .map_err(serde::ser::Error::custom)?
        .unwrap_or_default();
    s.serialize_str(&data)
}

// Deserialize YANG data tree from JSON.
pub fn deserialize<'de, D>(
    deserializer: D,
) -> Result<DataTree<'static>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let yang_ctx = YANG_CTX.get().unwrap();
    DataTree::parse_string(
        yang_ctx,
        &String::deserialize(deserializer)?,
        DataFormat::JSON,
        DataParserFlags::NO_VALIDATION,
        DataValidationFlags::NO_STATE,
    )
    .map_err(serde::de::Error::custom)
}

// DataTree wrapped in an Arc.
pub mod arc {
    use super::*;

    pub fn serialize<S>(
        dtree: &DataTree<'static>,
        s: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        super::serialize(dtree, s)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Arc<DataTree<'static>>, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        super::deserialize(deserializer).map(Arc::new)
    }
}
