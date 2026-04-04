//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::fmt::Write;

// Helper for writing indented code. Applies a base indentation level
// and allows adding extra indentation per line.
pub(crate) struct CodeWriter {
    pub(crate) output: String,
    pub(crate) level: usize,
}

// ===== impl CodeWriter =====

impl CodeWriter {
    pub(crate) fn new(output: String, level: usize) -> Self {
        CodeWriter { output, level }
    }

    pub(crate) fn line(
        &mut self,
        depth: usize,
        args: std::fmt::Arguments<'_>,
    ) -> std::fmt::Result {
        let indent = " ".repeat((self.level + depth) * 2);
        writeln!(self.output, "{indent}{args}")
    }
}

// Writes an indented line. The depth is relative to the writer's base level.
macro_rules! emit {
    ($w:expr, $n:literal, $($arg:tt)*) => {
        $w.line($n, format_args!($($arg)*))
    };
}
pub(crate) use emit;
