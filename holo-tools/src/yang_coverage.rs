//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::collections::BTreeMap;

use clap::{App, Arg};
use holo_yang as yang;
use num_traits::cast::AsPrimitive;
use yang2::context::Context;
use yang2::schema::{SchemaNodeKind, SchemaOutputFormat, SchemaPrinterFlags};

#[derive(Debug, Default)]
struct NodeCounters<T> {
    config: T,
    state: T,
    rpcs: T,
    notifs: T,
    total: T,
}

#[derive(Debug, Default)]
struct Coverage(f64);

// ===== impl Coverage =====

impl Coverage {
    fn new<T>(dividend: T, divisor: T) -> Coverage
    where
        T: AsPrimitive<f64> + PartialOrd,
    {
        // Assert coverage isn't greater than 100% :)
        assert!(dividend <= divisor);

        Coverage(dividend.as_() / divisor.as_())
    }
}

impl std::fmt::Display for Coverage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_nan() {
            write!(f, "-")
        } else {
            // Show coverage as a percentage with two decimal places.
            write!(f, "{:.*}%", 2, self.0 * 100_f64)
        }
    }
}

// ===== helper functions =====

fn load_deviation_modules(yang_ctx: &mut Context, matches: &clap::ArgMatches) {
    if let Some(modules) = matches.values_of("module") {
        for module_name in modules.rev() {
            yang::load_deviations(yang_ctx, module_name);
        }
    }
}

fn count_nodes(yang_ctx: &Context) -> BTreeMap<String, NodeCounters<usize>> {
    let mut counters: BTreeMap<String, NodeCounters<usize>> = BTreeMap::new();

    for snode in yang_ctx
        .traverse()
        // Ignore deprecated and obsolete nodes.
        .filter(|snode| snode.is_status_current())
        // Ignore schema-only (choice/case) nodes.
        .filter(|snode| !snode.is_schema_only())
        // Ignore internal module.
        .filter(|snode| snode.module().name() != "ietf-yang-schema-mount")
    {
        let module = snode.module();

        // Get full module name.
        let mut module_name = module.name().to_owned();
        if let Some(revision) = module.revision() {
            module_name.push('@');
            module_name.push_str(revision);
        }

        // Count number of nodes of each type and the grand total.
        let counter = counters.entry(module_name).or_default();
        if snode.kind() == SchemaNodeKind::Rpc
            || snode.kind() == SchemaNodeKind::Action
            || snode.is_within_input()
            || snode.is_within_output()
        {
            counter.rpcs += 1;
        } else if snode.kind() == SchemaNodeKind::Notification
            || snode.is_within_notification()
        {
            counter.notifs += 1;
        } else if snode.is_config() {
            counter.config += 1;
        } else {
            counter.state += 1;
        }
        counter.total += 1;
    }

    counters
}

fn calculate_coverage(mut yang_ctx: Context, matches: &clap::ArgMatches) {
    // Calculate node totals before applying deviations.
    let pre_dev = count_nodes(&yang_ctx);

    // Load YANG deviation modules.
    load_deviation_modules(&mut yang_ctx, matches);

    // Calculate node totals after applying deviations.
    let post_dev = count_nodes(&yang_ctx);

    // Calculate coverage and generate markdown output.
    println!(
        "\
        \n| Module | Configuration | State | RPCs | Notifications | Total |\
        \n| -- | -- | -- | -- | -- | -- |"
    );

    for ((module_name, pre_dev), (_, post_dev)) in
        pre_dev.iter().zip(post_dev.iter())
    {
        let coverage = NodeCounters::<Coverage> {
            config: Coverage::new(post_dev.config, pre_dev.config),
            state: Coverage::new(post_dev.state, pre_dev.state),
            rpcs: Coverage::new(post_dev.rpcs, pre_dev.rpcs),
            notifs: Coverage::new(post_dev.notifs, pre_dev.notifs),
            total: Coverage::new(post_dev.total, pre_dev.total),
        };
        let coverage_link =
            format!("holo-yang/modules/coverage/{}.coverage.md", module_name);
        println!(
            "| {} | {} | {} | {} | {} | [{}]({}) |",
            module_name,
            coverage.config,
            coverage.state,
            coverage.rpcs,
            coverage.notifs,
            coverage.total,
            coverage_link,
        );
    }
}

fn generate_tree_diff(
    mut yang_ctx: Context,
    matches: &clap::ArgMatches,
    module_name: &str,
) {
    // TODO: check if this is still necessary.
    //yang_ctx.set_options(ContextFlags::PRIV_PARSED).unwrap();

    // Print schema tree before applying deviations.
    let module = yang_ctx
        .get_module_latest(module_name)
        .expect("Module not found");
    let before = module
        .print_string(SchemaOutputFormat::TREE, SchemaPrinterFlags::empty())
        .expect("Failed to print module");

    // Load YANG deviation modules.
    load_deviation_modules(&mut yang_ctx, matches);

    // Print schema tree after applying deviations.
    let module = yang_ctx
        .get_module_latest(module_name)
        .expect("Module not found");
    let after = module
        .print_string(SchemaOutputFormat::TREE, SchemaPrinterFlags::empty())
        .expect("Failed to print module");

    // Generate schema tree diff.
    let diff = similar::TextDiff::from_lines(&before, &after);
    for change in diff.iter_all_changes() {
        let sign = match change.tag() {
            similar::ChangeTag::Delete => "-",
            similar::ChangeTag::Insert => "+",
            similar::ChangeTag::Equal => " ",
        };
        print!("{}{}", sign, change);
    }
}

// ===== main =====

fn main() {
    // Parse command-line parameters.
    let matches = App::new("YANG coverage calculator")
        .arg(
            Arg::with_name("diff")
                .long("diff")
                .value_name("MODULE_NAME")
                .help("Generate a YANG tree diff"),
        )
        .arg(
            Arg::with_name("module")
                .short("m")
                .long("module")
                .value_name("MODULE_NAME")
                .help("YANG module name")
                .multiple(true),
        )
        .get_matches();

    // Initialize YANG context.
    let mut yang_ctx = yang::new_context();

    // Load YANG modules.
    if let Some(modules) = matches.values_of("module") {
        for module_name in modules {
            yang::load_module(&mut yang_ctx, module_name);
        }
    }

    if let Some(module_name) = matches.value_of("diff") {
        generate_tree_diff(yang_ctx, &matches, module_name);
    } else {
        calculate_coverage(yang_ctx, &matches);
    }
}
