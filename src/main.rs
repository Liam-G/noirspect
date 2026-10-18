//! Command-line interface. Flags, report formats and exit codes follow
//! jwt-audit and oidc-audit: 0 clean, 2 findings, 1 usage or operational error.

use clap::{Parser, Subcommand};
use noirspect::driver::{EntryMode, Worker};
use noirspect::rules::{RULES, Severity, rule};
use noirspect::{AnalysisOptions, analyze, report};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "noirspect",
    version,
    about = "Find under-constrained values in Noir circuits."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze a Nargo package or workspace
    Lint(LintArgs),
    /// List every rule with its severity and default state
    Rules,
    /// Print the optimized SSA the rules run on (for debugging rules)
    Ssa(TargetArgs),
    /// Internal: lower one package's entry points for a parent process
    #[command(name = "__lower", hide = true)]
    Lower(LowerArgs),
}

#[derive(clap::Args)]
struct LowerArgs {
    #[arg(long)]
    program_dir: PathBuf,
    #[arg(long)]
    package: String,
    #[arg(long, value_enum)]
    entry: EntryMode,
    #[arg(long)]
    function: Option<String>,
    #[arg(long)]
    start: usize,
}

#[derive(clap::Args)]
struct TargetArgs {
    /// Directory containing Nargo.toml
    #[arg(long, default_value = ".")]
    program_dir: PathBuf,
    /// Analyze only this package of the workspace
    #[arg(long, conflicts_with = "workspace")]
    package: Option<String>,
    /// Analyze every package of the workspace
    #[arg(long)]
    workspace: bool,
    /// Which functions to start the analysis from
    #[arg(long, value_enum)]
    entry: Option<EntryMode>,
    /// Analyze only this function (name or path suffix)
    #[arg(long)]
    function: Option<String>,
}

#[derive(clap::Args)]
struct LintArgs {
    #[command(flatten)]
    target: TargetArgs,
    /// TOML policy configuration with a [noirspect] table
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, value_parser = ["text", "json", "sarif"])]
    format: Option<String>,
    /// Write the report instead of stdout
    #[arg(long)]
    output: Option<PathBuf>,
    /// Only report findings at or above this severity
    #[arg(long, value_parser = ["info", "low", "medium", "high"])]
    min_severity: Option<String>,
    /// Turn a rule off (repeatable)
    #[arg(long, value_name = "RULE_ID")]
    disable: Vec<String>,
    /// Turn on a rule that is off by default (repeatable)
    #[arg(long, value_name = "RULE_ID")]
    enable: Vec<String>,
    /// Skip an entry point whose compilation takes longer than this; 0 waits forever
    #[arg(long, value_name = "SECONDS")]
    entry_timeout: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct Policy {
    format: Option<String>,
    min_severity: Option<String>,
    #[serde(default)]
    disable: Vec<String>,
    #[serde(default)]
    enable: Vec<String>,
    entry: Option<EntryMode>,
    entry_timeout: Option<u64>,
}

const DEFAULT_ENTRY_TIMEOUT_SECONDS: u64 = 120;

#[derive(Deserialize)]
struct PolicyFile {
    noirspect: Policy,
}

fn load_policy(path: Option<&Path>) -> Result<Policy, String> {
    let Some(path) = path else {
        return Ok(Policy::default());
    };
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let file: PolicyFile =
        toml::from_str(&text).map_err(|e| format!("invalid {}: {e}", path.display()))?;
    Ok(file.noirspect)
}

fn rule_ids(ids: &[String]) -> Result<Vec<&'static str>, String> {
    ids.iter()
        .map(|id| {
            rule(id)
                .map(|r| r.id)
                .ok_or_else(|| format!("unknown rule ID: {id}"))
        })
        .collect()
}

fn options(target: &TargetArgs, policy: &Policy) -> AnalysisOptions {
    let mut options = AnalysisOptions::new(&target.program_dir);
    options.package = target.package.clone();
    options.workspace = target.workspace;
    options.entry = target.entry.or(policy.entry).unwrap_or(EntryMode::Auto);
    options.function = target.function.clone();
    options
}

fn lint(args: &LintArgs) -> Result<ExitCode, String> {
    let policy = load_policy(args.config.as_deref())?;
    let mut options = options(&args.target, &policy);
    let enable: BTreeSet<_> = rule_ids(&[policy.enable.clone(), args.enable.clone()].concat())?
        .into_iter()
        .collect();
    let disable: BTreeSet<_> = rule_ids(&[policy.disable.clone(), args.disable.clone()].concat())?
        .into_iter()
        .collect();
    options.rules = RULES
        .iter()
        .filter(|r| (r.default_enabled || enable.contains(r.id)) && !disable.contains(r.id))
        .map(|r| r.id)
        .collect();
    let min = args
        .min_severity
        .as_deref()
        .or(policy.min_severity.as_deref())
        .unwrap_or("info");
    options.min_severity =
        Severity::parse(min).ok_or_else(|| format!("unknown severity: {min}"))?;
    let format = args
        .format
        .as_deref()
        .or(policy.format.as_deref())
        .unwrap_or("text");
    if !["text", "json", "sarif"].contains(&format) {
        return Err(format!("unknown format: {format}"));
    }

    let timeout = args
        .entry_timeout
        .or(policy.entry_timeout)
        .unwrap_or(DEFAULT_ENTRY_TIMEOUT_SECONDS);
    if timeout > 0 {
        let exe = std::env::current_exe().map_err(|e| format!("cannot locate noirspect: {e}"))?;
        options.worker = Some(Worker {
            exe,
            timeout: Duration::from_secs(timeout),
        });
    }

    let analysis = analyze(&options)?;
    let rendered = report::render(&analysis, format);
    match &args.output {
        Some(path) => std::fs::write(path, rendered)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?,
        None => print!("{rendered}"),
    }
    Ok(if analysis.findings.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

fn print_ssa(target: &TargetArgs) -> Result<ExitCode, String> {
    let options = options(target, &Policy::default());
    let workspace = noirspect::driver::load(&noirspect::driver::LoadOptions {
        program_dir: &options.program_dir,
        package: options.package.as_deref(),
        workspace: options.workspace,
        entry: options.entry,
        function_filter: options.function.as_deref(),
        worker: None,
    })?;
    for package in &workspace.packages {
        for entry in &package.entries {
            println!("// {}::{}", package.name, entry.name);
            match &entry.ssa {
                Ok(ssa) => println!("{ssa}"),
                Err(e) => println!("// skipped: {e}\n"),
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match &cli.command {
        Command::Lint(args) => lint(args),
        Command::Rules => {
            for r in &RULES {
                let state = if r.default_enabled { "on" } else { "off" };
                println!("{}\t{}\t{state}\t{}", r.id, r.severity, r.title);
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Ssa(target) => print_ssa(target),
        Command::Lower(args) => noirspect::driver::worker_main(
            &args.program_dir,
            &args.package,
            args.entry,
            args.function.as_deref(),
            args.start,
        )
        .map(|()| ExitCode::SUCCESS),
    };
    result.unwrap_or_else(|e| {
        eprintln!("noirspect: error: {e}");
        ExitCode::from(1)
    })
}
