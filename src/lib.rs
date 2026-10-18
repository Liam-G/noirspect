//! noirspect: find under-constrained values in Noir circuits.

pub mod driver;
pub mod graph;
pub mod report;
pub mod rules;
pub mod source;
pub mod ssa;

use driver::{EntryMode, LoadOptions, Worker, WorkspaceSsa};
use rules::{Finding, RULES, Severity};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct AnalysisOptions {
    pub program_dir: PathBuf,
    pub package: Option<String>,
    pub workspace: bool,
    pub entry: EntryMode,
    pub function: Option<String>,
    pub min_severity: Severity,
    /// Rules to run; rules not listed are skipped.
    pub rules: BTreeSet<&'static str>,
    /// Lower entries in worker processes with a time budget; `None` lowers in-process.
    pub worker: Option<Worker>,
}

impl AnalysisOptions {
    pub fn new(program_dir: impl Into<PathBuf>) -> Self {
        AnalysisOptions {
            program_dir: program_dir.into(),
            package: None,
            workspace: false,
            entry: EntryMode::Auto,
            function: None,
            min_severity: Severity::Info,
            rules: RULES
                .iter()
                .filter(|r| r.default_enabled)
                .map(|r| r.id)
                .collect(),
            worker: None,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct EntryError {
    pub package: String,
    pub entry: String,
    pub error: String,
}

#[derive(Debug, Clone)]
pub struct Analysis {
    pub root: PathBuf,
    pub packages: Vec<String>,
    pub entries_analyzed: usize,
    pub findings: Vec<Finding>,
    /// Entry points the compiler could not lower to SSA; they are skipped.
    pub skipped: Vec<EntryError>,
}

pub fn analyze(options: &AnalysisOptions) -> Result<Analysis, String> {
    let workspace = driver::load(&LoadOptions {
        program_dir: &options.program_dir,
        package: options.package.as_deref(),
        workspace: options.workspace,
        entry: options.entry,
        function_filter: options.function.as_deref(),
        worker: options.worker.clone(),
    })?;
    Ok(analyze_loaded(&workspace, options))
}

pub fn analyze_loaded(workspace: &WorkspaceSsa, options: &AnalysisOptions) -> Analysis {
    let mut findings = Vec::new();
    let mut skipped = Vec::new();
    let mut entries_analyzed = 0;
    // Findings carry report paths; the compiler's printed names map onto them.
    let display: HashMap<&str, &str> = workspace
        .packages
        .iter()
        .flat_map(|p| {
            p.sources
                .iter()
                .map(|s| (s.name.as_str(), s.display.as_str()))
        })
        .collect();
    let sources: HashMap<&str, &str> = workspace
        .packages
        .iter()
        .flat_map(|p| {
            p.sources
                .iter()
                .map(|s| (s.display.as_str(), s.text.as_str()))
        })
        .collect();

    for package in &workspace.packages {
        let own_files: HashSet<&str> = package.sources.iter().map(|s| s.display.as_str()).collect();
        for entry in &package.entries {
            let text = match &entry.ssa {
                Ok(text) => text,
                Err(error) => {
                    skipped.push(EntryError {
                        package: package.name.clone(),
                        entry: entry.name.clone(),
                        error: error.clone(),
                    });
                    continue;
                }
            };
            entries_analyzed += 1;
            let program = ssa::parse_program(text);
            for func in program.acir_functions() {
                let g = graph::Graph::build(&program, func);
                for mut finding in rules::check_function(&g) {
                    // Library entry points: a value that escapes through the return
                    // value may be checked by the caller.
                    if finding.escapes && !entry.is_main {
                        continue;
                    }
                    finding.entry = entry.name.clone();
                    finding.package = package.name.clone();
                    let normalize = |file: &mut String| {
                        *file = match display.get(file.as_str()) {
                            Some(shown) => shown.to_string(),
                            None => normalize_file(&workspace.root, file),
                        }
                    };
                    if let Some(loc) = &mut finding.loc {
                        normalize(&mut loc.file);
                    }
                    for related in &mut finding.related {
                        normalize(&mut related.loc.file);
                    }
                    // Only report code that belongs to the analyzed packages.
                    if finding
                        .loc
                        .as_ref()
                        .is_some_and(|l| own_files.contains(l.file.as_str()))
                    {
                        findings.push(finding);
                    }
                }
            }
        }
        for file in &package.sources {
            for mut finding in source::empty_safety_comments(&file.display, &file.text) {
                finding.package = package.name.clone();
                findings.push(finding);
            }
        }
    }

    findings.retain(|f| {
        options.rules.contains(f.rule)
            && f.rule().severity >= options.min_severity
            && !f
                .loc
                .as_ref()
                .and_then(|l| sources.get(l.file.as_str()))
                .is_some_and(|text| source::is_suppressed(f, text))
    });
    let findings = dedupe(findings);

    Analysis {
        root: workspace.root.clone(),
        packages: workspace.packages.iter().map(|p| p.name.clone()).collect(),
        entries_analyzed,
        findings,
        skipped,
    }
}

/// Printed SSA locations are relative to the workspace root or absolute.
fn normalize_file(root: &Path, file: &str) -> String {
    let path = Path::new(file);
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

/// The same hint is seen from every entry point that inlines it; keep one finding.
fn dedupe(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(|a, b| {
        let key = |f: &Finding| {
            (
                std::cmp::Reverse(f.rule().severity),
                f.rule,
                f.loc.clone(),
                f.related.clone(),
            )
        };
        key(a).cmp(&key(b))
    });
    let mut seen = HashSet::new();
    findings.retain(|f| seen.insert((f.rule, f.loc.clone(), f.related.clone())));
    findings
}
