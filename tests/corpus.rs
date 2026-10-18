//! Seeded suite: every `tests/corpus/<rule>` package holds vulnerable functions
//! marked `// expect: RULE` and correct look-alikes with no marker. Every
//! vulnerable function must be flagged with exactly its rules, and no
//! look-alike may be flagged at all.

use noirspect::rules::RULES;
use noirspect::{AnalysisOptions, analyze};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

struct Function {
    name: String,
    start: u32,
    end: u32,
    expected: BTreeSet<String>,
}

/// Top-level `fn` items with their line ranges and `// expect:` markers.
fn functions(text: &str) -> Vec<Function> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out: Vec<Function> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let decl = line.strip_prefix("pub ").unwrap_or(line);
        let Some(rest) = decl
            .strip_prefix("fn ")
            .or_else(|| decl.strip_prefix("unconstrained fn "))
        else {
            continue;
        };
        let name = rest
            .split(['(', '<'])
            .next()
            .unwrap_or_default()
            .to_string();
        if let Some(last) = out.last_mut() {
            last.end = i as u32;
        }
        let expected = (i > 0)
            .then(|| lines[i - 1].trim().strip_prefix("// expect:"))
            .flatten()
            .map(|ids| ids.split(',').map(|id| id.trim().to_string()).collect())
            .unwrap_or_default();
        out.push(Function {
            name,
            start: i as u32 + 1,
            end: lines.len() as u32 + 1,
            expected,
        });
    }
    out
}

fn check_package(dir: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(dir.join("src/lib.nr")).expect("corpus source");
    let mut options = AnalysisOptions::new(dir);
    options.rules = RULES.iter().map(|r| r.id).collect();
    let analysis = analyze(&options).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    assert!(
        analysis.skipped.is_empty(),
        "{}: skipped entries {:?}",
        dir.display(),
        analysis.skipped
    );

    let funcs = functions(&text);
    let mut found: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for finding in &analysis.findings {
        let line = finding.loc.as_ref().expect("located finding").line;
        let func = funcs
            .iter()
            .find(|f| f.start <= line && line < f.end)
            .unwrap_or_else(|| {
                panic!(
                    "{}: finding outside any function: {finding:?}",
                    dir.display()
                )
            });
        found
            .entry(&func.name)
            .or_default()
            .insert(finding.rule.to_string());
    }

    let mut errors = Vec::new();
    let mut vulnerable = 0;
    let mut look_alikes = 0;
    for func in funcs
        .iter()
        .filter(|f| f.name.starts_with("vuln_") || f.name.starts_with("safe_"))
    {
        if func.name.starts_with("vuln_") {
            vulnerable += 1;
        } else {
            look_alikes += 1;
        }
        let got = found.get(func.name.as_str()).cloned().unwrap_or_default();
        if got != func.expected {
            errors.push(format!(
                "{}::{}: expected {:?}, found {:?}",
                dir.file_name().unwrap().to_string_lossy(),
                func.name,
                func.expected,
                got
            ));
        }
    }
    if vulnerable < 5 || look_alikes < 5 {
        errors.push(format!(
            "{}: needs at least 5 vulnerable and 5 correct cases",
            dir.display()
        ));
    }
    errors
}

#[test]
fn seeded_suite() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut dirs: Vec<_> = std::fs::read_dir(&root)
        .expect("corpus directory")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.join("Nargo.toml").exists())
        .collect();
    dirs.sort();
    let covered: BTreeSet<String> = dirs
        .iter()
        .map(|d| {
            d.file_name()
                .unwrap()
                .to_string_lossy()
                .to_ascii_uppercase()
        })
        .collect();
    for rule in &RULES {
        assert!(
            covered.contains(&rule.id.replace('-', "")),
            "no corpus for {}",
            rule.id
        );
    }
    let errors: Vec<String> = dirs.iter().flat_map(|d| check_package(d)).collect();
    assert!(
        errors.is_empty(),
        "seeded suite failures:\n{}",
        errors.join("\n")
    );
}
