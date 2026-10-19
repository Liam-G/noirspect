//! End-to-end tests of the `noirspect` binary: exit codes, report formats,
//! policy options and suppression comments.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn example(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(name)
}

fn noirspect(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_noirspect"))
        .args(args)
        .output()
        .expect("run noirspect")
}

fn lint(dir: &Path, extra: &[&str]) -> Output {
    let dir = dir.to_str().unwrap();
    let mut args = vec!["lint", "--program-dir", dir];
    args.extend_from_slice(extra);
    noirspect(&args)
}

fn rule_ids(report: &Value) -> Vec<String> {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule_id"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn findings_exit_2_and_clean_exits_0() {
    let vulnerable = lint(&example("vulnerable"), &[]);
    assert_eq!(
        vulnerable.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&vulnerable.stderr)
    );
    let text = String::from_utf8(vulnerable.stdout).unwrap();
    for rule in ["NUC-002", "NUC-003", "NUC-004", "NUC-008"] {
        assert!(text.contains(rule), "missing {rule} in:\n{text}");
    }

    let fixed = lint(&example("fixed"), &[]);
    assert_eq!(
        fixed.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&fixed.stdout)
    );
}

#[test]
fn usage_errors_exit_1() {
    let missing = lint(Path::new("/nonexistent/noirspect"), &[]);
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("noirspect: error:"));

    let unknown_rule = lint(&example("fixed"), &["--disable", "NUC-999"]);
    assert_eq!(unknown_rule.status.code(), Some(1));
}

#[test]
fn json_report_has_locations_and_summary() {
    let out = lint(
        &example("vulnerable"),
        &["--format", "json", "--entry-timeout", "0"],
    );
    let report: Value = serde_json::from_slice(&out.stdout).expect("json report");
    assert_eq!(report["schema_version"], "1.0");
    assert_eq!(report["summary"]["findings"], 4);
    assert_eq!(report["summary"]["high"], 3);
    let remainder = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule_id"] == "NUC-002")
        .unwrap();
    assert_eq!(remainder["file"], "src/main.nr");
    assert_eq!(remainder["line"], 11);
    assert_eq!(remainder["related"][0]["line"], 12);
}

#[test]
fn sarif_report_is_code_scanning_shaped() {
    let out = lint(&example("vulnerable"), &["--format", "sarif"]);
    let sarif: Value = serde_json::from_slice(&out.stdout).expect("sarif report");
    assert_eq!(sarif["version"], "2.1.0");
    let run = &sarif["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "noirspect");
    assert_eq!(run["tool"]["driver"]["rules"].as_array().unwrap().len(), 9);
    assert!(run["results"][0]["partialFingerprints"]["noirspect/v1"].is_string());
    let result = &run["results"][0];
    assert_eq!(result["level"], "error");
    let location = &result["locations"][0]["physicalLocation"];
    // Relative to the working directory (the crate root under `cargo test`).
    assert_eq!(
        location["artifactLocation"]["uri"],
        "examples/vulnerable/src/main.nr"
    );
    assert!(location["region"]["startLine"].as_u64().unwrap() > 0);
    assert!(result["relatedLocations"][0]["message"]["text"].is_string());
}

#[test]
fn policy_options_filter_findings() {
    let high_only = lint(
        &example("vulnerable"),
        &["--format", "json", "--min-severity", "high"],
    );
    let report: Value = serde_json::from_slice(&high_only.stdout).unwrap();
    assert_eq!(rule_ids(&report), ["NUC-002", "NUC-003", "NUC-004"]);

    let disabled = lint(
        &example("vulnerable"),
        &[
            "--format",
            "json",
            "--disable",
            "NUC-003",
            "--disable",
            "nuc-008",
        ],
    );
    let report: Value = serde_json::from_slice(&disabled.stdout).unwrap();
    assert_eq!(rule_ids(&report), ["NUC-002", "NUC-004"]);

    let dir = tempdir("config");
    let config = dir.join("noirspect.toml");
    std::fs::write(
        &config,
        "[noirspect]\nformat = \"json\"\ndisable = [\"NUC-002\", \"NUC-004\", \"NUC-008\"]\n",
    )
    .unwrap();
    let configured = lint(
        &example("vulnerable"),
        &["--config", config.to_str().unwrap()],
    );
    let report: Value = serde_json::from_slice(&configured.stdout).unwrap();
    assert_eq!(rule_ids(&report), ["NUC-003"]);
}

#[test]
fn output_file_is_written() {
    let dir = tempdir("output");
    let path = dir.join("report.sarif");
    let out = lint(
        &example("vulnerable"),
        &["--format", "sarif", "--output", path.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let sarif: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
}

#[test]
fn ignore_comments_suppress_findings() {
    let dir = tempdir("suppress");
    copy_dir(&example("vulnerable"), &dir);
    let main = dir.join("src/main.nr");
    let source = std::fs::read_to_string(&main).unwrap().replace(
        "    let (q, r) = unsafe { div_hint(n, d) };",
        "    // noirspect-ignore: NUC-002\n    let (q, r) = unsafe { div_hint(n, d) };",
    );
    std::fs::write(&main, source).unwrap();
    let out = lint(&dir, &["--format", "json"]);
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(!rule_ids(&report).contains(&"NUC-002".to_string()));
    assert!(rule_ids(&report).contains(&"NUC-004".to_string()));
}

#[test]
fn baseline_leaves_out_accepted_findings() {
    let dir = tempdir("baseline");
    copy_dir(&example("vulnerable"), &dir);
    let baseline = dir.join("baseline.json");
    let first = lint(
        &dir,
        &["--format", "json", "--output", baseline.to_str().unwrap()],
    );
    assert_eq!(first.status.code(), Some(2));

    // Unrelated edits above the findings move every line but keep the fingerprints.
    let main = dir.join("src/main.nr");
    let source = std::fs::read_to_string(&main).unwrap();
    std::fs::write(
        &main,
        format!("// a new header line\n// and another\n{source}"),
    )
    .unwrap();
    let accepted = lint(
        &dir,
        &["--format", "json", "--baseline", baseline.to_str().unwrap()],
    );
    assert_eq!(
        accepted.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&accepted.stdout)
    );
    let report: Value = serde_json::from_slice(&accepted.stdout).unwrap();
    assert_eq!(report["summary"]["baselined"], 4);

    // A new bug is still reported.
    let source = std::fs::read_to_string(&main).unwrap().replace(
        "fn main(",
        "unconstrained fn inv_hint(x: Field) -> Field { 1 / x }\n\nfn check_inv(x: Field) {\n    // Safety: checked\n    let inv = unsafe { inv_hint(x) };\n    assert(inv != 0);\n}\n\nfn main(",
    );
    let source = source.replace(
        "    (div(n, d), is_zero(x), to_bits(byte))",
        "    check_inv(x);\n    (div(n, d), is_zero(x), to_bits(byte))",
    );
    std::fs::write(&main, source).unwrap();
    let regressed = lint(
        &dir,
        &["--format", "json", "--baseline", baseline.to_str().unwrap()],
    );
    assert_eq!(regressed.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&regressed.stdout).unwrap();
    assert_eq!(rule_ids(&report), ["NUC-001"]);

    let not_a_report = dir.join("Nargo.toml");
    let bad = lint(&dir, &["--baseline", not_a_report.to_str().unwrap()]);
    assert_eq!(bad.status.code(), Some(1));
}

#[test]
fn parallel_jobs_match_a_sequential_run() {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/nuc003");
    let ids = |jobs: &str| {
        let out = lint(&corpus, &["--format", "json", "--jobs", jobs]);
        let report: Value = serde_json::from_slice(&out.stdout).unwrap();
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                (
                    f["line"].as_u64().unwrap(),
                    f["fingerprint"].as_str().unwrap().to_string(),
                )
            })
            .collect::<Vec<_>>()
    };
    let sequential = ids("1");
    assert_eq!(sequential.len(), 6);
    assert_eq!(ids("3"), sequential);
}

#[test]
fn rules_command_lists_catalogue() {
    let out = noirspect(&["rules"]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(text.lines().count(), 9);
    assert!(text.contains("NUC-007\tmedium\toff\tNarrowing cast of an unchecked Field"));
}

fn tempdir(name: &str) -> PathBuf {
    let dir =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn copy_dir(from: &Path, to: &Path) {
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            if entry.file_name() == "target" {
                continue;
            }
            std::fs::create_dir_all(&target).unwrap();
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

#[test]
fn version_names_the_pinned_nargo_release() {
    let out = noirspect(&["--version"]);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains(&format!("(nargo {})", noirspect::report::NOIR_VERSION)));
    // Every compiler crate in Cargo.toml must be pinned to that same release.
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    let tag = format!("tag = \"v{}\"", noirspect::report::NOIR_VERSION);
    let pinned: Vec<&str> = manifest
        .lines()
        .filter(|l| l.contains("noir-lang/noir"))
        .collect();
    assert!(!pinned.is_empty());
    for line in pinned {
        assert!(line.contains(&tag), "{line} is not pinned to {tag}");
    }
}
