//! Text, JSON and SARIF renderers, matching the jwt-audit and oidc-audit family.

use crate::Analysis;
use crate::rules::{Finding, RULES, Severity};
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn render(analysis: &Analysis, format: &str) -> String {
    match format {
        "json" => {
            serde_json::to_string_pretty(&json_report(analysis)).expect("serializable") + "\n"
        }
        "sarif" => {
            serde_json::to_string_pretty(&sarif_report(analysis)).expect("serializable") + "\n"
        }
        _ => text_report(analysis),
    }
}

fn location(f: &Finding) -> String {
    f.loc
        .as_ref()
        .map(|l| l.to_string())
        .unwrap_or_else(|| "<unknown>".to_string())
}

pub fn text_report(analysis: &Analysis) -> String {
    let mut lines = vec![
        "noirspect lint report".to_string(),
        format!("packages: {}", analysis.packages.join(", ")),
        format!("entry points analyzed: {}", analysis.entries_analyzed),
        format!("findings: {}", analysis.findings.len()),
    ];
    if analysis.baselined > 0 {
        lines.push(format!("left out by the baseline: {}", analysis.baselined));
    }
    for f in &analysis.findings {
        let rule = f.rule();
        lines.push(String::new());
        lines.push(format!(
            "[{}] {}: {}",
            rule.severity.to_string().to_uppercase(),
            rule.id,
            rule.title
        ));
        lines.push(format!("  at: {}", location(f)));
        for related in &f.related {
            lines.push(format!("  see: {} ({})", related.loc, related.label));
        }
        if !f.entry.is_empty() {
            lines.push(format!("  entry: {}::{}", f.package, f.entry));
        }
        lines.push(format!("  {}", f.message));
        lines.push(format!("  fix: {}", rule.remediation));
        lines.push(format!("  docs: {}", rule.help_uri()));
    }
    if !analysis.skipped.is_empty() {
        lines.push(String::new());
        lines.push(format!(
            "skipped {} entry point(s) the compiler could not lower:",
            analysis.skipped.len()
        ));
        for s in &analysis.skipped {
            let first = s.error.lines().next().unwrap_or_default();
            lines.push(format!("  {}::{}: {first}", s.package, s.entry));
        }
    }
    lines.join("\n") + "\n"
}

pub fn json_report(analysis: &Analysis) -> Value {
    let mut summary = serde_json::Map::new();
    summary.insert("packages".into(), json!(analysis.packages.len()));
    summary.insert("entry_points".into(), json!(analysis.entries_analyzed));
    summary.insert("findings".into(), json!(analysis.findings.len()));
    summary.insert("baselined".into(), json!(analysis.baselined));
    for severity in [
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let count = analysis
            .findings
            .iter()
            .filter(|f| f.rule().severity == severity)
            .count();
        summary.insert(severity.to_string(), json!(count));
    }
    let findings: Vec<Value> = analysis
        .findings
        .iter()
        .map(|f| {
            let rule = f.rule();
            json!({
                "rule_id": rule.id,
                "severity": rule.severity,
                "title": rule.title,
                "message": f.message,
                "file": f.loc.as_ref().map(|l| &l.file),
                "line": f.loc.as_ref().map(|l| l.line),
                "column": f.loc.as_ref().map(|l| l.col),
                "related": f.related.iter().map(|r| json!({
                    "file": r.loc.file, "line": r.loc.line, "column": r.loc.col, "label": r.label,
                })).collect::<Vec<_>>(),
                "package": f.package,
                "entry": if f.entry.is_empty() { None } else { Some(&f.entry) },
                "remediation": rule.remediation,
                "help_uri": rule.help_uri(),
                "fingerprint": f.fingerprint,
            })
        })
        .collect();
    json!({
        "schema_version": "1.0",
        "tool": { "name": "noirspect", "version": env!("CARGO_PKG_VERSION"), "noir": NOIR_VERSION },
        "generated_at": now_rfc3339(),
        "summary": summary,
        "packages": analysis.packages,
        "findings": findings,
        "skipped": analysis.skipped,
    })
}

pub const NOIR_VERSION: &str = "1.0.0-beta.26";

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn security_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "7.0",
        Severity::Medium => "4.0",
        Severity::Low => "1.0",
        Severity::Info => "0.0",
    }
}

/// Code scanning resolves URIs against the repository root, which is where CI
/// runs noirspect, so paths are made relative to the working directory when the
/// workspace is inside it (`--program-dir circuits/foo` gives `circuits/foo/src/main.nr`).
fn sarif_uri(analysis: &Analysis, file: &str) -> String {
    let absolute = analysis.root.join(file);
    let relative = std::env::current_dir().ok().and_then(|cwd| {
        let cwd = cwd.canonicalize().ok()?;
        absolute
            .strip_prefix(&cwd)
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    });
    relative
        .unwrap_or_else(|| file.to_string())
        .replace('\\', "/")
}

fn sarif_location(uri: &str, line: u32, col: u32) -> Value {
    json!({
        "physicalLocation": {
            "artifactLocation": { "uri": uri },
            "region": { "startLine": line, "startColumn": col },
        }
    })
}

pub fn sarif_report(analysis: &Analysis) -> Value {
    let rules: Vec<Value> = RULES
        .iter()
        .map(|rule| {
            json!({
                "id": rule.id,
                "name": rule.title.replace([' ', '-'], ""),
                "shortDescription": { "text": rule.title },
                "fullDescription": { "text": rule.summary },
                "helpUri": rule.help_uri(),
                "help": { "text": rule.remediation },
                "defaultConfiguration": { "level": sarif_level(rule.severity), "enabled": rule.default_enabled },
                "properties": {
                    "security-severity": security_severity(rule.severity),
                    "tags": ["security", "zero-knowledge", "under-constrained"],
                },
            })
        })
        .collect();
    let results: Vec<Value> = analysis
        .findings
        .iter()
        .map(|f| {
            let rule = f.rule();
            let mut result = json!({
                "ruleId": rule.id,
                "ruleIndex": RULES.iter().position(|r| r.id == rule.id),
                "level": sarif_level(rule.severity),
                "message": { "text": f.message },
            });
            if let Some(loc) = &f.loc {
                let uri = sarif_uri(analysis, &loc.file);
                result["partialFingerprints"] = json!({ "noirspect/v1": f.fingerprint });
                result["locations"] = json!([sarif_location(&uri, loc.line, loc.col)]);
            }
            if !f.related.is_empty() {
                result["relatedLocations"] = Value::Array(
                    f.related
                        .iter()
                        .enumerate()
                        .map(|(i, r)| {
                            let mut l = sarif_location(
                                &sarif_uri(analysis, &r.loc.file),
                                r.loc.line,
                                r.loc.col,
                            );
                            l["id"] = json!(i + 1);
                            l["message"] = json!({ "text": r.label });
                            l
                        })
                        .collect(),
                );
            }
            result
        })
        .collect();
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "noirspect",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/Liam-G/noirspect",
                "rules": rules,
            }},
            "results": results,
        }],
    })
}

/// UTC timestamp without pulling in a date library.
fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Howard Hinnant's civil-from-days algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}
