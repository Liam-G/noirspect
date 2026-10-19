//! Source-level checks: empty safety comments (NUC-008) and inline suppressions.

use crate::rules::Finding;
use crate::ssa::Loc;

const TRIVIAL_REASONS: [&str; 16] = [
    "",
    "safe",
    "is safe",
    "this is safe",
    "it is safe",
    "it's safe",
    "todo",
    "fixme",
    "xxx",
    "tbd",
    "n/a",
    "na",
    "none",
    "ok",
    "trust me",
    "unsafe",
];

/// The reason a `// Safety:` comment gives, if `line` starts one.
fn safety_reason(line: &str) -> Option<String> {
    let comment = line.trim_start().strip_prefix("//")?.trim_start();
    if !comment.get(..6)?.eq_ignore_ascii_case("safety") {
        return None;
    }
    let rest = &comment[6..];
    let rest = rest.strip_prefix(':').unwrap_or(rest);
    Some(rest.trim().to_string())
}

fn is_trivial(reason: &str) -> bool {
    let cleaned: String = reason
        .chars()
        .filter(|c| c.is_alphanumeric() || " '/".contains(*c))
        .collect();
    TRIVIAL_REASONS.contains(&cleaned.trim().to_ascii_lowercase().as_str())
}

/// NUC-008 over one file's text. `file` is the name used in reports.
pub fn empty_safety_comments(file: &str, text: &str) -> Vec<Finding> {
    let lines: Vec<&str> = text.lines().collect();
    let mut findings = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let Some(reason) = safety_reason(line) else {
            continue;
        };
        // A reason may continue on the following comment lines.
        let continuation = lines[i + 1..]
            .iter()
            .take_while(|l| l.trim_start().starts_with("//"))
            .any(|l| !l.trim_start().trim_start_matches('/').trim().is_empty());
        if !is_trivial(&reason) || (reason.is_empty() && continuation) {
            continue;
        }
        let col = line.find("//").map_or(1, |c| c as u32 + 1);
        findings.push(Finding {
            rule: "NUC-008",
            message: if reason.is_empty() {
                "this `// Safety:` comment gives no reason".to_string()
            } else {
                format!("this `// Safety:` comment gives no real reason (\"{reason}\")")
            },
            loc: Some(Loc {
                file: file.to_string(),
                line: i as u32 + 1,
                col,
            }),
            related: Vec::new(),
            entry: String::new(),
            package: String::new(),
            fingerprint: String::new(),
            escapes: false,
        });
    }
    findings
}

/// Rule ids listed in a `noirspect-ignore` comment on `line`; an empty list means every rule.
fn ignored_on(line: &str) -> Option<Vec<String>> {
    let at = line.find("noirspect-ignore")?;
    if !line[..at].contains("//") {
        return None;
    }
    let rest = &line[at + "noirspect-ignore".len()..];
    let rest = rest.trim_start_matches(':');
    Some(
        rest.split(|c: char| c == ',' || c.is_whitespace())
            .map(str::trim)
            .filter(|w| w.to_ascii_uppercase().starts_with("NUC-"))
            .map(str::to_ascii_uppercase)
            .collect(),
    )
}

/// True when `// noirspect-ignore[: RULE, …]` sits on the finding's line or the line above it.
pub fn is_suppressed(finding: &Finding, text: &str) -> bool {
    let Some(loc) = &finding.loc else {
        return false;
    };
    let lines: Vec<&str> = text.lines().collect();
    let line = loc.line as usize;
    [line.checked_sub(1), line.checked_sub(2)]
        .into_iter()
        .flatten()
        .filter_map(|i| lines.get(i))
        .any(|l| {
            ignored_on(l)
                .is_some_and(|rules| rules.is_empty() || rules.iter().any(|r| r == finding.rule))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_trivial_safety_comments() {
        let text = "fn f() {\n    // Safety:\n    let a = unsafe { h() };\n    // Safety: safe\n    let b = unsafe { h() };\n    // SAFETY: TODO.\n    let c = unsafe { h() };\n    // Safety: q and r are checked below\n    let d = unsafe { h() };\n}\n";
        let findings = empty_safety_comments("src/main.nr", text);
        let lines: Vec<u32> = findings
            .iter()
            .map(|f| f.loc.as_ref().unwrap().line)
            .collect();
        assert_eq!(lines, vec![2, 4, 6]);
    }

    #[test]
    fn multi_line_reason_is_accepted() {
        let text = "// Safety:\n// the result is range checked below\nlet a = unsafe { h() };\n";
        assert!(empty_safety_comments("a.nr", text).is_empty());
    }

    #[test]
    fn suppression_comments() {
        let text = "// noirspect-ignore: NUC-002\nlet x = unsafe { h() };\nlet y = unsafe { h() }; // noirspect-ignore\n";
        let mut f = empty_safety_comments("a.nr", "// Safety:\n").remove(0);
        f.rule = "NUC-002";
        f.loc = Some(Loc {
            file: "a.nr".into(),
            line: 2,
            col: 1,
        });
        assert!(is_suppressed(&f, text));
        f.rule = "NUC-001";
        assert!(!is_suppressed(&f, text));
        f.loc = Some(Loc {
            file: "a.nr".into(),
            line: 3,
            col: 1,
        });
        assert!(is_suppressed(&f, text));
    }
}
