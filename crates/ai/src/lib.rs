use leaklens_core::{AiTriage, Finding, ScanReport, Severity};

pub trait AiTriageProvider {
    fn enrich_report(&self, report: &mut ScanReport);
}

pub struct HeuristicAiTriageProvider;

impl AiTriageProvider for HeuristicAiTriageProvider {
    fn enrich_report(&self, report: &mut ScanReport) {
        for finding in &mut report.findings {
            finding.ai_triage = Some(build_finding_triage(finding));
        }

        report.coverage.ai_triage_enabled = true;
        report.executive_summary = build_executive_summary(report);
    }
}

fn build_finding_triage(finding: &Finding) -> AiTriage {
    let lower_path = finding.file_path.to_ascii_lowercase();
    let likely_real_secret = !looks_like_fixture_path(&lower_path);

    let explanation = match finding.secret_type.as_str() {
        "private_key" => "This looks like directly exposed private key material. If it is real, every dependent trust boundary should be treated as compromised.".to_string(),
        "aws_access_key" => "This resembles an AWS access key. Even without the paired secret, it is a strong indicator that credentials may be living in plaintext.".to_string(),
        "github_token" => "This resembles a GitHub token. Tokens like this often unlock repo, org, or CI automation access and should be rotated quickly.".to_string(),
        "slack_token" => "This resembles a Slack token. If valid, it can expose messages, integrations, or bot capabilities depending on the app scope.".to_string(),
        "openai_api_key" => "This resembles an OpenAI API key. If active, it can burn credits, expose model access, and leak downstream prompts or outputs.".to_string(),
        "anthropic_api_key" => "This resembles an Anthropic API key. If active, it can expose model access and billable usage.".to_string(),
        "huggingface_token" => "This resembles a Hugging Face token. If valid, it can expose private models, datasets, or write access depending on scope.".to_string(),
        "sendgrid_api_key" => "This resembles a SendGrid API key. If valid, it may allow outbound mail abuse or access to sender configuration.".to_string(),
        "database_url" => "This looks like a database connection string with embedded credentials. These often enable direct access to live data stores.".to_string(),
        _ => "This looks like a secret assigned directly in source or config. The surrounding code should be checked to confirm whether it is still active.".to_string(),
    };

    let mut next_steps = vec![
        "Confirm whether the value is active or only a sample/test placeholder.".to_string(),
        "Move secrets into a managed secret store or environment injection flow.".to_string(),
    ];

    match finding.severity {
        Severity::Critical | Severity::High => {
            next_steps.push("Rotate or revoke the exposed credential before the next deploy.".to_string());
            next_steps.push("Review audit logs for activity tied to the credential family.".to_string());
        }
        Severity::Medium | Severity::Low => {
            next_steps.push("Review git history to see whether the value was previously committed or copied elsewhere.".to_string());
        }
    }

    if finding.lineage.seen_in_history {
        next_steps.push("Check the first and last commits tied to this finding to understand how long the secret was exposed.".to_string());
    }

    if finding.lineage.present_in_working_tree {
        next_steps.push("The secret still appears in the working tree, so fix the live file in addition to cleaning history.".to_string());
    }

    AiTriage {
        explanation: format!(
            "{} Risk score {}. Seen {} time(s).",
            explanation, finding.risk_score, finding.lineage.occurrence_count
        ),
        likely_real_secret,
        next_steps,
    }
}

fn looks_like_fixture_path(path: &str) -> bool {
    path.contains("/docs/")
        || path.contains("readme")
        || path.contains("/example/")
        || path.contains("/examples/")
        || path.contains("/sample/")
        || path.contains("/samples/")
        || path.contains("/test/")
        || path.contains("/tests/")
        || path.contains("/test_data/")
        || path.contains("/fixture/")
        || path.contains("/fixtures/")
        || path.contains("/demo/")
        || path.contains("/mock/")
}

fn build_executive_summary(report: &ScanReport) -> String {
    if report.findings.is_empty() {
        return format!(
            "LeakLens scanned {} files, found no obvious secret exposures, and the heuristic AI layer had nothing high-risk to escalate.",
            report.summary.files_scanned
        );
    }

    let high_or_critical = report
        .findings
        .iter()
        .filter(|finding| matches!(finding.severity, Severity::Critical | Severity::High))
        .count();

    if high_or_critical > 0 {
        format!(
            "LeakLens found {} total finding{} across {} incident{} with {} higher-risk exposure{} that should be reviewed first. Highest risk score: {}.",
            report.findings.len(),
            if report.findings.len() == 1 { "" } else { "s" },
            report.summary.incidents_total,
            if report.summary.incidents_total == 1 { "" } else { "s" },
            high_or_critical,
            if high_or_critical == 1 { "" } else { "s" },
            report.summary.highest_risk_score
        )
    } else {
        format!(
            "LeakLens found {} lower-severity finding{} across {} incident{}; these still deserve review, but they look more triageable than immediately critical.",
            report.findings.len(),
            if report.findings.len() == 1 { "" } else { "s" },
            report.summary.incidents_total,
            if report.summary.incidents_total == 1 { "" } else { "s" }
        )
    }
}
