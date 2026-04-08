use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use leaklens_core::ScanReport;
use serde_json::json;

pub fn write_json_report(path: &Path, report: &ScanReport) -> Result<()> {
    ensure_parent(path)?;
    let content = serde_json::to_string_pretty(report).context("failed to serialize JSON report")?;
    fs::write(path, content).with_context(|| format!("failed to write JSON report to {}", path.display()))
}

pub fn write_html_report(path: &Path, report: &ScanReport) -> Result<()> {
    ensure_parent(path)?;
    let html = render_html(report);
    fs::write(path, html).with_context(|| format!("failed to write HTML report to {}", path.display()))
}

pub fn write_sarif_report(path: &Path, report: &ScanReport) -> Result<()> {
    ensure_parent(path)?;

    let rules = report
        .findings
        .iter()
        .map(|finding| {
            (
                finding.detector_id.clone(),
                json!({
                    "id": finding.detector_id,
                    "name": finding.detector_name,
                    "shortDescription": { "text": finding.title },
                    "fullDescription": { "text": finding.description },
                }),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>()
        .into_values()
        .collect::<Vec<_>>();

    let results = report
        .findings
        .iter()
        .map(|finding| {
            json!({
                "ruleId": &finding.detector_id,
                "level": sarif_level(finding.severity.as_str()),
                "message": {
                    "text": format!("{} ({})", finding.title, finding.redacted_secret)
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": &finding.file_path },
                        "region": {
                            "startLine": finding.line.unwrap_or(1),
                            "startColumn": finding.start_column.unwrap_or(1),
                            "endColumn": finding.end_column.unwrap_or(finding.start_column.unwrap_or(1))
                        }
                    }
                }]
            })
        })
        .collect::<Vec<_>>();

    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "LeakLens",
                    "informationUri": "https://github.com/shanksfigarland",
                    "rules": rules
                }
            },
            "results": results
        }]
    });

    let content = serde_json::to_string_pretty(&sarif).context("failed to serialize SARIF report")?;
    fs::write(path, content).with_context(|| format!("failed to write SARIF report to {}", path.display()))
}

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory {}", parent.display()))?;
    }
    Ok(())
}

fn render_html(report: &ScanReport) -> String {
    let incident_groups = build_incident_groups(report);
    let severity_cards = report
        .summary
        .by_severity
        .iter()
        .map(|(severity, count)| {
            format!(
                r#"<div class="metric"><span class="metric-label">{}</span><span class="metric-value">{}</span></div>"#,
                escape_html(severity),
                count
            )
        })
        .collect::<Vec<_>>()
        .join("");

    let confidence_cards = report
        .summary
        .by_confidence
        .iter()
        .map(|(confidence, count)| {
            format!(
                r#"<div class="metric"><span class="metric-label">confidence {}</span><span class="metric-value">{}</span></div>"#,
                escape_html(confidence),
                count
            )
        })
        .collect::<Vec<_>>()
        .join("");

    let incident_cards = incident_groups
        .iter()
        .map(|(_, findings)| render_incident_card(findings))
        .collect::<Vec<_>>()
        .join("");

    let finding_cards = report
        .findings
        .iter()
        .map(|finding| {
            let ai_block = finding
                .ai_triage
                .as_ref()
                .map(|triage| {
                    format!(
                        r#"<div class="triage"><strong>AI triage:</strong> {}<ul>{}</ul></div>"#,
                        escape_html(&triage.explanation),
                        triage
                            .next_steps
                            .iter()
                            .map(|step| format!("<li>{}</li>", escape_html(step)))
                            .collect::<Vec<_>>()
                            .join("")
                    )
                })
                .unwrap_or_default();

            format!(
                r#"<article class="finding finding-{}">
<div class="finding-head">
  <span class="pill">{}</span>
  <span class="detector">{}</span>
</div>
<h3>{}</h3>
<p>{}</p>
<div class="meta">
  <span>{}</span>
  <span>line {}</span>
  <span>risk {}</span>
  <span>{}</span>
  <span>{}</span>
  <span>{}</span>
</div>
<pre>{}</pre>
<div class="lineage">
  <span>seen {}</span>
  <span>working tree: {}</span>
  <span>history: {}</span>
  {}
</div>
{}
</article>"#,
                escape_html(finding.severity.as_str()),
                escape_html(finding.severity.as_str()),
                escape_html(&finding.detector_name),
                escape_html(&finding.title),
                escape_html(&finding.description),
                escape_html(&finding.file_path),
                finding.line.unwrap_or_default(),
                finding.risk_score,
                escape_html(finding.confidence.as_str()),
                escape_html(&finding.source_origin.replace('_', " ")),
                escape_html(&finding.redacted_secret),
                escape_html(&finding.context),
                finding.lineage.occurrence_count,
                if finding.lineage.present_in_working_tree { "yes" } else { "no" },
                if finding.lineage.seen_in_history { "yes" } else { "no" },
                render_lineage_span(finding),
                ai_block
            )
        })
        .collect::<Vec<_>>()
        .join("");

    let recommendation_items = report
        .recommendations
        .iter()
        .map(|item| format!("<li>{}</li>", escape_html(item)))
        .collect::<Vec<_>>()
        .join("");

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>LeakLens Report</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #09111f;
      --panel: rgba(15, 23, 42, 0.88);
      --panel-border: rgba(148, 163, 184, 0.14);
      --text: #e5eefb;
      --muted: #9fb0c8;
      --critical: #ff6b81;
      --high: #ff8c69;
      --medium: #ffd166;
      --low: #79d2a6;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", Inter, Arial, sans-serif;
      background:
        radial-gradient(circle at top right, rgba(110, 168, 254, 0.16), transparent 25%),
        linear-gradient(180deg, #08101d 0%, #0a1323 100%);
      color: var(--text);
    }}
    .wrap {{
      max-width: 1200px;
      margin: 0 auto;
      padding: 32px 20px 48px;
    }}
    .hero, .panel, .finding {{
      background: var(--panel);
      border: 1px solid var(--panel-border);
      border-radius: 20px;
      backdrop-filter: blur(16px);
      box-shadow: 0 18px 48px rgba(0, 0, 0, 0.24);
    }}
    .hero {{ padding: 28px; margin-bottom: 24px; }}
    .grid {{ display: grid; grid-template-columns: 1.2fr 0.8fr; gap: 20px; margin-bottom: 24px; }}
    .panel {{ padding: 22px; }}
    .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; margin-top: 16px; }}
    .metric {{ padding: 14px; border-radius: 16px; background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.06); }}
    .metric-label {{ display: block; font-size: 12px; text-transform: uppercase; letter-spacing: 0.1em; color: var(--muted); margin-bottom: 6px; }}
    .metric-value {{ font-size: 24px; font-weight: 700; }}
    .finding-list {{ display: grid; gap: 16px; }}
    .finding {{ padding: 20px; }}
    .finding-head {{ display: flex; gap: 10px; align-items: center; margin-bottom: 12px; }}
    .pill {{ text-transform: uppercase; letter-spacing: 0.08em; font-size: 12px; padding: 6px 10px; border-radius: 999px; background: rgba(255,255,255,0.08); }}
    .finding-critical .pill {{ color: var(--critical); }}
    .finding-high .pill {{ color: var(--high); }}
    .finding-medium .pill {{ color: var(--medium); }}
    .finding-low .pill {{ color: var(--low); }}
    .meta {{ display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 14px; color: var(--muted); font-size: 14px; }}
    .lineage {{ display: flex; flex-wrap: wrap; gap: 12px; margin: 14px 0; color: var(--muted); font-size: 14px; }}
    .incident-grid {{ display: grid; gap: 16px; margin-bottom: 24px; }}
    .incident-card {{ padding: 18px; border-radius: 18px; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.06); }}
    pre {{ margin: 0; padding: 14px; border-radius: 14px; background: rgba(8, 15, 28, 0.85); color: #d8e6fb; overflow-x: auto; white-space: pre-wrap; word-break: break-word; }}
    ul {{ margin: 10px 0 0; padding-left: 18px; color: var(--muted); }}
    .triage {{ margin-top: 14px; padding-top: 14px; border-top: 1px solid rgba(255,255,255,0.08); }}
    @media (max-width: 900px) {{ .grid {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <h1>LeakLens Scan Report</h1>
      <p>{}</p>
      <p>Target: {}</p>
    </section>
    <div class="grid">
      <section class="panel">
        <h2>Summary</h2>
        <p>{}</p>
        <div class="metrics">
          <div class="metric"><span class="metric-label">Files scanned</span><span class="metric-value">{}</span></div>
          <div class="metric"><span class="metric-label">Bytes scanned</span><span class="metric-value">{}</span></div>
          <div class="metric"><span class="metric-label">Findings</span><span class="metric-value">{}</span></div>
          <div class="metric"><span class="metric-label">Incidents</span><span class="metric-value">{}</span></div>
          <div class="metric"><span class="metric-label">Top risk</span><span class="metric-value">{}</span></div>
          <div class="metric"><span class="metric-label">History commits</span><span class="metric-value">{}</span></div>
          {}
          {}
        </div>
      </section>
      <section class="panel">
        <h2>Recommendations</h2>
        <ul>{}</ul>
      </section>
    </div>
    <section class="panel">
      <h2>Incident overview</h2>
      <div class="incident-grid">{}</div>
    </section>
    <section class="finding-list">
      {}
    </section>
  </div>
</body>
</html>"#,
        escape_html(&report.generated_at),
        escape_html(&report.target),
        escape_html(&report.executive_summary),
        report.summary.files_scanned,
        report.summary.bytes_scanned,
        report.summary.findings_total,
        report.summary.incidents_total,
        report.summary.highest_risk_score,
        report.coverage.history_commits_scanned,
        severity_cards,
        confidence_cards,
        recommendation_items,
        incident_cards,
        finding_cards
    )
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn sarif_level(severity: &str) -> &'static str {
    match severity {
        "critical" | "high" => "error",
        "medium" => "warning",
        _ => "note",
    }
}

fn build_incident_groups<'a>(report: &'a ScanReport) -> BTreeMap<String, Vec<&'a leaklens_core::Finding>> {
    let mut groups = BTreeMap::new();
    for finding in &report.findings {
        groups
            .entry(finding.incident_id.clone())
            .or_insert_with(Vec::new)
            .push(finding);
    }
    groups
}

fn render_incident_card(findings: &[&leaklens_core::Finding]) -> String {
    let lead = findings[0];
    let paths = findings
        .iter()
        .map(|finding| finding.relative_path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|path| escape_html(&path))
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        r#"<article class="incident-card">
<div class="finding-head">
  <span class="pill">{}</span>
  <span class="detector">risk {}</span>
</div>
<h3>{}</h3>
<p>Seen {} time(s). Working tree: {}. History: {}.</p>
<p>{}</p>
</article>"#,
        escape_html(lead.severity.as_str()),
        lead.risk_score,
        escape_html(&lead.title),
        lead.lineage.occurrence_count,
        if lead.lineage.present_in_working_tree { "yes" } else { "no" },
        if lead.lineage.seen_in_history { "yes" } else { "no" },
        paths
    )
}

fn render_lineage_span(finding: &leaklens_core::Finding) -> String {
    if let (Some(first_commit), Some(last_commit)) = (
        finding.lineage.first_seen_commit.as_ref(),
        finding.lineage.last_seen_commit.as_ref(),
    ) {
        format!(
            "<span>first {} / last {}</span>",
            escape_html(first_commit),
            escape_html(last_commit)
        )
    } else {
        String::new()
    }
}
