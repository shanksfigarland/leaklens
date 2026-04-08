use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use leaklens_ai::{AiTriageProvider, HeuristicAiTriageProvider};
use leaklens_core::{looks_like_git_repo, scan_git_repo, scan_path, GitScanOptions, ScanOptions};
use leaklens_detectors::default_detectors;
use leaklens_reporters::{write_html_report, write_json_report, write_sarif_report};

const BLUE: &str = "\x1b[38;5;75m";
const CYAN: &str = "\x1b[38;5;117m";
const MUTED: &str = "\x1b[38;5;110m";
const GREEN: &str = "\x1b[38;5;78m";
const YELLOW: &str = "\x1b[38;5;221m";
const ORANGE: &str = "\x1b[38;5;215m";
const RED: &str = "\x1b[38;5;203m";
const WHITE: &str = "\x1b[38;5;255m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";
const BANNER: &str = r#"
 _                _      _                    
| |    ___   __ _| | __ | |    ___ _ __  ___ 
| |   / _ \ / _` | |/ / | |   / _ \ '_ \/ __|
| |__|  __/| (_| |   <  | |__|  __/ | | \__ \
|_____\___| \__,_|_|\_\ |_____\___|_| |_|___/
"#;

#[derive(Parser, Debug)]
#[command(name = "leaklens", version, about = "AI-assisted secret exposure scanner")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Scan(ScanArgs),
    #[command(hide = true)]
    Git(GitScanArgs),
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum ScanMode {
    Auto,
    Filesystem,
    Git,
}

#[derive(Args, Debug)]
struct ScanArgs {
    /// Path to scan.
    path: PathBuf,

    /// Where to write the JSON report.
    #[arg(long, short = 'j')]
    json: Option<PathBuf>,

    /// Where to write the HTML report.
    #[arg(long)]
    html: Option<PathBuf>,

    /// Maximum file size to scan in megabytes.
    #[arg(long, default_value_t = 4)]
    max_file_size_mb: u64,

    /// Disable heuristic AI triage.
    #[arg(long)]
    no_ai: bool,

    /// Path to an ignore file with one wildcard pattern per line.
    #[arg(long, short = 'i', visible_alias = "ignore")]
    ignore_file: Option<PathBuf>,

    /// Path to a prior LeakLens JSON report used as a baseline.
    #[arg(long, short = 'b')]
    baseline: Option<PathBuf>,

    /// Where to write the SARIF report.
    #[arg(long, short = 's')]
    sarif: Option<PathBuf>,

    /// Print the console summary only and skip writing JSON/HTML/SARIF reports.
    #[arg(long)]
    summary_only: bool,

    /// Disable recursive directory scanning.
    #[arg(long)]
    no_recursive: bool,

    /// Maximum subdirectory depth below the target root. `0` means only files directly inside the target.
    #[arg(long)]
    max_depth: Option<usize>,

    /// Include only files whose relative paths match one of these wildcard patterns. Repeatable.
    #[arg(long)]
    include: Vec<String>,

    /// Exclude files whose relative paths match one of these wildcard patterns. Repeatable.
    #[arg(long)]
    exclude: Vec<String>,

    /// Scan mode. Auto chooses git when the path is a git repo, otherwise filesystem.
    #[arg(long, value_enum, default_value_t = ScanMode::Auto)]
    mode: ScanMode,

    /// Include git history when scanning a git repository.
    #[arg(long)]
    history: bool,

    /// Scan only git history, not the current working tree.
    #[arg(long)]
    history_only: bool,

    /// Maximum number of commits to inspect when history scanning is enabled.
    #[arg(long, default_value_t = 25)]
    max_history_commits: usize,
}

#[derive(Args, Debug)]
struct GitScanArgs {
    /// Git repository path.
    repo: PathBuf,

    /// Where to write the JSON report.
    #[arg(long)]
    json: Option<PathBuf>,

    /// Where to write the HTML report.
    #[arg(long)]
    html: Option<PathBuf>,

    /// Maximum file size to scan in megabytes.
    #[arg(long, default_value_t = 4)]
    max_file_size_mb: u64,

    /// Disable heuristic AI triage.
    #[arg(long)]
    no_ai: bool,

    /// Path to an ignore file with one wildcard pattern per line.
    #[arg(long)]
    ignore_file: Option<PathBuf>,

    /// Path to a prior LeakLens JSON report used as a baseline.
    #[arg(long)]
    baseline: Option<PathBuf>,

    /// Where to write the SARIF report.
    #[arg(long)]
    sarif: Option<PathBuf>,

    /// Print the console summary only and skip writing JSON/HTML/SARIF reports.
    #[arg(long)]
    summary_only: bool,

    /// Disable recursive directory scanning when using the hidden legacy command.
    #[arg(long)]
    no_recursive: bool,

    /// Maximum subdirectory depth below the target root when using the hidden legacy command.
    #[arg(long)]
    max_depth: Option<usize>,

    /// Include only files whose relative paths match one of these wildcard patterns. Repeatable.
    #[arg(long)]
    include: Vec<String>,

    /// Exclude files whose relative paths match one of these wildcard patterns. Repeatable.
    #[arg(long)]
    exclude: Vec<String>,

    /// Skip working tree files.
    #[arg(long)]
    no_working_tree: bool,

    /// Skip historical commits.
    #[arg(long)]
    no_history: bool,

    /// Maximum number of commits to inspect from history.
    #[arg(long, default_value_t = 25)]
    max_history_commits: usize,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan(args) => run_scan(args)?,
        Commands::Git(args) => run_git_scan(args)?,
    }

    Ok(())
}

fn run_scan(args: ScanArgs) -> Result<()> {
    let json_output = args
        .json
        .unwrap_or_else(|| PathBuf::from(".\\reports\\leaklens-report.json"));
    let html_output = args
        .html
        .unwrap_or_else(|| PathBuf::from(".\\reports\\leaklens-report.html"));

    let detectors = default_detectors();
    let options = build_scan_options(
        args.max_file_size_mb,
        !args.no_ai,
        args.ignore_file.as_ref(),
        args.baseline.as_ref(),
        !args.no_recursive,
        args.max_depth,
        args.include,
        args.exclude,
    )?;

    let mode = match args.mode {
        ScanMode::Auto => {
            if looks_like_git_repo(&args.path) {
                ScanMode::Git
            } else {
                ScanMode::Filesystem
            }
        }
        explicit => explicit,
    };

    let mut report = match mode {
        ScanMode::Filesystem => {
            if args.history || args.history_only {
                anyhow::bail!("--history and --history-only only apply to git repository scans");
            }
            scan_path(&args.path, &detectors, &options)?
        }
        ScanMode::Git => {
            let git_options = GitScanOptions {
                include_working_tree: !args.history_only,
                include_history: args.history || args.history_only,
                max_history_commits: args.max_history_commits,
            };
            scan_git_repo(&args.path, &detectors, &options, &git_options)?
        }
        ScanMode::Auto => unreachable!(),
    };

    if !args.no_ai {
        HeuristicAiTriageProvider.enrich_report(&mut report);
    }

    if !args.summary_only {
        write_json_report(&json_output, &report)?;
        write_html_report(&html_output, &report)?;
        if let Some(path) = args.sarif.as_ref() {
            write_sarif_report(path, &report)?;
        }
    }

    print_summary(
        &report,
        if args.summary_only { None } else { Some(&json_output) },
        if args.summary_only { None } else { Some(&html_output) },
        if args.summary_only { None } else { args.sarif.as_ref() },
    );
    Ok(())
}

fn run_git_scan(args: GitScanArgs) -> Result<()> {
    let json_output = args
        .json
        .unwrap_or_else(|| PathBuf::from(".\\reports\\leaklens-git-report.json"));
    let html_output = args
        .html
        .unwrap_or_else(|| PathBuf::from(".\\reports\\leaklens-git-report.html"));

    let detectors = default_detectors();
    let options = build_scan_options(
        args.max_file_size_mb,
        !args.no_ai,
        args.ignore_file.as_ref(),
        args.baseline.as_ref(),
        !args.no_recursive,
        args.max_depth,
        args.include,
        args.exclude,
    )?;
    let git_options = GitScanOptions {
        include_working_tree: !args.no_working_tree,
        include_history: !args.no_history,
        max_history_commits: args.max_history_commits,
    };

    let mut report = scan_git_repo(&args.repo, &detectors, &options, &git_options)?;

    if !args.no_ai {
        HeuristicAiTriageProvider.enrich_report(&mut report);
    }

    if !args.summary_only {
        write_json_report(&json_output, &report)?;
        write_html_report(&html_output, &report)?;
        if let Some(path) = args.sarif.as_ref() {
            write_sarif_report(path, &report)?;
        }
    }

    print_summary(
        &report,
        if args.summary_only { None } else { Some(&json_output) },
        if args.summary_only { None } else { Some(&html_output) },
        if args.summary_only { None } else { args.sarif.as_ref() },
    );
    Ok(())
}

fn print_summary(
    report: &leaklens_core::ScanReport,
    json_output: Option<&PathBuf>,
    html_output: Option<&PathBuf>,
    sarif_output: Option<&PathBuf>,
) {
    println!("{BLUE}{BANNER}{RESET}");
    println!("{MUTED}AI-assisted secret exposure scanner{RESET}");
    println!("{CYAN}------------------------------------------------------------{RESET}");
    println!("{MUTED}Source      :{RESET} {WHITE}{}{RESET}", report.coverage.source_type);
    println!("{MUTED}Target      :{RESET} {WHITE}{}{RESET}", report.target);
    println!("{MUTED}Files       :{RESET} {WHITE}{}{RESET}", report.summary.files_scanned);
    println!("{MUTED}Bytes       :{RESET} {WHITE}{}{RESET}", report.summary.bytes_scanned);
    println!("{MUTED}Incidents   :{RESET} {WHITE}{}{RESET}", report.summary.incidents_total);
    println!(
        "{MUTED}Findings    :{RESET} {}{}{RESET}",
        color_for_total_findings(report.summary.findings_total),
        report.summary.findings_total
    );
    println!("{MUTED}Top risk    :{RESET} {WHITE}{}{RESET}", report.summary.highest_risk_score);
    println!(
        "{MUTED}AI triage   :{RESET} {}{}{RESET}",
        if report.coverage.ai_triage_enabled {
            GREEN
        } else {
            MUTED
        },
        if report.coverage.ai_triage_enabled {
            "enabled"
        } else {
            "disabled"
        }
    );

    if !report.summary.by_severity.is_empty() {
        println!("{MUTED}Severity    :{RESET} {}", format_severity_counts(report));
    }
    if !report.summary.by_confidence.is_empty() {
        println!("{MUTED}Confidence  :{RESET} {}", format_confidence_counts(report));
    }
    if report.coverage.history_commits_scanned > 0 {
        println!(
            "{MUTED}History     :{RESET} {WHITE}{} commit(s), {} author(s){RESET}",
            report.coverage.history_commits_scanned,
            report.coverage.history_authors_observed
        );
    }
    if report.coverage.files_skipped_custom_ignore > 0 {
        println!(
            "{MUTED}Filtered    :{RESET} {YELLOW}{} file(s) skipped by path filters{RESET}",
            report.coverage.files_skipped_custom_ignore
        );
    }
    if report.coverage.findings_suppressed_baseline > 0 {
        println!(
            "{MUTED}Baseline    :{RESET} {YELLOW}{} finding(s) suppressed by baseline{RESET}",
            report.coverage.findings_suppressed_baseline
        );
    }

    println!("{CYAN}------------------------------------------------------------{RESET}");
    println!("{BOLD}{WHITE}{}{RESET}", report.executive_summary);
    println!("{CYAN}------------------------------------------------------------{RESET}");

    if report.findings.is_empty() {
        println!("{GREEN}No findings in the current scan.{RESET}");
    } else {
        println!("{BOLD}{WHITE}Top findings:{RESET}");
        for finding in report.findings.iter().take(5) {
            println!(
                "{}- [{}]{} {WHITE}{}{RESET} {MUTED}:: {}:{}{RESET}",
                color_for_severity(finding.severity),
                finding.severity.as_str().to_ascii_uppercase(),
                RESET,
                finding.title,
                finding.file_path,
                finding.line.unwrap_or_default()
            );
            println!(
                "  {MUTED}value{RESET}  : {CYAN}{}{RESET}",
                finding.redacted_secret
            );
            println!(
                "  {MUTED}risk{RESET}   : {WHITE}{} | {} | {}{RESET}",
                finding.risk_score,
                finding.confidence.as_str(),
                finding.source_origin.replace('_', " ")
            );
            if !finding.context.is_empty() {
                println!(
                    "  {MUTED}context{RESET}: {WHITE}{}{RESET}",
                    finding.context
                );
            }
            if finding.lineage.occurrence_count > 0 {
                println!(
                    "  {MUTED}lineage{RESET}: {WHITE}seen {} time(s), working tree {}, history {}{RESET}",
                    finding.lineage.occurrence_count,
                    yes_no(finding.lineage.present_in_working_tree),
                    yes_no(finding.lineage.seen_in_history)
                );
            }
            if let Some(first_commit) = finding.lineage.first_seen_commit.as_ref() {
                println!(
                    "  {MUTED}first{RESET}  : {WHITE}{} ({}){RESET}",
                    first_commit,
                    finding.lineage.first_seen_author.as_deref().unwrap_or("unknown")
                );
            }
        }
    }

    println!();
    if let Some(path) = json_output {
        println!("{MUTED}JSON report :{RESET} {CYAN}{}{RESET}", path.display());
    }
    if let Some(path) = html_output {
        println!("{MUTED}HTML report :{RESET} {CYAN}{}{RESET}", path.display());
    }
    if let Some(path) = sarif_output {
        println!("{MUTED}SARIF report:{RESET} {CYAN}{}{RESET}", path.display());
    }
}

fn format_severity_counts(report: &leaklens_core::ScanReport) -> String {
    report
        .summary
        .by_severity
        .iter()
        .map(|(severity, count)| {
            format!(
                "{}{}={}{}",
                color_for_severity_name(severity),
                severity.to_ascii_uppercase(),
                count,
                RESET
            )
        })
        .collect::<Vec<_>>()
        .join("  ")
}

fn format_confidence_counts(report: &leaklens_core::ScanReport) -> String {
    report
        .summary
        .by_confidence
        .iter()
        .map(|(confidence, count)| format!("{WHITE}{}={}{}", confidence.to_ascii_uppercase(), count, RESET))
        .collect::<Vec<_>>()
        .join("  ")
}

fn color_for_total_findings(total: usize) -> &'static str {
    match total {
        0 => GREEN,
        1..=2 => YELLOW,
        3..=5 => ORANGE,
        _ => RED,
    }
}

fn color_for_severity_name(severity: &str) -> &'static str {
    match severity {
        "critical" => RED,
        "high" => ORANGE,
        "medium" => YELLOW,
        "low" => GREEN,
        _ => MUTED,
    }
}

fn color_for_severity(severity: leaklens_core::Severity) -> &'static str {
    match severity {
        leaklens_core::Severity::Critical => RED,
        leaklens_core::Severity::High => ORANGE,
        leaklens_core::Severity::Medium => YELLOW,
        leaklens_core::Severity::Low => GREEN,
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn build_scan_options(
    max_file_size_mb: u64,
    ai_triage_enabled: bool,
    ignore_file: Option<&PathBuf>,
    baseline: Option<&PathBuf>,
    recursive: bool,
    max_depth: Option<usize>,
    include_path_patterns: Vec<String>,
    exclude_path_patterns: Vec<String>,
) -> Result<ScanOptions> {
    Ok(ScanOptions {
        max_file_size_bytes: max_file_size_mb * 1024 * 1024,
        ai_triage_enabled,
        recursive,
        max_depth,
        ignore_path_patterns: load_ignore_patterns(ignore_file)?,
        include_path_patterns: normalize_patterns(include_path_patterns),
        exclude_path_patterns: normalize_patterns(exclude_path_patterns),
        baseline_fingerprints: load_baseline_fingerprints(baseline)?,
    })
}

fn load_ignore_patterns(ignore_file: Option<&PathBuf>) -> Result<Vec<String>> {
    let Some(path) = ignore_file else {
        return Ok(Vec::new());
    };

    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read ignore file {}", path.display()))?;

    let patterns = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.to_string())
        .collect::<Vec<_>>();

    Ok(normalize_patterns(patterns))
}

fn load_baseline_fingerprints(baseline: Option<&PathBuf>) -> Result<HashSet<String>> {
    let Some(path) = baseline else {
        return Ok(HashSet::new());
    };

    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read baseline report {}", path.display()))?;

    #[derive(serde::Deserialize)]
    struct BaselineFinding {
        fingerprint: String,
    }

    #[derive(serde::Deserialize)]
    struct BaselineReport {
        findings: Vec<BaselineFinding>,
    }

    let report: BaselineReport = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse baseline report {}", path.display()))?;

    Ok(report
        .findings
        .into_iter()
        .map(|finding| finding.fingerprint)
        .collect())
}

fn normalize_patterns(patterns: Vec<String>) -> Vec<String> {
    patterns
        .into_iter()
        .map(|pattern| pattern.replace('\\', "/").to_ascii_lowercase())
        .collect()
}
