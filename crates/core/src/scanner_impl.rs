use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::detector::{Detector, TextChunk};
use crate::models::{Confidence, Finding, FindingLineage, ScanCoverage, ScanReport, ScanSummary, Severity};

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub max_file_size_bytes: u64,
    pub ai_triage_enabled: bool,
    pub recursive: bool,
    pub max_depth: Option<usize>,
    pub ignore_path_patterns: Vec<String>,
    pub include_path_patterns: Vec<String>,
    pub exclude_path_patterns: Vec<String>,
    pub baseline_fingerprints: HashSet<String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_file_size_bytes: 4 * 1024 * 1024,
            ai_triage_enabled: false,
            recursive: true,
            max_depth: None,
            ignore_path_patterns: Vec::new(),
            include_path_patterns: Vec::new(),
            exclude_path_patterns: Vec::new(),
            baseline_fingerprints: HashSet::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GitScanOptions {
    pub include_working_tree: bool,
    pub include_history: bool,
    pub max_history_commits: usize,
}

impl Default for GitScanOptions {
    fn default() -> Self {
        Self {
            include_working_tree: true,
            include_history: true,
            max_history_commits: 25,
        }
    }
}

#[derive(Default)]
struct ScanAccumulator {
    findings: Vec<Finding>,
    lineages: HashMap<String, LineageAccumulator>,
    location_fingerprints: HashMap<String, usize>,
    seen_fingerprints: HashSet<String>,
    history_authors: HashSet<String>,
    files_scanned: usize,
    bytes_scanned: u64,
    files_skipped_large: usize,
    files_skipped_binary: usize,
    files_skipped_read_error: usize,
    files_skipped_custom_ignore: usize,
    findings_suppressed_baseline: usize,
    history_commits_scanned: usize,
}

#[derive(Debug, Clone)]
struct CandidateOrigin {
    relative_path: String,
    source_origin: String,
    commit: Option<GitCommitInfo>,
}

#[derive(Debug, Clone)]
struct GitCommitInfo {
    hash: String,
    short_hash: String,
    author: String,
    authored_at: String,
}

#[derive(Debug, Default, Clone)]
struct LineageAccumulator {
    present_in_working_tree: bool,
    seen_in_history: bool,
    occurrence_count: usize,
    paths: BTreeSet<String>,
    first_seen_commit: Option<String>,
    first_seen_author: Option<String>,
    first_seen_at: Option<String>,
    last_seen_commit: Option<String>,
    last_seen_author: Option<String>,
    last_seen_at: Option<String>,
}

impl LineageAccumulator {
    fn register(&mut self, origin: &CandidateOrigin) {
        self.occurrence_count += 1;
        self.paths.insert(origin.relative_path.clone());

        match origin.source_origin.as_str() {
            "filesystem" => self.present_in_working_tree = true,
            "git_working_tree" => self.present_in_working_tree = true,
            "git_history" => self.seen_in_history = true,
            _ => {}
        }

        let Some(commit) = origin.commit.as_ref() else {
            return;
        };

        match self.first_seen_at.as_deref() {
            Some(existing) if existing <= commit.authored_at.as_str() => {}
            _ => {
                self.first_seen_commit = Some(commit.short_hash.clone());
                self.first_seen_author = Some(commit.author.clone());
                self.first_seen_at = Some(commit.authored_at.clone());
            }
        }

        match self.last_seen_at.as_deref() {
            Some(existing) if existing >= commit.authored_at.as_str() => {}
            _ => {
                self.last_seen_commit = Some(commit.short_hash.clone());
                self.last_seen_author = Some(commit.author.clone());
                self.last_seen_at = Some(commit.authored_at.clone());
            }
        }
    }

    fn to_model(&self) -> FindingLineage {
        FindingLineage {
            present_in_working_tree: self.present_in_working_tree,
            seen_in_history: self.seen_in_history,
            occurrence_count: self.occurrence_count,
            paths: self.paths.iter().cloned().collect(),
            first_seen_commit: self.first_seen_commit.clone(),
            first_seen_author: self.first_seen_author.clone(),
            first_seen_at: self.first_seen_at.clone(),
            last_seen_commit: self.last_seen_commit.clone(),
            last_seen_author: self.last_seen_author.clone(),
            last_seen_at: self.last_seen_at.clone(),
        }
    }
}

pub fn scan_path(path: impl AsRef<Path>, detectors: &[Box<dyn Detector>], options: &ScanOptions) -> Result<ScanReport> {
    let root = path.as_ref();
    let target = root
        .canonicalize()
        .unwrap_or_else(|_| root.to_path_buf())
        .display()
        .to_string();

    let ignored_directories = default_ignored_directories();
    let mut accumulator = ScanAccumulator::default();
    scan_filesystem_path(root, detectors, options, &ignored_directories, &mut accumulator);
    Ok(finalize_report(
        target,
        "filesystem".to_string(),
        options,
        ignored_directories,
        accumulator,
    ))
}

pub fn scan_git_repo(
    repo_path: impl AsRef<Path>,
    detectors: &[Box<dyn Detector>],
    options: &ScanOptions,
    git_options: &GitScanOptions,
) -> Result<ScanReport> {
    let repo_root = repo_path.as_ref();
    ensure_git_repository(repo_root)?;

    if !git_options.include_working_tree && !git_options.include_history {
        bail!("at least one git scan mode must be enabled");
    }

    let target = repo_root
        .canonicalize()
        .unwrap_or_else(|_| repo_root.to_path_buf())
        .display()
        .to_string();

    let ignored_directories = default_ignored_directories();
    let mut accumulator = ScanAccumulator::default();
    let mut scan_modes = Vec::new();

    if git_options.include_working_tree {
        scan_modes.push("working_tree");
        scan_git_working_tree(repo_root, detectors, options, &mut accumulator)?;
    }

    if git_options.include_history {
        scan_modes.push("history");
        scan_git_history(repo_root, detectors, options, git_options, &mut accumulator)?;
    }

    Ok(finalize_report(
        target,
        format!("git:{}", scan_modes.join("+")),
        options,
        ignored_directories,
        accumulator,
    ))
}

pub fn looks_like_git_repo(repo_path: impl AsRef<Path>) -> bool {
    ensure_git_repository(repo_path.as_ref()).is_ok()
}

fn scan_filesystem_path(
    root: &Path,
    detectors: &[Box<dyn Detector>],
    options: &ScanOptions,
    ignored_directories: &[String],
    accumulator: &mut ScanAccumulator,
) {
    let mut walker = WalkDir::new(root);
    if !options.recursive {
        walker = walker.max_depth(1);
    } else if let Some(depth) = options.max_depth {
        walker = walker.max_depth(depth.saturating_add(1));
    }

    for entry in walker.into_iter().filter_entry(|entry| !is_ignored(entry.path(), ignored_directories)) {
        let entry = match entry {
            Ok(value) => value,
            Err(_) => {
                accumulator.files_skipped_read_error += 1;
                continue;
            }
        };

        if !entry.file_type().is_file() {
            continue;
        }

        let raw = match fs::read(entry.path()) {
            Ok(value) => value,
            Err(_) => {
                accumulator.files_skipped_read_error += 1;
                continue;
            }
        };

        let origin = CandidateOrigin {
            relative_path: entry
                .path()
                .strip_prefix(root)
                .unwrap_or(entry.path())
                .display()
                .to_string(),
            source_origin: "filesystem".to_string(),
            commit: None,
        };

        process_candidate(
            entry.path().display().to_string(),
            raw,
            detectors,
            options,
            accumulator,
            &origin,
        );
    }
}

fn scan_git_working_tree(
    repo_root: &Path,
    detectors: &[Box<dyn Detector>],
    options: &ScanOptions,
    accumulator: &mut ScanAccumulator,
) -> Result<()> {
    let file_list = git_command_bytes(repo_root, &["ls-files", "-z", "--cached", "--others", "--exclude-standard"])?;

    for relative_bytes in file_list.split(|byte| *byte == 0).filter(|part| !part.is_empty()) {
        let relative_path = String::from_utf8_lossy(relative_bytes).to_string();
        let absolute_path = repo_root.join(&relative_path);
        let raw = match fs::read(&absolute_path) {
            Ok(value) => value,
            Err(_) => {
                accumulator.files_skipped_read_error += 1;
                continue;
            }
        };

        let origin = CandidateOrigin {
            relative_path,
            source_origin: "git_working_tree".to_string(),
            commit: None,
        };

        process_candidate(
            absolute_path.display().to_string(),
            raw,
            detectors,
            options,
            accumulator,
            &origin,
        );
    }

    Ok(())
}

fn scan_git_history(
    repo_root: &Path,
    detectors: &[Box<dyn Detector>],
    options: &ScanOptions,
    git_options: &GitScanOptions,
    accumulator: &mut ScanAccumulator,
) -> Result<()> {
    let max_count = format!("--max-count={}", git_options.max_history_commits);
    let commit_output = git_command_text(repo_root, &["rev-list", "--all", &max_count])?;

    for commit_hash in commit_output.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let commit = git_commit_info(repo_root, commit_hash)?;
        accumulator.history_commits_scanned += 1;
        accumulator.history_authors.insert(commit.author.clone());

        let file_list = git_command_bytes(repo_root, &["ls-tree", "-r", "--name-only", "-z", commit_hash])?;

        for relative_bytes in file_list.split(|byte| *byte == 0).filter(|part| !part.is_empty()) {
            let relative_path = String::from_utf8_lossy(relative_bytes).to_string();
            let spec = format!("{}:{}", commit.hash, relative_path);
            let raw = match git_command_bytes(repo_root, &["show", "--no-textconv", &spec]) {
                Ok(value) => value,
                Err(_) => {
                    accumulator.files_skipped_read_error += 1;
                    continue;
                }
            };

            let display_path = format!("{}@{}:{}", repo_root.display(), commit.short_hash, relative_path);
            let origin = CandidateOrigin {
                relative_path,
                source_origin: "git_history".to_string(),
                commit: Some(commit.clone()),
            };

            process_candidate(display_path, raw, detectors, options, accumulator, &origin);
        }
    }

    Ok(())
}

fn process_candidate(
    display_path: String,
    raw: Vec<u8>,
    detectors: &[Box<dyn Detector>],
    options: &ScanOptions,
    accumulator: &mut ScanAccumulator,
    origin: &CandidateOrigin,
) {
    let normalized_path = normalize_path(&origin.relative_path);

    if exceeds_depth_limit(&normalized_path, options) {
        accumulator.files_skipped_custom_ignore += 1;
        return;
    }

    if !options.include_path_patterns.is_empty()
        && !matches_any_pattern(&normalized_path, &options.include_path_patterns)
    {
        accumulator.files_skipped_custom_ignore += 1;
        return;
    }

    if matches_any_pattern(&normalized_path, &options.exclude_path_patterns)
        || matches_any_pattern(&normalized_path, &options.ignore_path_patterns)
    {
        accumulator.files_skipped_custom_ignore += 1;
        return;
    }

    let file_size = raw.len() as u64;
    if file_size > options.max_file_size_bytes {
        accumulator.files_skipped_large += 1;
        return;
    }

    if is_probably_binary(&raw) {
        accumulator.files_skipped_binary += 1;
        return;
    }

    let chunk = TextChunk {
        path: display_path,
        content: String::from_utf8_lossy(&raw).to_string(),
        file_size,
    };

    accumulator.files_scanned += 1;
    accumulator.bytes_scanned += file_size;

    let lowered = chunk.content.to_ascii_lowercase();

    for detector in detectors {
        let should_run = detector.keywords().is_empty()
            || detector
                .keywords()
                .iter()
                .any(|keyword| lowered.contains(*keyword));

        if !should_run {
            continue;
        }

        for draft in detector.detect(&chunk) {
            let fingerprint = fingerprint(&chunk.path, draft.line, &draft.detector_id, &draft.redacted_secret);
            if options.baseline_fingerprints.contains(&fingerprint) {
                accumulator.findings_suppressed_baseline += 1;
                continue;
            }
            if !accumulator.seen_fingerprints.insert(fingerprint.clone()) {
                continue;
            }

            let incident_id = lineage_key(&draft.detector_id, &draft.raw_secret);
            let entropy = shannon_entropy(&draft.raw_secret);
            let (severity, confidence, risk_score) =
                score_draft(draft.severity, draft.confidence, &normalized_path, &origin.source_origin, entropy);
            let mut metadata = draft.metadata;
            metadata.insert("source_origin".to_string(), origin.source_origin.clone());
            metadata.insert("entropy".to_string(), format!("{entropy:.2}"));
            if let Some(commit) = origin.commit.as_ref() {
                metadata.insert("commit".to_string(), commit.hash.clone());
                metadata.insert("commit_short".to_string(), commit.short_hash.clone());
                metadata.insert("commit_author".to_string(), commit.author.clone());
                metadata.insert("commit_date".to_string(), commit.authored_at.clone());
            }

            let candidate = Finding {
                fingerprint,
                incident_id,
                detector_id: draft.detector_id,
                detector_name: draft.detector_name,
                secret_type: draft.secret_type,
                title: draft.title,
                description: draft.description,
                severity,
                confidence,
                file_path: chunk.path.clone(),
                relative_path: origin.relative_path.clone(),
                source_origin: origin.source_origin.clone(),
                file_size: chunk.file_size,
                line: draft.line,
                start_column: draft.start_column,
                end_column: draft.end_column,
                risk_score,
                entropy: Some(round_entropy(entropy)),
                redacted_secret: draft.redacted_secret,
                context: draft.context,
                keywords: draft.keywords,
                validation: draft.validation,
                metadata,
                lineage: FindingLineage::default(),
                ai_triage: None,
            };

            let location_key = format!(
                "{}|{}|{}",
                chunk.path,
                candidate.line.unwrap_or_default(),
                candidate.redacted_secret
            );

            if let Some(existing_index) = accumulator.location_fingerprints.get(&location_key).copied() {
                if should_replace_existing(&candidate, &accumulator.findings[existing_index]) {
                    accumulator.findings[existing_index] = candidate;
                }
                continue;
            }

            let lineage = accumulator.lineages.entry(candidate.incident_id.clone()).or_default();
            lineage.register(origin);

            let insert_index = accumulator.findings.len();
            accumulator.location_fingerprints.insert(location_key, insert_index);
            accumulator.findings.push(candidate);
        }
    }
}

fn finalize_report(
    target: String,
    source_type: String,
    options: &ScanOptions,
    ignored_directories: Vec<String>,
    mut accumulator: ScanAccumulator,
) -> ScanReport {
    for finding in &mut accumulator.findings {
        if let Some(lineage) = accumulator.lineages.get(&finding.incident_id) {
            finding.lineage = lineage.to_model();
            if finding.lineage.present_in_working_tree && finding.lineage.seen_in_history {
                finding.risk_score = finding.risk_score.saturating_add(8).min(100);
            }
            if finding.lineage.occurrence_count > 1 {
                finding.risk_score = finding.risk_score.saturating_add(4).min(100);
            }
        }
    }

    accumulator.findings.sort_by(|left, right| {
        severity_rank(left.severity)
            .cmp(&severity_rank(right.severity))
            .then_with(|| right.risk_score.cmp(&left.risk_score))
            .then_with(|| left.file_path.cmp(&right.file_path))
            .then_with(|| left.line.cmp(&right.line))
    });

    let by_severity = build_severity_counts(&accumulator.findings);
    let by_confidence = build_confidence_counts(&accumulator.findings);
    let recommendations = build_recommendations(&accumulator.findings);
    let incidents_total = accumulator.lineages.len();
    let highest_risk_score = accumulator
        .findings
        .iter()
        .map(|finding| finding.risk_score)
        .max()
        .unwrap_or_default();

    let executive_summary = if accumulator.findings.is_empty() {
        format!(
            "LeakLens scanned {} files and did not find any obvious secret exposures.",
            accumulator.files_scanned
        )
    } else {
        format!(
            "LeakLens found {} potential exposure{} across {} incident{}.",
            accumulator.findings.len(),
            if accumulator.findings.len() == 1 { "" } else { "s" },
            incidents_total,
            if incidents_total == 1 { "" } else { "s" }
        )
    };

    ScanReport {
        report_version: 2,
        tool: "LeakLens".to_string(),
        generated_at: Utc::now().to_rfc3339(),
        target,
        executive_summary,
        coverage: ScanCoverage {
            source_type,
            ai_triage_enabled: options.ai_triage_enabled,
            recursive: options.recursive,
            max_depth: options.max_depth,
            files_skipped_large: accumulator.files_skipped_large,
            files_skipped_binary: accumulator.files_skipped_binary,
            files_skipped_read_error: accumulator.files_skipped_read_error,
            files_skipped_custom_ignore: accumulator.files_skipped_custom_ignore,
            findings_suppressed_baseline: accumulator.findings_suppressed_baseline,
            ignored_directories,
            custom_ignore_patterns: options.ignore_path_patterns.clone(),
            include_path_patterns: options.include_path_patterns.clone(),
            exclude_path_patterns: options.exclude_path_patterns.clone(),
            max_file_size_bytes: options.max_file_size_bytes,
            history_commits_scanned: accumulator.history_commits_scanned,
            history_authors_observed: accumulator.history_authors.len(),
        },
        summary: ScanSummary {
            files_scanned: accumulator.files_scanned,
            bytes_scanned: accumulator.bytes_scanned,
            findings_total: accumulator.findings.len(),
            incidents_total,
            highest_risk_score,
            by_severity,
            by_confidence,
        },
        recommendations,
        findings: accumulator.findings,
    }
}

fn default_ignored_directories() -> Vec<String> {
    vec![
        ".git".to_string(),
        "node_modules".to_string(),
        "target".to_string(),
        ".venv".to_string(),
        "vendor".to_string(),
        "dist".to_string(),
    ]
}

fn build_severity_counts(findings: &[Finding]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for finding in findings {
        *counts.entry(finding.severity.as_str().to_string()).or_insert(0) += 1;
    }
    counts
}

fn build_confidence_counts(findings: &[Finding]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for finding in findings {
        *counts.entry(finding.confidence.as_str().to_string()).or_insert(0) += 1;
    }
    counts
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
    }
}

fn build_recommendations(findings: &[Finding]) -> Vec<String> {
    let mut recommendations = BTreeSet::new();
    for finding in findings {
        recommendations.insert("Rotate any exposed secrets before merging or deploying affected code.".to_string());
        recommendations.insert("Purge leaked values from git history if they were previously committed.".to_string());

        if finding.lineage.present_in_working_tree && finding.lineage.seen_in_history {
            recommendations.insert("Treat secrets that exist in both working tree and history as ongoing incidents until both locations are cleaned up.".to_string());
        }

        if finding.secret_type.contains("private_key") {
            recommendations.insert("Treat exposed private keys as compromised and replace every dependent trust relationship.".to_string());
        }

        if finding.secret_type.contains("aws")
            || finding.secret_type.contains("github")
            || finding.secret_type.contains("gitlab")
            || finding.secret_type.contains("slack")
            || finding.secret_type.contains("openai")
            || finding.secret_type.contains("anthropic")
            || finding.secret_type.contains("sendgrid")
        {
            recommendations.insert("Review provider audit logs for activity tied to the exposed credential family.".to_string());
        }
    }

    recommendations.into_iter().collect()
}

fn should_replace_existing(candidate: &Finding, existing: &Finding) -> bool {
    let candidate_rank = (
        severity_rank(candidate.severity),
        confidence_rank(candidate.confidence),
        detector_specificity(&candidate.detector_id),
        candidate.risk_score,
    );
    let existing_rank = (
        severity_rank(existing.severity),
        confidence_rank(existing.confidence),
        detector_specificity(&existing.detector_id),
        existing.risk_score,
    );

    candidate_rank.0 < existing_rank.0
        || (candidate_rank.0 == existing_rank.0 && candidate_rank.1 > existing_rank.1)
        || (candidate_rank.0 == existing_rank.0
            && candidate_rank.1 == existing_rank.1
            && candidate_rank.2 > existing_rank.2)
        || (candidate_rank.0 == existing_rank.0
            && candidate_rank.1 == existing_rank.1
            && candidate_rank.2 == existing_rank.2
            && candidate_rank.3 > existing_rank.3)
}

fn confidence_rank(confidence: Confidence) -> u8 {
    match confidence {
        Confidence::High => 3,
        Confidence::Medium => 2,
        Confidence::Low => 1,
    }
}

fn detector_specificity(detector_id: &str) -> u8 {
    match detector_id {
        "generic_secret_assignment" | "bearer_token" => 1,
        _ => 2,
    }
}

fn score_draft(
    severity: Severity,
    confidence: Confidence,
    normalized_path: &str,
    source_origin: &str,
    entropy: f32,
) -> (Severity, Confidence, u8) {
    let docs_like = normalized_path.contains("/docs/")
        || normalized_path.contains("readme")
        || normalized_path.contains("/examples/")
        || normalized_path.contains("/example/")
        || normalized_path.contains("/samples/")
        || normalized_path.contains("/sample/")
        || normalized_path.contains("/test/")
        || normalized_path.contains("/tests/")
        || normalized_path.contains("/fixture/")
        || normalized_path.contains("/fixtures/")
        || normalized_path.contains("/test_data/");

    let runtime_like = normalized_path.ends_with(".env")
        || normalized_path.ends_with(".npmrc")
        || normalized_path.ends_with(".pypirc")
        || normalized_path.ends_with(".pem")
        || normalized_path.ends_with("kubeconfig")
        || normalized_path.contains("credentials")
        || normalized_path.contains("secrets")
        || normalized_path.contains("terraform")
        || normalized_path.contains("tfvars")
        || normalized_path.contains("config")
        || normalized_path.contains("appsettings")
        || normalized_path.contains("docker");

    let mut adjusted_severity = severity;
    let mut adjusted_confidence = confidence;
    let mut risk: u8 = match severity {
        Severity::Critical => 84,
        Severity::High => 70,
        Severity::Medium => 52,
        Severity::Low => 32,
    };

    risk += match confidence {
        Confidence::High => 10,
        Confidence::Medium => 5,
        Confidence::Low => 0,
    };

    if entropy >= 4.25 {
        risk += 10;
        adjusted_confidence = promote_confidence(adjusted_confidence);
    } else if entropy >= 3.7 {
        risk += 6;
    } else if entropy < 2.6 {
        adjusted_confidence = demote_confidence(adjusted_confidence);
    }

    if runtime_like {
        risk += 8;
    }

    if source_origin == "git_working_tree" {
        risk += 6;
    } else if source_origin == "git_history" {
        risk += 3;
    }

    if docs_like {
        risk = risk.saturating_sub(20);
        adjusted_confidence = demote_confidence(adjusted_confidence);
        adjusted_severity = demote_severity(adjusted_severity);
    }

    (adjusted_severity, adjusted_confidence, risk.min(100) as u8)
}

fn promote_confidence(confidence: Confidence) -> Confidence {
    match confidence {
        Confidence::Low => Confidence::Medium,
        Confidence::Medium => Confidence::High,
        Confidence::High => Confidence::High,
    }
}

fn demote_confidence(confidence: Confidence) -> Confidence {
    match confidence {
        Confidence::High => Confidence::Medium,
        Confidence::Medium => Confidence::Low,
        Confidence::Low => Confidence::Low,
    }
}

fn demote_severity(severity: Severity) -> Severity {
    match severity {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        Severity::Low => Severity::Low,
    }
}

fn shannon_entropy(value: &str) -> f32 {
    if value.is_empty() {
        return 0.0;
    }

    let mut counts = HashMap::new();
    for byte in value.bytes() {
        *counts.entry(byte).or_insert(0usize) += 1;
    }

    let len = value.len() as f32;
    counts
        .values()
        .map(|count| {
            let probability = *count as f32 / len;
            -probability * probability.log2()
        })
        .sum()
}

fn round_entropy(value: f32) -> f32 {
    (value * 100.0).round() / 100.0
}

fn fingerprint(path: &str, line: Option<usize>, detector_id: &str, redacted_secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path.as_bytes());
    hasher.update(line.unwrap_or_default().to_le_bytes());
    hasher.update(detector_id.as_bytes());
    hasher.update(redacted_secret.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn lineage_key(detector_id: &str, raw_secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(detector_id.as_bytes());
    hasher.update(raw_secret.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn is_ignored(path: &Path, ignored_directories: &[String]) -> bool {
    path.components().any(|component| {
        let text = component.as_os_str().to_string_lossy();
        ignored_directories.iter().any(|ignored| ignored == &text)
    })
}

fn is_probably_binary(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }

    let sample = &bytes[..bytes.len().min(1024)];
    sample.iter().any(|byte| *byte == 0)
}

fn matches_any_pattern(path: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| wildcard_match(path, pattern))
}

fn exceeds_depth_limit(path: &str, options: &ScanOptions) -> bool {
    let depth = relative_path_depth(path);

    if !options.recursive {
        return depth > 0;
    }

    if let Some(max_depth) = options.max_depth {
        return depth > max_depth;
    }

    false
}

fn relative_path_depth(path: &str) -> usize {
    let normalized = normalize_path(path);
    let parts = normalized
        .split('/')
        .filter(|part| !part.is_empty())
        .count();

    parts.saturating_sub(1)
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/").to_ascii_lowercase()
}

fn wildcard_match(value: &str, pattern: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }

    if pattern == "*" {
        return true;
    }

    let parts = pattern.split('*').filter(|part| !part.is_empty()).collect::<Vec<_>>();
    if parts.is_empty() {
        return true;
    }

    let starts_with_wildcard = pattern.starts_with('*');
    let ends_with_wildcard = pattern.ends_with('*');
    let mut cursor = 0usize;

    for (index, part) in parts.iter().enumerate() {
        if let Some(found_at) = value[cursor..].find(part) {
            let absolute = cursor + found_at;
            if index == 0 && !starts_with_wildcard && absolute != 0 {
                return false;
            }
            cursor = absolute + part.len();
        } else {
            return false;
        }
    }

    if !ends_with_wildcard {
        if let Some(last) = parts.last() {
            return value.ends_with(last);
        }
    }

    true
}

fn ensure_git_repository(repo_root: &Path) -> Result<()> {
    let result = git_command_text(repo_root, &["rev-parse", "--is-inside-work-tree"])?;
    if result.trim() != "true" {
        bail!("{} does not look like a git working tree", repo_root.display());
    }
    Ok(())
}

fn git_commit_info(repo_root: &Path, commit_hash: &str) -> Result<GitCommitInfo> {
    let output = git_command_text(repo_root, &["show", "-s", "--format=%H%x1f%an%x1f%aI", commit_hash])?;
    let parts = output.trim().split('\u{1f}').collect::<Vec<_>>();
    if parts.len() != 3 {
        bail!("git show returned unexpected commit metadata for {}", commit_hash);
    }

    Ok(GitCommitInfo {
        hash: parts[0].to_string(),
        short_hash: short_commit(parts[0]).to_string(),
        author: parts[1].to_string(),
        authored_at: parts[2].to_string(),
    })
}

fn git_command_text(repo_root: &Path, args: &[&str]) -> Result<String> {
    let output = git_command_bytes(repo_root, args)?;
    Ok(String::from_utf8_lossy(&output).to_string())
}

fn git_command_bytes(repo_root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .with_context(|| format!("failed to run git in {}", repo_root.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git {} failed: {}", args.join(" "), stderr.trim());
    }

    Ok(output.stdout)
}

fn short_commit(commit_hash: &str) -> &str {
    &commit_hash[..commit_hash.len().min(8)]
}
