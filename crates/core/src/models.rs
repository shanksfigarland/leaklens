use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationState {
    NotAttempted,
    OfflineHeuristic,
    Valid,
    Invalid,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiTriage {
    pub explanation: String,
    pub likely_real_secret: bool,
    pub next_steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FindingLineage {
    #[serde(default)]
    pub present_in_working_tree: bool,
    #[serde(default)]
    pub seen_in_history: bool,
    #[serde(default)]
    pub occurrence_count: usize,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub first_seen_commit: Option<String>,
    #[serde(default)]
    pub first_seen_author: Option<String>,
    #[serde(default)]
    pub first_seen_at: Option<String>,
    #[serde(default)]
    pub last_seen_commit: Option<String>,
    #[serde(default)]
    pub last_seen_author: Option<String>,
    #[serde(default)]
    pub last_seen_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub fingerprint: String,
    #[serde(default)]
    pub incident_id: String,
    pub detector_id: String,
    pub detector_name: String,
    pub secret_type: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub file_path: String,
    #[serde(default)]
    pub relative_path: String,
    #[serde(default)]
    pub source_origin: String,
    pub file_size: u64,
    pub line: Option<usize>,
    pub start_column: Option<usize>,
    pub end_column: Option<usize>,
    #[serde(default)]
    pub risk_score: u8,
    #[serde(default)]
    pub entropy: Option<f32>,
    pub redacted_secret: String,
    pub context: String,
    pub keywords: Vec<String>,
    pub validation: ValidationState,
    pub metadata: BTreeMap<String, String>,
    #[serde(default)]
    pub lineage: FindingLineage,
    pub ai_triage: Option<AiTriage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCoverage {
    pub source_type: String,
    pub ai_triage_enabled: bool,
    #[serde(default = "default_true")]
    pub recursive: bool,
    #[serde(default)]
    pub max_depth: Option<usize>,
    pub files_skipped_large: usize,
    pub files_skipped_binary: usize,
    pub files_skipped_read_error: usize,
    #[serde(default)]
    pub files_skipped_custom_ignore: usize,
    #[serde(default)]
    pub findings_suppressed_baseline: usize,
    pub ignored_directories: Vec<String>,
    #[serde(default)]
    pub custom_ignore_patterns: Vec<String>,
    #[serde(default)]
    pub include_path_patterns: Vec<String>,
    #[serde(default)]
    pub exclude_path_patterns: Vec<String>,
    pub max_file_size_bytes: u64,
    #[serde(default)]
    pub history_commits_scanned: usize,
    #[serde(default)]
    pub history_authors_observed: usize,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub files_scanned: usize,
    pub bytes_scanned: u64,
    pub findings_total: usize,
    #[serde(default)]
    pub incidents_total: usize,
    #[serde(default)]
    pub highest_risk_score: u8,
    pub by_severity: BTreeMap<String, usize>,
    #[serde(default)]
    pub by_confidence: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub report_version: u32,
    pub tool: String,
    pub generated_at: String,
    pub target: String,
    pub executive_summary: String,
    pub coverage: ScanCoverage,
    pub summary: ScanSummary,
    pub recommendations: Vec<String>,
    pub findings: Vec<Finding>,
}
