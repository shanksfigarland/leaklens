pub mod detector;
pub mod models;
#[path = "scanner_impl.rs"]
pub mod scanner;

pub use detector::{Detector, FindingDraft, TextChunk};
pub use models::{
    AiTriage, Confidence, Finding, FindingLineage, ScanCoverage, ScanReport, ScanSummary, Severity,
    ValidationState,
};
pub use scanner::{looks_like_git_repo, scan_git_repo, scan_path, GitScanOptions, ScanOptions};
