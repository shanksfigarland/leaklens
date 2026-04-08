use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::models::{Confidence, Severity, ValidationState};

#[derive(Debug, Clone)]
pub struct TextChunk {
    pub path: String,
    pub content: String,
    pub file_size: u64,
}

pub trait Detector: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn keywords(&self) -> &'static [&'static str];
    fn detect(&self, chunk: &TextChunk) -> Vec<FindingDraft>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingDraft {
    pub detector_id: String,
    pub detector_name: String,
    pub secret_type: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub line: Option<usize>,
    pub start_column: Option<usize>,
    pub end_column: Option<usize>,
    pub raw_secret: String,
    pub redacted_secret: String,
    pub context: String,
    pub keywords: Vec<String>,
    pub validation: ValidationState,
    pub metadata: BTreeMap<String, String>,
}
