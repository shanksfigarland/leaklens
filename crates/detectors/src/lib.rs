use std::collections::BTreeMap;
use std::sync::OnceLock;

use leaklens_core::{
    Confidence, Detector, FindingDraft, Severity, TextChunk, ValidationState,
};
use regex::Regex;

pub fn default_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(GitHubTokenDetector),
        Box::new(AwsAccessKeyDetector),
        Box::new(SlackTokenDetector),
        Box::new(pattern_detector(
            "gitlab_token",
            "GitLab Token",
            &["gitlab", "glpat-"],
            r"\bglpat-[A-Za-z0-9\-_]{20,255}\b",
            "gitlab_token",
            Severity::High,
            Confidence::High,
            "Potential GitLab token",
            "A GitLab token-like credential was found in plaintext.",
        )),
        Box::new(pattern_detector(
            "google_api_key",
            "Google API Key",
            &["google", "aiza"],
            r"\bAIza[0-9A-Za-z\-_]{35}\b",
            "google_api_key",
            Severity::High,
            Confidence::High,
            "Potential Google API key",
            "A Google API key-like value was found in plaintext.",
        )),
        Box::new(pattern_detector(
            "stripe_key",
            "Stripe Key",
            &["stripe", "sk_live_", "sk_test_"],
            r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b",
            "stripe_key",
            Severity::High,
            Confidence::High,
            "Potential Stripe key",
            "A Stripe secret or restricted key-like value was found in plaintext.",
        )),
        Box::new(pattern_detector(
            "openai_api_key",
            "OpenAI API Key",
            &["openai", "sk-proj-", "sk-live-"],
            r"\bsk-(?:proj|live|test)-[A-Za-z0-9_-]{20,}\b",
            "openai_api_key",
            Severity::High,
            Confidence::High,
            "Potential OpenAI API key",
            "An OpenAI API key-like value was found in plaintext.",
        )),
        Box::new(pattern_detector(
            "anthropic_api_key",
            "Anthropic API Key",
            &["anthropic", "sk-ant-"],
            r"\bsk-ant-[A-Za-z0-9_-]{20,}\b",
            "anthropic_api_key",
            Severity::High,
            Confidence::High,
            "Potential Anthropic API key",
            "An Anthropic API key-like value was found in plaintext.",
        )),
        Box::new(pattern_detector(
            "huggingface_token",
            "Hugging Face Token",
            &["huggingface", "hf_"],
            r"\bhf_[A-Za-z0-9]{30,}\b",
            "huggingface_token",
            Severity::High,
            Confidence::High,
            "Potential Hugging Face token",
            "A Hugging Face token-like value was found in plaintext.",
        )),
        Box::new(pattern_detector(
            "sendgrid_api_key",
            "SendGrid API Key",
            &["sendgrid", "sg."],
            r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b",
            "sendgrid_api_key",
            Severity::High,
            Confidence::High,
            "Potential SendGrid API key",
            "A SendGrid API key-like value was found in plaintext.",
        )),
        Box::new(pattern_detector(
            "terraform_cloud_token",
            "Terraform Cloud Token",
            &["terraform", "tfc_"],
            r"\btfc_[A-Za-z0-9]{20,}\b",
            "terraform_cloud_token",
            Severity::High,
            Confidence::High,
            "Potential Terraform Cloud token",
            "A Terraform Cloud token-like value was found in plaintext.",
        )),
        Box::new(pattern_detector(
            "pypi_token",
            "PyPI Token",
            &["pypi-", "pypi"],
            r"\bpypi-[A-Za-z0-9_-]{20,}\b",
            "pypi_token",
            Severity::High,
            Confidence::High,
            "Potential PyPI token",
            "A PyPI token-like value was found in plaintext.",
        )),
        Box::new(pattern_detector(
            "jwt_token",
            "JWT",
            &["bearer", "authorization", "eyj"],
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
            "jwt_token",
            Severity::Medium,
            Confidence::Medium,
            "Potential JWT token",
            "A JWT-like token was found in plaintext.",
        )),
        Box::new(pattern_detector(
            "discord_token",
            "Discord Token",
            &["discord", "mfa.", "discordapp"],
            r"(?:\bmfa\.[A-Za-z0-9_-]{20,}\b)|(?:\b[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{20,}\b)",
            "discord_token",
            Severity::High,
            Confidence::Medium,
            "Potential Discord token",
            "A Discord token-like credential was found in plaintext.",
        )),
        Box::new(pattern_detector(
            "discord_webhook",
            "Discord Webhook",
            &["discord", "webhooks"],
            r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
            "discord_webhook",
            Severity::High,
            Confidence::High,
            "Potential Discord webhook",
            "A Discord webhook URL was found in plaintext.",
        )),
        Box::new(pattern_detector(
            "slack_webhook",
            "Slack Webhook",
            &["slack", "hooks.slack.com/services"],
            r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+",
            "slack_webhook",
            Severity::High,
            Confidence::High,
            "Potential Slack webhook",
            "A Slack webhook URL was found in plaintext.",
        )),
        Box::new(pattern_detector(
            "npm_token",
            "NPM Token",
            &["npm_", "npmjs"],
            r"\bnpm_[A-Za-z0-9]{36}\b",
            "npm_token",
            Severity::High,
            Confidence::High,
            "Potential NPM token",
            "An NPM token-like value was found in plaintext.",
        )),
        Box::new(pattern_detector(
            "azure_connection_string",
            "Azure Connection String",
            &["defaultendpointsprotocol=", "accountkey=", "accountname="],
            r"DefaultEndpointsProtocol=https;AccountName=[^;\s]+;AccountKey=[A-Za-z0-9+/=]{20,};EndpointSuffix=[^;\s]+",
            "azure_connection_string",
            Severity::High,
            Confidence::High,
            "Potential Azure connection string",
            "An Azure storage connection string was found in plaintext.",
        )),
        Box::new(pattern_detector(
            "twilio_key_sid",
            "Twilio API Key SID",
            &["twilio", "sk"],
            r"\bSK[0-9a-fA-F]{32}\b",
            "twilio_key_sid",
            Severity::Medium,
            Confidence::Medium,
            "Potential Twilio key SID",
            "A Twilio API key SID-like value was found in plaintext.",
        )),
        Box::new(pattern_detector(
            "bearer_token",
            "Bearer Token",
            &["bearer "],
            r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]+=*\b",
            "bearer_token",
            Severity::Medium,
            Confidence::Medium,
            "Potential bearer token",
            "A bearer-style authorization value was found in plaintext.",
        )),
        Box::new(pattern_detector(
            "database_url",
            "Database URL",
            &["postgres://", "mysql://", "mongodb://", "redis://", "mssql://"],
            r#"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql)://[^:\s]+:[^@\s]+@[^/\s]+[^\s'"`]*\b"#,
            "database_url",
            Severity::High,
            Confidence::Medium,
            "Potential database connection URL",
            "A database URL with embedded credentials was found in plaintext.",
        )),
        Box::new(PrivateKeyDetector),
        Box::new(GenericAssignmentDetector),
    ]
}

struct GitHubTokenDetector;
struct AwsAccessKeyDetector;
struct SlackTokenDetector;
struct PrivateKeyDetector;
struct GenericAssignmentDetector;
struct PatternDetector {
    id: &'static str,
    name: &'static str,
    keywords: &'static [&'static str],
    regex: Regex,
    secret_type: &'static str,
    severity: Severity,
    confidence: Confidence,
    title: &'static str,
    description: &'static str,
}

impl Detector for PatternDetector {
    fn id(&self) -> &'static str {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn keywords(&self) -> &'static [&'static str] {
        self.keywords
    }

    fn detect(&self, chunk: &TextChunk) -> Vec<FindingDraft> {
        self.regex
            .find_iter(&chunk.content)
            .filter_map(|candidate| {
                let raw = &chunk.content[candidate.start()..candidate.end()];
                if looks_like_placeholder(self.name, raw) {
                    return None;
                }
                Some(draft_from_match(
                    self,
                    chunk,
                    candidate.start(),
                    candidate.end(),
                    self.secret_type,
                    self.severity,
                    self.confidence,
                    self.title,
                    self.description,
                ))
            })
            .collect()
    }
}

fn pattern_detector(
    id: &'static str,
    name: &'static str,
    keywords: &'static [&'static str],
    pattern: &'static str,
    secret_type: &'static str,
    severity: Severity,
    confidence: Confidence,
    title: &'static str,
    description: &'static str,
) -> PatternDetector {
    PatternDetector {
        id,
        name,
        keywords,
        regex: Regex::new(pattern).expect("valid regex"),
        secret_type,
        severity,
        confidence,
        title,
        description,
    }
}

impl Detector for GitHubTokenDetector {
    fn id(&self) -> &'static str {
        "github_token"
    }

    fn name(&self) -> &'static str {
        "GitHub Token"
    }

    fn keywords(&self) -> &'static [&'static str] {
        &["github", "ghp_", "github_token", "gho_", "ghu_"]
    }

    fn detect(&self, chunk: &TextChunk) -> Vec<FindingDraft> {
        github_token_regex()
            .find_iter(&chunk.content)
            .map(|candidate| draft_from_match(
                self,
                chunk,
                candidate.start(),
                candidate.end(),
                "github_token",
                Severity::High,
                Confidence::High,
                "Potential GitHub token",
                "A GitHub token-like credential was found in plaintext.",
            ))
            .collect()
    }
}

impl Detector for AwsAccessKeyDetector {
    fn id(&self) -> &'static str {
        "aws_access_key"
    }

    fn name(&self) -> &'static str {
        "AWS Access Key"
    }

    fn keywords(&self) -> &'static [&'static str] {
        &["aws", "akia", "asia", "secret_access_key"]
    }

    fn detect(&self, chunk: &TextChunk) -> Vec<FindingDraft> {
        aws_access_key_regex()
            .find_iter(&chunk.content)
            .map(|candidate| draft_from_match(
                self,
                chunk,
                candidate.start(),
                candidate.end(),
                "aws_access_key",
                Severity::High,
                Confidence::High,
                "Potential AWS access key",
                "An AWS access key pattern was found in plaintext.",
            ))
            .collect()
    }
}

impl Detector for SlackTokenDetector {
    fn id(&self) -> &'static str {
        "slack_token"
    }

    fn name(&self) -> &'static str {
        "Slack Token"
    }

    fn keywords(&self) -> &'static [&'static str] {
        &["slack", "xoxb-", "xoxp-", "xoxa-"]
    }

    fn detect(&self, chunk: &TextChunk) -> Vec<FindingDraft> {
        slack_token_regex()
            .find_iter(&chunk.content)
            .map(|candidate| draft_from_match(
                self,
                chunk,
                candidate.start(),
                candidate.end(),
                "slack_token",
                Severity::High,
                Confidence::Medium,
                "Potential Slack token",
                "A Slack token-like string was found in plaintext.",
            ))
            .collect()
    }
}

impl Detector for PrivateKeyDetector {
    fn id(&self) -> &'static str {
        "private_key"
    }

    fn name(&self) -> &'static str {
        "Private Key"
    }

    fn keywords(&self) -> &'static [&'static str] {
        &["private key", "begin rsa private key", "begin openssh private key"]
    }

    fn detect(&self, chunk: &TextChunk) -> Vec<FindingDraft> {
        private_key_regex()
            .find_iter(&chunk.content)
            .map(|candidate| draft_from_match(
                self,
                chunk,
                candidate.start(),
                candidate.end(),
                "private_key",
                Severity::Critical,
                Confidence::High,
                "Private key material exposed",
                "A private key header was found. This usually indicates directly exposed key material.",
            ))
            .collect()
    }
}

impl Detector for GenericAssignmentDetector {
    fn id(&self) -> &'static str {
        "generic_secret_assignment"
    }

    fn name(&self) -> &'static str {
        "Generic Secret Assignment"
    }

    fn keywords(&self) -> &'static [&'static str] {
        &[
            "token",
            "secret",
            "password",
            "passwd",
            "api_key",
            "apikey",
            "client_secret",
            "access_key",
            "connection_string",
        ]
    }

    fn detect(&self, chunk: &TextChunk) -> Vec<FindingDraft> {
        generic_assignment_regex()
            .captures_iter(&chunk.content)
            .filter_map(|captures| {
                let full = captures.get(0)?;
                let key_name = captures.get(1)?.as_str();
                let secret_value = captures.get(2)?;
                if looks_like_placeholder(key_name, secret_value.as_str()) {
                    return None;
                }

                let draft = draft_from_span(
                    self,
                    chunk,
                    full.start(),
                    full.end(),
                    secret_value.as_str(),
                    "generic_secret_assignment",
                    Severity::Medium,
                    Confidence::Medium,
                    "Potential plaintext secret assignment",
                    "A secret-looking value was assigned directly in code or config.",
                );
                Some(draft)
            })
            .collect()
    }
}

fn draft_from_match(
    detector: &dyn Detector,
    chunk: &TextChunk,
    start: usize,
    end: usize,
    secret_type: &str,
    severity: Severity,
    confidence: Confidence,
    title: &str,
    description: &str,
) -> FindingDraft {
    let raw_secret = chunk.content[start..end].to_string();
    draft_from_span(
        detector,
        chunk,
        start,
        end,
        &raw_secret,
        secret_type,
        severity,
        confidence,
        title,
        description,
    )
}

fn draft_from_span(
    detector: &dyn Detector,
    chunk: &TextChunk,
    start: usize,
    end: usize,
    raw_secret: &str,
    secret_type: &str,
    severity: Severity,
    confidence: Confidence,
    title: &str,
    description: &str,
) -> FindingDraft {
    let (line, column) = line_and_column(&chunk.content, start);
    let context = line_context(&chunk.content, line);

    FindingDraft {
        detector_id: detector.id().to_string(),
        detector_name: detector.name().to_string(),
        secret_type: secret_type.to_string(),
        title: title.to_string(),
        description: description.to_string(),
        severity,
        confidence,
        line: Some(line),
        start_column: Some(column),
        end_column: Some(column + end.saturating_sub(start)),
        raw_secret: raw_secret.to_string(),
        redacted_secret: redact(raw_secret),
        context,
        keywords: detector.keywords().iter().map(|value| (*value).to_string()).collect(),
        validation: ValidationState::OfflineHeuristic,
        metadata: BTreeMap::new(),
    }
}

fn line_and_column(content: &str, offset: usize) -> (usize, usize) {
    let mut line = 1usize;
    let mut column = 1usize;
    for (index, character) in content.char_indices() {
        if index >= offset {
            break;
        }

        if character == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    (line, column)
}

fn line_context(content: &str, target_line: usize) -> String {
    content
        .lines()
        .nth(target_line.saturating_sub(1))
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn redact(value: &str) -> String {
    let visible_prefix: String = value.chars().take(4).collect();
    let visible_suffix: String = value
        .chars()
        .rev()
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect();

    if value.chars().count() <= 10 {
        format!("{}***", visible_prefix)
    } else {
        format!("{}***{}", visible_prefix, visible_suffix)
    }
}

fn looks_like_placeholder(key_name: &str, value: &str) -> bool {
    let lowered_key = key_name.to_ascii_lowercase();
    let lowered_value = value.to_ascii_lowercase();

    if lowered_value == "placeholder"
        || lowered_value == "example"
        || lowered_value == "changeme"
        || lowered_value == "redacted"
        || lowered_value == "dummy"
        || lowered_value == "sample"
        || lowered_value == "your_token_here"
        || lowered_value == "your_api_key_here"
        || lowered_value == "replace_me"
        || lowered_value.starts_with("example-")
        || lowered_value.starts_with("placeholder-")
        || lowered_value.starts_with("dummy-")
    {
        return true;
    }

    if lowered_key.contains("example") || lowered_key.contains("sample") {
        return true;
    }

    false
}

fn github_token_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{20,255}\b").expect("valid regex"))
}

fn aws_access_key_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b").expect("valid regex"))
}

fn slack_token_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"\bxox(?:a|b|p|r|s)-[A-Za-z0-9-]{10,200}\b").expect("valid regex"))
}

fn private_key_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"-----BEGIN(?: RSA| EC| OPENSSH)? PRIVATE KEY-----").expect("valid regex"))
}

fn generic_assignment_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r#"(?im)\b([A-Za-z0-9_.-]*?(?:secret|token|api[_-]?key|apikey|password|passwd|client[_-]?secret|access[_-]?key|connection[_-]?string)[A-Za-z0-9_.-]*)\b\s*[:=]\s*["']?([A-Za-z0-9_\-/+=:.]{16,})["']?"#,
        )
        .expect("valid regex")
    })
}
