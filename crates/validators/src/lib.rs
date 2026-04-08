use leaklens_core::ValidationState;

pub trait Validator: Send + Sync {
    fn id(&self) -> &'static str;
    fn can_validate(&self, detector_id: &str) -> bool;
    fn validate(&self, secret: &str) -> ValidationState;
}

pub struct NoopValidator;

impl Validator for NoopValidator {
    fn id(&self) -> &'static str {
        "noop"
    }

    fn can_validate(&self, _detector_id: &str) -> bool {
        false
    }

    fn validate(&self, _secret: &str) -> ValidationState {
        ValidationState::NotAttempted
    }
}
