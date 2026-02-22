use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LatticeError {
    InvalidParameter(String),
    VerificationFailed(String),
    Ring(String),
    RangeProof(String),
    Mining(String),
}

impl fmt::Display for LatticeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParameter(msg) => write!(f, "invalid parameter: {msg}"),
            Self::VerificationFailed(msg) => write!(f, "verification failed: {msg}"),
            Self::Ring(msg) => write!(f, "ring error: {msg}"),
            Self::RangeProof(msg) => write!(f, "range proof error: {msg}"),
            Self::Mining(msg) => write!(f, "mining error: {msg}"),
        }
    }
}

impl std::error::Error for LatticeError {}
