use std::fmt;

/// Unified error type for tobira.
/// Thin wrapper around `anyhow::Error` for convenience.
#[allow(dead_code)]
#[derive(Debug)]
pub struct Error(pub anyhow::Error);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Error {}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Error(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error(e.into())
    }
}
