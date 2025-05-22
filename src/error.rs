use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;

#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum AppErrorKind {
    #[error("Request error")]
    RequestError,
    #[error("File error")]
    FileError,
    #[error("No IPs parsed")]
    NoAddressesParsedError,
    #[error("nftables failed")]
    NftablesError,
}

#[derive(Error, PartialEq, Eq, Clone)]
pub struct AppError {
    pub error_kind: AppErrorKind,
    pub message: String,
}

impl Debug for AppError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "AppError: {}: {}", self.error_kind, self.message)
    }
}

impl Display for AppError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.error_kind, self.message)
    }
}

impl AppError {
    pub fn new(error_kind: AppErrorKind, message: &str) -> Self {
        Self {
            error_kind,
            message: message.to_owned(),
        }
    }
}

impl From<ureq::Error> for AppError {
    fn from(error: ureq::Error) -> Self {
        Self::new(AppErrorKind::RequestError, &error.to_string())
    }
}

impl From<std::io::Error> for AppError {
    fn from(value: std::io::Error) -> Self {
        Self::new(AppErrorKind::FileError, &value.to_string())
    }
}

impl From<nftables::helper::NftablesError> for AppError {
    fn from(value: nftables::helper::NftablesError) -> Self {
        Self::new(AppErrorKind::NftablesError, &value.to_string())
    }
}
