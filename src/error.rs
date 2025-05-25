use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;

/// Represents the different types of errors that can occur in the application.
///
/// Each variant of `AppErrorKind` corresponds to a specific error category
/// and provides an appropriate error message.
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
    #[error("could not parse IP address")]
    ParseError,
}

/// Represents an error that occurred during execution, including an error kind
/// and a detailed message describing the issue.
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
    /// Constructs a new instance of `AppError`.
    ///
    /// # Parameters
    /// - `error_kind`: The specific type of error that occurred.
    /// - `message`: A string containing more details about the issue.
    ///
    /// # Returns
    /// A new `AppError` instance.
    pub fn new(error_kind: AppErrorKind, message: &str) -> Self {
        Self {
            error_kind,
            message: message.to_owned(),
        }
    }
}

impl From<ureq::Error> for AppError {
    /// Converts a `ureq::Error` into an `AppError`.
    ///
    /// # Returns
    /// A new `AppError` with the `RequestError` kind and the corresponding error message.
    fn from(error: ureq::Error) -> Self {
        Self::new(AppErrorKind::RequestError, &error.to_string())
    }
}

impl From<std::io::Error> for AppError {
    /// Converts a `std::io::Error` into an `AppError`.
    ///
    /// # Returns
    /// A new `AppError` with the `FileError` kind and the corresponding error message.
    fn from(value: std::io::Error) -> Self {
        Self::new(AppErrorKind::FileError, &value.to_string())
    }
}

impl From<nftables::helper::NftablesError> for AppError {
    /// Converts an `nftables::helper::NftablesError` into an `AppError`.
    ///
    /// # Returns
    /// A new `AppError` with the `NftablesError` kind and the corresponding error message.
    fn from(value: nftables::helper::NftablesError) -> Self {
        Self::new(AppErrorKind::NftablesError, &value.to_string())
    }
}

impl From<ipnetwork::IpNetworkError> for AppError {
    fn from(value: ipnetwork::IpNetworkError) -> Self {
        Self::new(AppErrorKind::ParseError, &value.to_string())
    }
}