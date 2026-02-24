use std::fmt::Debug;
use thiserror::Error;

/// Represents the different types of errors that can occur in the application.
///
/// Each variant of `AppError` corresponds to a specific error category
/// and provides an appropriate error message.
#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum AppError {
    #[error("request error: {0}")]
    RequestError(String),
    #[error("file error: {0}")]
    FileError(String),
    #[error("nftables failed: {0}")]
    NftablesError(String),
    #[error("could not parse IP address: {0}")]
    ParseError(String),
    #[error("could not parse json: {0}")]
    DeserializeError(String),
    #[error("table {0} must be defined first")]
    TableNotFound(String),
    #[error("chain {0} must be defined first")]
    ChainNotFound(String),
}

impl From<ureq::Error> for AppError {
    /// Converts a `ureq::Error` into an `AppError`.
    ///
    /// # Returns
    /// A new `AppError` with the `RequestError`  and the corresponding error message.
    fn from(error: ureq::Error) -> Self {
        AppError::RequestError(error.to_string())
    }
}

impl From<std::io::Error> for AppError {
    /// Converts a `std::io::Error` into an `AppError`.
    ///
    /// # Returns
    /// A new `AppError` with the `FileError`  and the corresponding error message.
    fn from(value: std::io::Error) -> Self {
        AppError::FileError(value.to_string())
    }
}

impl From<nftables::helper::NftablesError> for AppError {
    /// Converts an `nftables::helper::NftablesError` into an `AppError`.
    ///
    /// # Returns
    /// A new `AppError` with the `NftablesError`  and the corresponding error message.
    fn from(value: nftables::helper::NftablesError) -> Self {
        AppError::NftablesError(value.to_string())
    }
}

/// Converts an `IpNetworkError` into an `AppError`.
///
/// This implementation creates a new `AppError` of  `ParseError`
/// using the string representation of the `IpNetworkError`.
///
/// # Arguments
///
/// * `value` - The `IpNetworkError` to be converted.
///
/// # Returns
///
/// Returns an `AppError` with details about the parsing error.
impl From<ipnetwork::IpNetworkError> for AppError {
    fn from(value: ipnetwork::IpNetworkError) -> Self {
        AppError::ParseError(value.to_string())
    }
}

/// Converts a `serde_json::Error` into an `AppError`.
///
/// This implementation creates a new `AppError` of  `DeserializeError`
/// using the string representation of the `serde_json::Error`.
///
/// # Arguments
///
/// * `value` - The `serde_json::Error` to be converted.
///
/// # Returns
///
/// Returns an `AppError` with details about the deserialization failure.
impl From<serde_json::Error> for AppError {
    fn from(value: serde_json::Error) -> Self {
        AppError::DeserializeError(value.to_string())
    }
}

impl From<std::ffi::NulError> for AppError {
    fn from(value: std::ffi::NulError) -> Self {
        AppError::ParseError(value.to_string())
    }
}