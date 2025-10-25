use crate::error::{AppError, AppErrorKind};
use std::fs;

pub mod iptrie;
pub mod network;
pub mod subnet;

pub fn read_ip_set_file<S: AsRef<str>>(path: Option<S>) -> Result<Option<String>, AppError> {
    let data = path.map_or_else(
        || Ok::<Option<String>, AppError>(None),
        |p| {
            let data = fs::read_to_string(p.as_ref()).map_err(|e| {
                AppError::new(
                    AppErrorKind::FileError,
                    format!("{e}: {}", p.as_ref()).as_str(),
                )
            })?;
            Ok(Some(data))
        },
    )?;
    Ok(data)
}
