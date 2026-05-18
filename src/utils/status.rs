use crate::{error::AppError, grpc::ctl::nftblockd::StatusSummary};
use std::fmt::Display;

#[derive(Debug, Clone, Default)]
pub enum NftblockdStatus {
    #[default]
    Ok,
    Failed(AppError),
    Pending,
    PreFail(AppError),
}

impl NftblockdStatus {
    pub fn get_status_code(&self) -> i32 {
        match self {
            NftblockdStatus::Ok => 0,
            NftblockdStatus::Pending => 1,
            NftblockdStatus::PreFail(_) => 2,
            NftblockdStatus::Failed(_) => 3,
        }
    }

    pub fn get_status(&self) -> String {
        match self {
            NftblockdStatus::Ok => "ok".to_string(),
            NftblockdStatus::Failed(_) => "failed".to_string(),
            NftblockdStatus::Pending => "pending".to_string(),
            NftblockdStatus::PreFail(_) => "pre-fail".to_string(),
        }
    }

    pub fn get_message(&self) -> String {
        match self {
            NftblockdStatus::Ok | NftblockdStatus::Pending => String::default(),
            NftblockdStatus::Failed(e) | NftblockdStatus::PreFail(e) => e.to_string(),
        }
    }
}

impl Display for NftblockdStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NftblockdStatus::Ok => write!(f, "ok"),
            NftblockdStatus::Failed(e) => write!(f, "failed: {e}"),
            NftblockdStatus::Pending => write!(f, "pending"),
            NftblockdStatus::PreFail(e) => write!(f, "pre-fail: {e}"),
        }
    }
}

impl From<NftblockdStatus> for StatusSummary {
    fn from(status: NftblockdStatus) -> Self {
        StatusSummary {
            status_code: status.get_status_code(),
            status: status.get_status(),
            message: status.get_message(),
        }
    }
}

impl StatusSummary {
    pub fn new_ok(message: &str) -> Self {
        StatusSummary {
            status_code: 0,
            status: "ok".to_string(),
            message: message.to_string(),
        }
    }

    pub fn new_failed(message: &str) -> Self {
        StatusSummary {
            status_code: 3,
            status: "failed".to_string(),
            message: message.to_string(),
        }
    }
}
