use std::fmt::Display;

use crate::{error::AppError, grpc::ctl::nftblockd::StatusSummary};

#[derive(Debug, Clone, Default)]
pub enum NftblockdStatus {
    #[default]
    Ok,
    Failed(AppError),
    Pending,
    PreFail(AppError),
}

impl NftblockdStatus {
    pub fn is_ok(&self) -> bool {
        !matches!(self, NftblockdStatus::Failed(_))
    }
}

impl Display for NftblockdStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NftblockdStatus::Ok => write!(f, "ok"),
            NftblockdStatus::Failed(e) => write!(f, "failed: {}", e),
            NftblockdStatus::Pending => write!(f, "pending"),
            NftblockdStatus::PreFail(e) => write!(f, "pre-fail: {}", e),
        }
    }
}


impl From<NftblockdStatus> for StatusSummary {
    fn from(status: NftblockdStatus) -> Self {
        StatusSummary {
            is_ok: status.is_ok(),
            status: status.to_string(),
        }
    }
}
