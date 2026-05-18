use std::sync::Arc;

use crate::grpc::ctl::nftblockd::StatusSummary;
use crate::utils::status::NftblockdStatus;
use crate::{
    grpc::ctl::nftblockd::{Stats, status_service_server::StatusService},
    utils::stats::Stats as StatsInfo,
};

use crate::error::AppError;
use tokio::sync::RwLock;
use tonic::{Request, Response, Status};

pub enum Command {
    Flush {
        respond_to: tokio::sync::oneshot::Sender<Result<(), AppError>>,
    },
    Reload {
        respond_to: tokio::sync::oneshot::Sender<Result<(), AppError>>,
    },
}

pub struct ServiceStatusStruct {
    pub status: Arc<RwLock<NftblockdStatus>>,
    pub stats: Arc<RwLock<StatsInfo>>,
    pub command_channel: tokio::sync::mpsc::Sender<Command>,
}

#[tonic::async_trait]
impl StatusService for ServiceStatusStruct {
    async fn get_status(&self, _request: Request<()>) -> Result<Response<StatusSummary>, Status> {
        let status = StatusSummary::from(self.status.read().await.clone());
        Ok(Response::new(status))
    }

    async fn get_drop_stats(&self, _request: Request<()>) -> Result<Response<Stats>, Status> {
        let reply = Stats::from(self.stats.read().await.clone());
        Ok(Response::new(reply))
    }

    async fn reload_table(&self, _request: Request<()>) -> Result<Response<StatusSummary>, Status> {
        let chan = tokio::sync::oneshot::channel();
        self.command_channel
            .send(Command::Reload { respond_to: chan.0 })
            .await
            .ok();
        match chan.1.await {
            Ok(Ok(())) => Ok(Response::new(StatusSummary {
                is_ok: true,
                status: "Table reloaded".to_string(),
            })),
            Ok(Err(e)) => Ok(Response::new(StatusSummary {
                is_ok: false,
                status: e.to_string(),
            })),
            Err(e) => Ok(Response::new(StatusSummary {
                is_ok: false,
                status: e.to_string(),
            })),
        }
    }

    async fn flush_table(&self, _request: Request<()>) -> Result<Response<StatusSummary>, Status> {
        let chan = tokio::sync::oneshot::channel();
        self.command_channel
            .send(Command::Flush { respond_to: chan.0 })
            .await
            .ok();

        match chan.1.await {
            Ok(Ok(())) => Ok(Response::new(StatusSummary {
                is_ok: true,
                status: "Table flushed".to_string(),
            })),
            Ok(Err(e)) => Ok(Response::new(StatusSummary {
                is_ok: false,
                status: e.to_string(),
            })),
            Err(e) => Ok(Response::new(StatusSummary {
                is_ok: false,
                status: e.to_string(),
            })),
        }
    }
}
