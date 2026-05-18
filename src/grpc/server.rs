use std::sync::Arc;

use crate::grpc::ctl::nftblockd::StatusSummary;
use crate::{
    grpc::ctl::nftblockd::{Stats, status_service_server::StatusService},
    utils::stats::Stats as StatsInfo,
};

use tokio::sync::RwLock;
use tonic::{Request, Response, Status};

pub struct ServiceStatusStruct {
    pub stats: Arc<RwLock<StatsInfo>>,
}

#[tonic::async_trait]
impl StatusService for ServiceStatusStruct {
    async fn get_status(&self, request: Request<()>) -> Result<Response<StatusSummary>, Status> {
        let reply = StatusSummary {
            is_ok: true,
            status: format!("Hello!"),
        };
        Ok(Response::new(reply))
    }

    async fn get_drop_stats(&self, request: Request<()>) -> Result<Response<Stats>, Status> {
        let reply = Stats::from(self.stats.read().await);
        Ok(Response::new(reply.into()))
    }

    async fn reload_table(&self, request: Request<()>) -> Result<Response<StatusSummary>, Status> {
        Ok(Response::new(StatusSummary {
            is_ok: true,
            status: format!("Table reloaded"),
        }))
    }

    async fn flush_table(&self, request: Request<()>) -> Result<Response<StatusSummary>, Status> {
        Ok(Response::new(StatusSummary {
            is_ok: true,
            status: format!("Table flushed"),
        }))
    }
}
