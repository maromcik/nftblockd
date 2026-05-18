use std::fmt;

use nftblockd::{
    error::AppError, grpc::ctl::nftblockd::status_service_client::StatusServiceClient,
};

use clap::{Parser, Subcommand};
use tonic::Response;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Reload {
        #[arg(short = 'j', long = "json", action = clap::ArgAction::SetTrue)]
        json: bool,
    },
    Flush {
        #[arg(short = 'j', long = "json", action = clap::ArgAction::SetTrue)]
        json: bool,
    },
    Status {
        #[arg(short = 'j', long = "json", action = clap::ArgAction::SetTrue)]
        json: bool,
    },
    Stats {
        #[arg(short = 'j', long = "json", action = clap::ArgAction::SetTrue)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let cli = Cli::parse();
    let mut client = StatusServiceClient::connect("unix:///run/nftblockd.sock").await?;

    match cli.command {
        Commands::Reload { json } => {
            let request = tonic::Request::new(());
            let response = client.reload_table(request).await?;
            print_response(response, json)?;
        }
        Commands::Flush { json } => {
            let request = tonic::Request::new(());
            let response = client.flush_table(request).await?;
            print_response(response, json)?;
        }
        Commands::Status { json } => {
            let request = tonic::Request::new(());
            let response = client.get_status(request).await?;
            print_response(response, json)?;
        }
        Commands::Stats { json } => {
            let request = tonic::Request::new(());
            let response = client.get_drop_stats(request).await?;
            print_response(response, json)?;
        }
    }

    Ok(())
}

pub fn print_response<T>(response: Response<T>, json: bool) -> Result<(), AppError>
where
    T: serde::Serialize + fmt::Display,
{
    if json {
        println!("{}", serde_json::to_string(&response.into_inner())?);
    } else {
        println!("{}", response.into_inner());
    }
    Ok(())
}
