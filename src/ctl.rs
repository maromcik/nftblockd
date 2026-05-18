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
    #[arg(short = 'j', long = "json", action = clap::ArgAction::SetTrue)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    Reload,
    Flush,
    Status,
    Stats,
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let cli = Cli::parse();
    let mut client = StatusServiceClient::connect("unix:///run/nftblockd.sock").await?;

    match cli.command {
        Commands::Reload => todo!(),
        Commands::Flush => todo!(),
        Commands::Status => {
            let request = tonic::Request::new({});
            let response = client.get_status(request).await?;
            print_response(response, cli.json)?;
        }
        Commands::Stats => {
            let request = tonic::Request::new({});
            let response = client.get_drop_stats(request).await?;
            print_response(response, cli.json)?;
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
