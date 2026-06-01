mod auth;
mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "detour", version, about = "Cloud-to-local traffic routing")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print environment values for a remote service
    Env(commands::env::EnvArgs),
    /// Run a local process with remote runtime defaults
    Run(commands::run::RunArgs),
    /// Start a tunnel session
    Start(commands::start::StartArgs),
    /// Show status of the current tunnel session
    Status(commands::status::StatusArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Env(args) => commands::env::run(args).await,
        Command::Run(args) => commands::run::run(args).await,
        Command::Start(args) => commands::start::run(args).await,
        Command::Status(args) => commands::status::run(args).await,
    }
}
