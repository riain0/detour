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
    /// Start a tunnel session
    Start(commands::start::StartArgs),
    /// Show status of the current tunnel session
    Status(commands::status::StatusArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Start(args) => commands::start::run(args).await,
        Command::Status(args) => commands::status::run(args).await,
    }
}
