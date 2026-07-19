//! outlook — unofficial Outlook Web calendar CLI.

use clap::{CommandFactory, Parser, Subcommand};

mod auth;
mod calendar;
mod config;
mod oauth;
mod output;
mod owa;
mod session;
mod timezone;
mod unattended;

#[derive(Parser)]
#[command(
    name = "outlook",
    version,
    about = "Query an Outlook Web calendar from the terminal"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Authentication and token lifecycle
    #[command(subcommand)]
    Auth(AuthSubcommand),
    /// Read or update local configuration
    #[command(subcommand)]
    Config(ConfigSubcommand),
    /// Calendar queries
    #[command(subcommand)]
    Calendar(CalendarSubcommand),
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        shell: clap_complete::Shell,
    },
}

#[derive(Subcommand)]
enum AuthSubcommand {
    /// Ensure a usable Outlook session, renewing or signing in when necessary
    Login,
    /// Clear CLI authentication state while preserving configuration
    Logout,
    /// Display local token and session expiration status
    Status,
}

#[derive(Subcommand)]
enum ConfigSubcommand {
    /// Read one setting, or the redacted complete session when KEY is omitted
    Get {
        key: Option<config::ConfigKey>,
        /// Display stored passwords, authenticator keys, cookies, and token values
        #[arg(long)]
        show_secrets: bool,
    },
    /// Set a configuration value; omit VALUE to be prompted
    Set {
        key: config::ConfigKey,
        value: Option<String>,
    },
}

#[derive(Subcommand)]
enum CalendarSubcommand {
    /// List all events in a Sunday-through-Saturday calendar week
    List {
        /// Which week to query
        #[arg(long, value_enum, default_value_t = owa::Week::Current)]
        week: owa::Week,
        /// Emit the unmodified OWA response instead of normalized event JSON
        #[arg(long)]
        raw: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(error) = run(cli) {
        if output::is_broken_pipe(&error) {
            return;
        }
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let store = session::Store::default();
    match cli.command {
        Command::Auth(command) => match command {
            AuthSubcommand::Login => auth::login(&store),
            AuthSubcommand::Logout => auth::logout(&store),
            AuthSubcommand::Status => auth::status(&store),
        },
        Command::Config(command) => match command {
            ConfigSubcommand::Get { key, show_secrets } => config::get(&store, key, show_secrets),
            ConfigSubcommand::Set { key, value } => config::set(&store, key, value),
        },
        Command::Calendar(command) => match command {
            CalendarSubcommand::List { week, raw } => calendar::list(&store, week, raw),
        },
        Command::Completions { shell } => {
            let mut command = Cli::command();
            let binary = command.get_name().to_string();
            clap_complete::generate(shell, &mut command, binary, &mut std::io::stdout());
            Ok(())
        }
    }
}
