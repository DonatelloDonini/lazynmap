use std::{error::Error, os::unix::process::CommandExt, process::Command};

use clap::{Parser, Subcommand};

pub mod consts;
pub mod run;
pub mod scan;
pub mod tui;

use run::process::{ScanInvocation, authenticate_sudo, nmap_args};
use scan::model::NmapScan;
use scan::parser::NmapParser;
use tui::{
    app::App,
    scan_screen::{ScanOutcome, ScanScreen},
};

use crate::scan::builder::NmapCommandBuilder;

#[derive(Parser)]
#[command(name = "lazynmap")]
#[command(about = "A TUI for interactively generating nmap commands", long_about = None)]
struct Cli {
    /// Replace lazynmap with nmap when executing, instead of following the scan in the TUI
    #[arg(long, global = true)]
    exec: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate if a string is a valid nmap command
    Validate {
        /// The nmap command string to validate
        command: String,
    },
    /// Launch the TUI with a pre-parsed nmap command
    Parse {
        /// The nmap command string to parse and use
        command: String,
    },
}

fn exec_nmap(scan: &NmapScan, requires_admin: bool) -> Result<(), Box<dyn Error>> {
    let command = NmapCommandBuilder::build(scan);
    let args = nmap_args(&command);
    let error = if requires_admin {
        println!("sudo {}", command);
        Command::new("sudo").arg("nmap").args(&args).exec()
    } else {
        println!("{}", command);
        Command::new("nmap").args(&args).exec()
    };
    Err(format!("Failed to exec: {}", error).into())
}

fn run_scan(scan: &mut NmapScan, exec: bool) -> Result<(), Box<dyn Error>> {
    color_eyre::install()?;
    let mut terminal = ratatui::init();
    let result = run_screens(&mut terminal, scan, exec);
    ratatui::restore();
    match result? {
        Exit::Quit => Ok(()),
        Exit::Exec(requires_admin) => exec_nmap(scan, requires_admin),
        Exit::ScanDone(command, output) => {
            println!("$ {}", command);
            for line in output {
                println!("{}", line);
            }
            Ok(())
        }
    }
}

enum Exit {
    Quit,
    Exec(bool),
    ScanDone(String, Vec<String>),
}

/// Alternate between the command builder and the scan screen until the user quits
fn run_screens(
    terminal: &mut ratatui::DefaultTerminal,
    scan: &mut NmapScan,
    exec: bool,
) -> Result<Exit, Box<dyn Error>> {
    let mut app = App::new(scan);
    let mut sudo_error = None;
    loop {
        app.error = sudo_error.take();
        let result = app.run(terminal)?;
        if !result.execute {
            return Ok(Exit::Quit);
        }
        if exec {
            return Ok(Exit::Exec(result.requires_admin));
        }
        let invocation = ScanInvocation::new(app.scan, result.requires_admin);
        if invocation.sudo {
            // The password prompt needs the normal terminal, not the alternate screen
            ratatui::restore();
            println!("lazynmap needs sudo to run: {}", invocation.display());
            let authenticated = authenticate_sudo();
            *terminal = ratatui::init();
            match authenticated {
                Ok(true) => {}
                Ok(false) => {
                    sudo_error = Some("sudo authentication failed".to_string());
                    continue;
                }
                Err(error) => {
                    sudo_error = Some(format!("could not run sudo: {error}"));
                    continue;
                }
            }
        }
        let display = invocation.display();
        match ScanScreen::new(invocation).run(terminal)? {
            ScanOutcome::Back => continue,
            ScanOutcome::Quit(output) => return Ok(Exit::ScanDone(display, output)),
        }
    }
}

fn validate_command(command: &str) -> Result<(), Box<dyn Error>> {
    match NmapParser::parse(command) {
        Ok(_) => {
            println!("Valid nmap command");
            Ok(())
        }
        Err(e) => {
            eprintln!("Invalid nmap command: {}", e);
            std::process::exit(1);
        }
    }
}

fn parse_and_run(command: &str, exec: bool) -> Result<(), Box<dyn Error>> {
    match NmapParser::parse(command) {
        Ok(mut scan) => run_scan(&mut scan, exec),
        Err(e) => {
            eprintln!("Failed to parse nmap command: {}", e);
            std::process::exit(1);
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Validate { command }) => validate_command(&command),
        Some(Commands::Parse { command }) => parse_and_run(&command, cli.exec),
        None => run_scan(&mut NmapScan::new(), cli.exec),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parse_no_args() {
        let cli = Cli::try_parse_from(["lazynmap"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn test_cli_parse_validate_command() {
        let cli = Cli::try_parse_from(["lazynmap", "validate", "nmap -sS 192.168.1.1"]).unwrap();
        match cli.command {
            Some(Commands::Validate { command }) => {
                assert_eq!(command, "nmap -sS 192.168.1.1");
            }
            _ => panic!("Expected Validate command"),
        }
    }

    #[test]
    fn test_cli_parse_parse_command() {
        let cli = Cli::try_parse_from(["lazynmap", "parse", "nmap -sV example.com"]).unwrap();
        match cli.command {
            Some(Commands::Parse { command }) => {
                assert_eq!(command, "nmap -sV example.com");
            }
            _ => panic!("Expected Parse command"),
        }
    }

    #[test]
    fn test_validate_valid_command() {
        let result = NmapParser::parse("nmap -sS -p 80,443 192.168.1.1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_invalid_flag() {
        let result = NmapParser::parse("nmap --invalid-flag test.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_invalid_value() {
        let result = NmapParser::parse("nmap -iR not-a-number test.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_command_with_multiple_flags() {
        let result = NmapParser::parse("nmap -sS -sV -O -p- -T4 192.168.1.1");
        assert!(result.is_ok());
        let scan = result.unwrap();
        assert_eq!(scan.target_specification.targets, vec!["192.168.1.1"]);
    }

    #[test]
    fn test_parse_command_with_targets() {
        let result = NmapParser::parse("nmap scanme.nmap.org");
        assert!(result.is_ok());
        let scan = result.unwrap();
        assert_eq!(scan.target_specification.targets, vec!["scanme.nmap.org"]);
    }

    #[test]
    fn test_parse_command_with_quotes() {
        let result = NmapParser::parse(r#"nmap --script "http-title" example.com"#);
        assert!(result.is_ok());
        let scan = result.unwrap();
        assert_eq!(scan.nse_script.script, vec!["http-title"]);
    }

    #[test]
    fn test_get_scan_args_strips_nmap() {
        let args = nmap_args("nmap -sS -p 80,443 192.168.1.1");
        assert_eq!(args, vec!["-sS", "-p", "80,443", "192.168.1.1"]);
    }

    #[test]
    fn test_get_scan_args_with_quoted_strings() {
        let args = nmap_args(r#"nmap --script-args "arg1=val1 arg2=val2" 192.168.1.1"#);
        assert_eq!(
            args,
            vec!["--script-args", "arg1=val1 arg2=val2", "192.168.1.1"]
        );
    }
}
