//! Spawning nmap as a child process and streaming its output.

use std::{
    io::{self, BufRead, BufReader, Read},
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver, Sender},
    thread,
};

use crate::scan::{builder::NmapCommandBuilder, model::NmapScan, parser::NmapParser};

/// How often nmap prints progress lines when the user did not set --stats-every
pub const DEFAULT_STATS_EVERY: &str = "1s";

/// The exact command the scan screen runs, built from the user's scan
#[derive(Clone, Debug)]
pub struct ScanInvocation {
    /// The command as built in the builder, without the flags lazynmap adds
    pub user_command: String,
    /// The command actually run, including the progress flags lazynmap adds
    pub run_command: String,
    /// nmap arguments of `run_command`
    pub args: Vec<String>,
    /// The flags lazynmap added so the screen can show progress
    pub added_flags: Vec<String>,
    pub sudo: bool,
}

impl ScanInvocation {
    pub fn new(scan: &NmapScan, requires_admin: bool) -> Self {
        let mut run_scan = scan.clone();
        let mut added_flags = Vec::new();
        if run_scan.output.stats_every.is_none() {
            run_scan.output.stats_every = Some(DEFAULT_STATS_EVERY.to_string());
            added_flags.push(format!("--stats-every {DEFAULT_STATS_EVERY}"));
        }
        // Verbosity 1 makes nmap report open ports and scan phases as they happen
        if run_scan.output.verbosity.is_none() {
            run_scan.output.verbosity = Some(1);
            added_flags.push("-v1".to_string());
        }
        // nmap reads runtime keypresses from /dev/tty: it would steal the TUI's keys and
        // leave crossterm blocked in a read for a byte nmap already consumed
        if !run_scan.output.noninteractive {
            run_scan.output.noninteractive = true;
            added_flags.push("--noninteractive".to_string());
        }
        // Already root: sudo would only add a password prompt
        let sudo = requires_admin && unsafe { libc::geteuid() } != 0;
        let run_command = NmapCommandBuilder::build(&run_scan);
        Self {
            user_command: NmapCommandBuilder::build(scan),
            args: nmap_args(&run_command),
            run_command,
            added_flags,
            sudo,
        }
    }

    pub fn display(&self) -> String {
        let prefix = if self.sudo { "sudo " } else { "" };
        format!("{prefix}{}", self.run_command)
    }

    fn command(&self) -> Command {
        let mut command = if self.sudo {
            let mut command = Command::new("sudo");
            // Credentials are cached beforehand with `sudo -v`: never prompt inside the TUI
            command.args(["-n", "nmap"]);
            command
        } else {
            Command::new("nmap")
        };
        command.args(&self.args);
        command
    }
}

pub enum OutputLine {
    Stdout(String),
    Stderr(String),
}

pub struct ScanProcess {
    child: Child,
    pub lines: Receiver<OutputLine>,
}

impl ScanProcess {
    pub fn spawn(invocation: &ScanInvocation) -> io::Result<Self> {
        let mut child = invocation
            .command()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let (sender, lines) = mpsc::channel();
        if let Some(stdout) = child.stdout.take() {
            forward_lines(stdout, sender.clone(), OutputLine::Stdout);
        }
        if let Some(stderr) = child.stderr.take() {
            forward_lines(stderr, sender, OutputLine::Stderr);
        }
        Ok(Self { child, lines })
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    /// Send a signal to the child. sudo forwards SIGINT/SIGTERM to nmap, while SIGKILL
    /// would kill only sudo and leave nmap running, so stopping never uses SIGKILL.
    pub fn signal(&self, signal: libc::c_int) {
        if let Ok(pid) = libc::pid_t::try_from(self.child.id()) {
            unsafe {
                libc::kill(pid, signal);
            }
        }
    }
}

impl Drop for ScanProcess {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            self.signal(libc::SIGTERM);
            let _ = self.child.wait();
        }
    }
}

fn forward_lines<R: Read + Send + 'static>(
    reader: R,
    sender: Sender<OutputLine>,
    wrap: fn(String) -> OutputLine,
) {
    thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        let mut buffer = Vec::new();
        loop {
            buffer.clear();
            match reader.read_until(b'\n', &mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let line = String::from_utf8_lossy(&buffer)
                        .trim_end_matches(['\r', '\n'])
                        .to_string();
                    if sender.send(wrap(line)).is_err() {
                        break;
                    }
                }
            }
        }
    });
}

/// Split a built command into the arguments to pass to nmap, without the leading `nmap`
pub fn nmap_args(command: &str) -> Vec<String> {
    let tokens = NmapParser::tokenize(command);
    if tokens.first().map(|s| s.as_str()) == Some("nmap") {
        tokens.into_iter().skip(1).collect()
    } else {
        tokens
    }
}

/// Cache sudo credentials while the terminal is in normal mode, so the password prompt works
pub fn authenticate_sudo() -> io::Result<bool> {
    Ok(Command::new("sudo").arg("-v").status()?.success())
}
