//! Incremental parser for nmap's normal (human readable) output.
//!
//! Lines are fed one at a time while the scan runs, so the state must always be consistent
//! after any prefix of the output. Unknown lines are ignored: the raw log keeps them.

#[derive(Clone, Debug, Default, PartialEq)]
pub enum HostStatus {
    #[default]
    Unknown,
    Up(Option<String>),
    Down,
}

#[derive(Clone, Debug, Default)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: String,
    pub version: String,
    pub scripts: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct HostInfo {
    pub address: String,
    pub hostname: Option<String>,
    pub status: HostStatus,
    pub ports: Vec<PortInfo>,
    pub mac: Option<String>,
    pub os: Option<String>,
    pub notes: Vec<String>,
    pub scripts: Vec<String>,
    /// Whether nmap already printed the final report for this host
    pub reported: bool,
}

impl HostInfo {
    pub fn label(&self) -> String {
        match &self.hostname {
            Some(name) => format!("{} ({})", name, self.address),
            None => self.address.clone(),
        }
    }

    pub fn open_ports(&self) -> usize {
        self.ports.iter().filter(|p| p.state == "open").count()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Phase {
    pub name: String,
    pub started_at: String,
    /// Text after "Completed <phase> at <time>, " e.g. "1.20s elapsed (1000 total ports)"
    pub completed: Option<String>,
}

#[derive(Clone, Copy, Debug, Default)]
enum Context {
    #[default]
    None,
    Host(usize),
    Ports(usize),
    Port(usize, usize),
    HostScripts(usize),
}

#[derive(Clone, Debug, Default)]
pub struct ScanProgress {
    pub hosts: Vec<HostInfo>,
    pub phases: Vec<Phase>,
    pub current_phase: Option<String>,
    pub percent: Option<f64>,
    pub etc: Option<String>,
    pub remaining: Option<String>,
    pub hosts_completed: Option<u32>,
    pub hosts_up: Option<u32>,
    pub summary: Option<String>,
    pub warnings: Vec<String>,
    context: Context,
    /// Host of the latest report: "Host script results:" comes after a blank line
    last_reported: Option<usize>,
}

impl ScanProgress {
    pub fn new() -> Self {
        Self::default()
    }

    /// Lines that only feed the progress bar and would flood the log
    pub fn is_stats_line(line: &str) -> bool {
        line.starts_with("Stats: ") || parse_timing(line).is_some()
    }

    pub fn feed_line(&mut self, line: &str) {
        let line = line.trim_end_matches(['\r', '\n']);

        if line.trim().is_empty() {
            self.context = Context::None;
            return;
        }

        if let Some(rest) = line.strip_prefix("Nmap scan report for ") {
            self.on_report(rest);
            return;
        }
        if let Some(rest) = line.strip_prefix("Discovered open port ") {
            self.on_discovered(rest);
            return;
        }
        if let Some((phase, percent, etc, remaining)) = parse_timing(line) {
            self.current_phase = Some(phase);
            self.percent = Some(percent);
            self.etc = etc;
            self.remaining = remaining;
            return;
        }
        if let Some(rest) = line.strip_prefix("Stats: ") {
            self.on_stats(rest);
            return;
        }
        if let Some(rest) = line.strip_prefix("Initiating ") {
            self.on_initiating(rest);
            return;
        }
        if let Some(rest) = line.strip_prefix("Completed ") {
            self.on_completed(rest);
            return;
        }
        if let Some(rest) = line.strip_prefix("Nmap done: ") {
            self.summary = Some(rest.to_string());
            // "1 IP address (1 host up) scanned in 0.25 seconds"
            let number = |text: &str| text.split_whitespace().next().and_then(|n| n.parse().ok());
            self.hosts_completed = number(rest);
            self.hosts_up = rest.split_once('(').and_then(|(_, up)| number(up));
            self.current_phase = None;
            self.percent = Some(100.0);
            self.etc = None;
            self.remaining = None;
            return;
        }
        if line.starts_with("WARNING") || line.starts_with("Warning") {
            self.warnings.push(line.to_string());
        }
        if line.starts_with("Host script results:")
            && let Some(host) = self.last_reported
        {
            self.context = Context::HostScripts(host);
            return;
        }

        let host_index = match self.context {
            Context::None => return,
            Context::Host(h)
            | Context::Ports(h)
            | Context::Port(h, _)
            | Context::HostScripts(h) => h,
        };
        self.on_host_line(host_index, line);
    }

    fn on_host_line(&mut self, h: usize, line: &str) {
        if line.starts_with("PORT ") {
            self.context = Context::Ports(h);
            return;
        }
        if line.starts_with('|') {
            let text = strip_script_prefix(line);
            match self.context {
                Context::Port(h, p) => self.hosts[h].ports[p].scripts.push(text),
                Context::HostScripts(h) => self.hosts[h].scripts.push(text),
                _ => {}
            }
            return;
        }
        if matches!(self.context, Context::Ports(_) | Context::Port(_, _))
            && let Some(port) = parse_port_line(line)
        {
            let host = &mut self.hosts[h];
            let index = match host
                .ports
                .iter()
                .position(|p| p.port == port.port && p.protocol == port.protocol)
            {
                Some(index) => {
                    host.ports[index] = port;
                    index
                }
                None => {
                    host.ports.push(port);
                    host.ports.len() - 1
                }
            };
            self.context = Context::Port(h, index);
            return;
        }

        let host = &mut self.hosts[h];
        if let Some(rest) = line.strip_prefix("Host is up") {
            host.status = HostStatus::Up(
                rest.trim_start_matches(" (")
                    .split_once(" latency")
                    .map(|(latency, _)| latency.to_string()),
            );
        } else if let Some(rest) = line.strip_prefix("MAC Address: ") {
            host.mac = Some(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("OS details: ") {
            host.os = Some(rest.to_string());
        } else if let Some(rest) = line
            .strip_prefix("Running: ")
            .or_else(|| line.strip_prefix("Running (JUST GUESSING): "))
            .or_else(|| line.strip_prefix("Aggressive OS guesses: "))
        {
            if host.os.is_none() {
                host.os = Some(rest.to_string());
            }
        } else if line.starts_with("Service Info: ")
            || line.starts_with("Not shown: ")
            || line.starts_with("All ")
            || line.starts_with("rDNS record for ")
            || line.starts_with("Other addresses for ")
        {
            host.notes.push(line.to_string());
        }
    }

    fn on_report(&mut self, rest: &str) {
        let (rest, down) = match rest.strip_suffix(" [host down]") {
            Some(rest) => (rest, true),
            None => (rest, false),
        };
        let (hostname, address) = split_name_address(rest);
        let index = self.host_index(&address);
        let host = &mut self.hosts[index];
        if hostname.is_some() {
            host.hostname = hostname;
        }
        host.reported = true;
        if down {
            host.status = HostStatus::Down;
        }
        self.context = Context::Host(index);
        self.last_reported = Some(index);
    }

    /// "80/tcp on 192.168.1.1"
    fn on_discovered(&mut self, rest: &str) {
        let Some((port, target)) = rest.split_once(" on ") else {
            return;
        };
        let Some((number, protocol)) = port.split_once('/') else {
            return;
        };
        let Ok(number) = number.parse::<u16>() else {
            return;
        };
        let (hostname, address) = split_name_address(target);
        let index = self.host_index(&address);
        let host = &mut self.hosts[index];
        if hostname.is_some() && host.hostname.is_none() {
            host.hostname = hostname;
        }
        if host.status == HostStatus::Unknown {
            host.status = HostStatus::Up(None);
        }
        if !host
            .ports
            .iter()
            .any(|p| p.port == number && p.protocol == protocol)
        {
            host.ports.push(PortInfo {
                port: number,
                protocol: protocol.to_string(),
                state: "open".to_string(),
                ..Default::default()
            });
            host.ports.sort_by_key(|p| (p.port, p.protocol.clone()));
        }
    }

    /// "0:00:05 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan"
    fn on_stats(&mut self, rest: &str) {
        for part in rest.split(';').map(str::trim) {
            if let Some((completed, up)) = part.split_once(" hosts completed (") {
                self.hosts_completed = completed.trim().parse().ok();
                self.hosts_up = up.split_once(" up)").and_then(|(n, _)| n.parse().ok());
                if let Some((_, phase)) = up.split_once(" undergoing ") {
                    self.current_phase = Some(phase.to_string());
                }
            }
        }
    }

    /// "Connect Scan at 14:53"
    fn on_initiating(&mut self, rest: &str) {
        let Some((name, time)) = rest.rsplit_once(" at ") else {
            return;
        };
        self.current_phase = Some(name.to_string());
        self.percent = None;
        self.etc = None;
        self.remaining = None;
        // NSE runs several times in a row: keep one entry per run of identical phases
        if let Some(last) = self.phases.last_mut()
            && last.name == name
            && last.completed.is_some()
        {
            last.completed = None;
            return;
        }
        self.phases.push(Phase {
            name: name.to_string(),
            started_at: time.to_string(),
            completed: None,
        });
    }

    /// "Connect Scan at 14:53, 0.02s elapsed (2000 total ports)"
    fn on_completed(&mut self, rest: &str) {
        let Some((head, detail)) = rest.split_once(", ") else {
            return;
        };
        let Some((name, _)) = head.rsplit_once(" at ") else {
            return;
        };
        if let Some(phase) = self
            .phases
            .iter_mut()
            .rev()
            .find(|p| p.name == name && p.completed.is_none())
        {
            phase.completed = Some(detail.to_string());
        }
        if self.current_phase.as_deref() == Some(name) {
            self.percent = Some(100.0);
            self.etc = None;
            self.remaining = None;
        }
    }

    fn host_index(&mut self, address: &str) -> usize {
        match self.hosts.iter().position(|h| h.address == address) {
            Some(index) => index,
            None => {
                self.hosts.push(HostInfo {
                    address: address.to_string(),
                    ..Default::default()
                });
                self.hosts.len() - 1
            }
        }
    }

    pub fn total_open_ports(&self) -> usize {
        self.hosts.iter().map(HostInfo::open_ports).sum()
    }
}

/// "name (1.2.3.4)" -> (Some(name), 1.2.3.4); "1.2.3.4" -> (None, 1.2.3.4)
fn split_name_address(text: &str) -> (Option<String>, String) {
    if let Some(stripped) = text.strip_suffix(')')
        && let Some((name, address)) = stripped.rsplit_once(" (")
    {
        return (Some(name.to_string()), address.to_string());
    }
    (None, text.to_string())
}

fn strip_script_prefix(line: &str) -> String {
    let text = line
        .strip_prefix("|_")
        .or_else(|| line.strip_prefix('|'))
        .unwrap_or(line);
    // Keep nested indentation, drop only the single separator space
    text.strip_prefix(' ').unwrap_or(text).to_string()
}

/// "8765/tcp open  http     SimpleHTTPServer 0.6 (Python 3.10.12)"
fn parse_port_line(line: &str) -> Option<PortInfo> {
    let mut rest = line;
    let mut next = || {
        let trimmed = rest.trim_start();
        let end = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
        let (token, tail) = trimmed.split_at(end);
        rest = tail;
        token
    };
    let (number, protocol) = next().split_once('/')?;
    let port = number.parse::<u16>().ok()?;
    if !matches!(protocol, "tcp" | "udp" | "sctp" | "ip") {
        return None;
    }
    let state = next().to_string();
    if state.is_empty() {
        return None;
    }
    let service = next().to_string();
    Some(PortInfo {
        port,
        protocol: protocol.to_string(),
        state,
        service,
        version: rest.trim().to_string(),
        scripts: Vec::new(),
    })
}

/// "Connect Scan Timing: About 53.97% done; ETC: 14:53 (0:00:09 remaining)"
fn parse_timing(line: &str) -> Option<(String, f64, Option<String>, Option<String>)> {
    let (phase, rest) = line.split_once(" Timing: About ")?;
    let (percent, rest) = rest.split_once("% done")?;
    let percent = percent.trim().parse::<f64>().ok()?;
    let (etc, remaining) = match rest.split_once("ETC: ") {
        Some((_, etc)) => match etc.split_once(" (") {
            Some((time, remaining)) => (
                Some(time.to_string()),
                remaining
                    .split_once(" remaining")
                    .map(|(r, _)| r.to_string()),
            ),
            None => (Some(etc.trim().to_string()), None),
        },
        None => (None, None),
    };
    Some((phase.to_string(), percent, etc, remaining))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
Starting Nmap 7.80 ( https://nmap.org ) at 2026-11-24 14:53 CET
NSE: Loaded 46 scripts for scanning.
Initiating NSE at 14:53
Completed NSE at 14:53, 0.00s elapsed
Initiating NSE at 14:53
Completed NSE at 14:53, 0.00s elapsed
Initiating Ping Scan at 14:53
Scanning 127.0.0.1 [2 ports]
Completed Ping Scan at 14:53, 0.00s elapsed (1 total hosts)
Initiating Connect Scan at 14:53
Scanning localhost (127.0.0.1) [9000 ports]
Discovered open port 5500/tcp on 127.0.0.1
Stats: 0:00:01 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 4.78% done; ETC: 14:53 (0:00:20 remaining)
Discovered open port 8765/tcp on 127.0.0.1
Completed Connect Scan at 14:53, 18.40s elapsed (9000 total ports)
Initiating Service scan at 14:53
Stats: 0:00:24 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 0.00% done
Completed Service scan at 14:54, 11.04s elapsed (2 services on 1 host)
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000022s latency).
Not shown: 8998 closed ports
PORT     STATE SERVICE  VERSION
5500/tcp open  hotline?
| fingerprint-strings:
|   GetRequest:
|_    HTTP/1.1 200 OK
8765/tcp open  http     SimpleHTTPServer 0.6 (Python 3.10.12)
|_http-server-header: SimpleHTTP/0.6 Python/3.10.12
|_http-title: Directory listing for /
MAC Address: 00:11:22:33:44:55 (Acme)
OS details: Linux 5.0 - 5.4

Host script results:
|_clock-skew: 0s

Nmap done: 1 IP address (1 host up) scanned in 30.25 seconds
";

    fn parse(text: &str) -> ScanProgress {
        let mut progress = ScanProgress::new();
        for line in text.lines() {
            progress.feed_line(line);
        }
        progress
    }

    #[test]
    fn test_full_sample() {
        let p = parse(SAMPLE);
        assert_eq!(p.hosts.len(), 1);
        let host = &p.hosts[0];
        assert_eq!(host.address, "127.0.0.1");
        assert_eq!(host.hostname.as_deref(), Some("localhost"));
        assert_eq!(host.status, HostStatus::Up(Some("0.000022s".to_string())));
        assert!(host.reported);
        assert_eq!(host.ports.len(), 2);
        assert_eq!(host.ports[0].service, "hotline?");
        assert_eq!(host.ports[0].scripts.len(), 3);
        assert_eq!(host.ports[1].port, 8765);
        assert_eq!(
            host.ports[1].version,
            "SimpleHTTPServer 0.6 (Python 3.10.12)"
        );
        assert_eq!(
            host.ports[1].scripts,
            vec![
                "http-server-header: SimpleHTTP/0.6 Python/3.10.12",
                "http-title: Directory listing for /"
            ]
        );
        assert_eq!(host.mac.as_deref(), Some("00:11:22:33:44:55 (Acme)"));
        assert_eq!(host.os.as_deref(), Some("Linux 5.0 - 5.4"));
        assert_eq!(host.scripts, vec!["clock-skew: 0s"]);
        assert_eq!(host.notes, vec!["Not shown: 8998 closed ports"]);
        assert_eq!(
            p.summary.as_deref(),
            Some("1 IP address (1 host up) scanned in 30.25 seconds")
        );
        assert_eq!(p.percent, Some(100.0));
        assert_eq!(p.hosts_completed, Some(1));
        assert_eq!(p.hosts_up, Some(1));
        assert_eq!(p.total_open_ports(), 2);
    }

    #[test]
    fn test_phases_merge_consecutive_nse() {
        let p = parse(SAMPLE);
        let names: Vec<_> = p.phases.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["NSE", "Ping Scan", "Connect Scan", "Service scan"]
        );
        assert!(p.phases.iter().all(|p| p.completed.is_some()));
        assert_eq!(
            p.phases[2].completed.as_deref(),
            Some("18.40s elapsed (9000 total ports)")
        );
    }

    #[test]
    fn test_progress_while_running() {
        let cut = SAMPLE.find("Discovered open port 8765").unwrap();
        let p = parse(&SAMPLE[..cut]);
        assert_eq!(p.current_phase.as_deref(), Some("Connect Scan"));
        assert_eq!(p.percent, Some(4.78));
        assert_eq!(p.etc.as_deref(), Some("14:53"));
        assert_eq!(p.remaining.as_deref(), Some("0:00:20"));
        assert_eq!(p.hosts_completed, Some(0));
        assert_eq!(p.hosts_up, Some(1));
        assert_eq!(p.hosts[0].ports.len(), 1);
        assert!(!p.hosts[0].reported);
    }

    #[test]
    fn test_timing_without_etc() {
        assert_eq!(
            parse_timing("Service scan Timing: About 0.00% done"),
            Some(("Service scan".to_string(), 0.0, None, None))
        );
    }

    #[test]
    fn test_host_down_and_plain_address() {
        let p = parse(
            "Nmap scan report for 10.0.0.5 [host down]\nNmap scan report for 10.0.0.6\nHost is up.\n",
        );
        assert_eq!(p.hosts.len(), 2);
        assert_eq!(p.hosts[0].status, HostStatus::Down);
        assert_eq!(p.hosts[1].address, "10.0.0.6");
        assert_eq!(p.hosts[1].hostname, None);
        assert_eq!(p.hosts[1].status, HostStatus::Up(None));
    }

    #[test]
    fn test_port_lines_outside_table_ignored() {
        let p = parse("Nmap scan report for 10.0.0.6\n80/tcp open http\n");
        assert!(p.hosts[0].ports.is_empty());
    }

    #[test]
    fn test_stats_line_detection() {
        assert!(ScanProgress::is_stats_line(
            "Stats: 0:00:01 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan"
        ));
        assert!(ScanProgress::is_stats_line(
            "Connect Scan Timing: About 4.78% done; ETC: 14:53 (0:00:20 remaining)"
        ));
        assert!(!ScanProgress::is_stats_line(
            "Discovered open port 80/tcp on 1.2.3.4"
        ));
    }
}
