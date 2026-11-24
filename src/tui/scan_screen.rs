//! Live view of a running nmap scan: progress, discovered hosts and ports, phases and raw output.

use std::{
    error::Error,
    process::ExitStatus,
    sync::mpsc::TryRecvError,
    time::{Duration, Instant},
};

use ratatui::{
    DefaultTerminal,
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    prelude::*,
    widgets::{
        Block, BorderType, Gauge, List, ListItem, ListState, Paragraph, Scrollbar,
        ScrollbarOrientation, ScrollbarState,
    },
};

use crate::run::{
    process::{OutputLine, ScanInvocation, ScanProcess},
    progress::{HostInfo, HostStatus, ScanProgress},
};

const TICK: Duration = Duration::from_millis(100);
const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
/// How long quitting during a scan waits for nmap to exit after SIGINT
const QUIT_GRACE: Duration = Duration::from_secs(3);

pub enum ScanOutcome {
    /// Return to the command builder
    Back,
    /// Leave lazynmap, printing the scan output
    Quit(Vec<String>),
}

#[derive(Clone, Copy, PartialEq)]
enum Pane {
    Hosts,
    Ports,
    Output,
}

impl Pane {
    fn next(self) -> Self {
        match self {
            Pane::Hosts => Pane::Ports,
            Pane::Ports => Pane::Output,
            Pane::Output => Pane::Hosts,
        }
    }

    fn prev(self) -> Self {
        match self {
            Pane::Hosts => Pane::Output,
            Pane::Ports => Pane::Hosts,
            Pane::Output => Pane::Ports,
        }
    }
}

enum RunStatus {
    Running,
    Stopping,
    Finished(ExitStatus),
    Failed(String),
}

#[derive(Clone, Copy, PartialEq)]
enum LineKind {
    Stdout,
    Stderr,
    Info,
}

struct LogLine {
    text: String,
    kind: LineKind,
    stats: bool,
}

pub struct ScanScreen {
    invocation: ScanInvocation,
    process: Option<ScanProcess>,
    progress: ScanProgress,
    log: Vec<LogLine>,
    status: RunStatus,
    started: Instant,
    finished: Option<Duration>,
    stop_requested: bool,
    focus: Pane,
    hosts_state: ListState,
    ports_scroll: usize,
    ports_height: usize,
    log_scroll: usize,
    log_height: usize,
    follow: bool,
    show_stats: bool,
    outcome: Option<ScanOutcome>,
}

impl ScanScreen {
    pub fn new(invocation: ScanInvocation) -> Self {
        let mut screen = Self {
            invocation,
            process: None,
            progress: ScanProgress::new(),
            log: Vec::new(),
            status: RunStatus::Running,
            started: Instant::now(),
            finished: None,
            stop_requested: false,
            focus: Pane::Hosts,
            hosts_state: ListState::default(),
            ports_scroll: 0,
            ports_height: 0,
            log_scroll: 0,
            log_height: 0,
            follow: true,
            show_stats: false,
            outcome: None,
        };
        screen.start();
        screen
    }

    fn start(&mut self) {
        self.progress = ScanProgress::new();
        self.log.clear();
        self.started = Instant::now();
        self.finished = None;
        self.stop_requested = false;
        self.hosts_state = ListState::default();
        self.ports_scroll = 0;
        self.log_scroll = 0;
        self.follow = true;
        self.push_info(format!("$ {}", self.invocation.display()));
        match ScanProcess::spawn(&self.invocation) {
            Ok(process) => {
                self.process = Some(process);
                self.status = RunStatus::Running;
            }
            Err(error) => {
                self.process = None;
                self.status = RunStatus::Failed(format!("failed to start nmap: {error}"));
                self.finished = Some(Duration::ZERO);
            }
        }
    }

    fn is_running(&self) -> bool {
        matches!(self.status, RunStatus::Running | RunStatus::Stopping)
    }

    pub fn run(mut self, terminal: &mut DefaultTerminal) -> Result<ScanOutcome, Box<dyn Error>> {
        loop {
            self.poll_process();
            terminal.draw(|frame| self.draw(frame))?;
            if event::poll(TICK)? {
                // Handle every queued event before redrawing, so key repeat stays responsive
                loop {
                    self.handle_event(event::read()?);
                    if self.outcome.is_some() || !event::poll(Duration::ZERO)? {
                        break;
                    }
                }
            }
            if let Some(outcome) = self.outcome.take() {
                if self.is_running() {
                    self.stop_and_wait();
                }
                return Ok(match outcome {
                    ScanOutcome::Quit(_) => ScanOutcome::Quit(self.nmap_output()),
                    back => back,
                });
            }
        }
    }

    fn poll_process(&mut self) {
        let Some(process) = &mut self.process else {
            return;
        };
        let mut lines = Vec::new();
        let mut disconnected = false;
        loop {
            match process.lines.try_recv() {
                Ok(line) => lines.push(line),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }
        let exit = match process.try_wait() {
            Ok(exit) => exit,
            Err(error) => {
                self.status = RunStatus::Failed(error.to_string());
                None
            }
        };
        for line in lines {
            self.push_output(line);
        }
        // Wait for both output pipes to close too, so no trailing line is lost
        if let Some(exit) = exit
            && disconnected
        {
            self.process = None;
            self.finished = Some(self.started.elapsed());
            self.status = RunStatus::Finished(exit);
            let message = if self.stop_requested {
                "Scan stopped".to_string()
            } else {
                format!("nmap exited with {exit}")
            };
            self.push_info(message);
        }
    }

    fn stop_and_wait(&mut self) {
        if let Some(process) = &self.process {
            process.signal(libc::SIGINT);
        }
        let deadline = Instant::now() + QUIT_GRACE;
        while self.process.is_some() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
            self.poll_process();
        }
        // Dropping the process sends SIGTERM if nmap is still alive
        self.process = None;
    }

    fn push_output(&mut self, line: OutputLine) {
        let (text, kind) = match line {
            OutputLine::Stdout(text) => {
                self.progress.feed_line(&text);
                (text, LineKind::Stdout)
            }
            OutputLine::Stderr(text) => (text, LineKind::Stderr),
        };
        let stats = ScanProgress::is_stats_line(&text);
        self.log.push(LogLine { text, kind, stats });
        if self.hosts_state.selected().is_none() && !self.progress.hosts.is_empty() {
            self.hosts_state.select(Some(0));
        }
    }

    fn push_info(&mut self, text: String) {
        self.log.push(LogLine {
            text,
            kind: LineKind::Info,
            stats: false,
        });
    }

    fn handle_event(&mut self, event: Event) {
        let Event::Key(key) = event else {
            return;
        };
        if key.kind != KeyEventKind::Press {
            return;
        }
        self.handle_key(key);
    }

    fn handle_key(&mut self, key: KeyEvent) {
        let ctrl_c =
            key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c');
        match key.code {
            _ if ctrl_c => self.request_stop(),
            KeyCode::Char('q') | KeyCode::Char('Q') => {
                self.outcome = Some(ScanOutcome::Quit(Vec::new()));
            }
            KeyCode::Char('s') | KeyCode::Char('S') => self.request_stop(),
            KeyCode::Char('b') | KeyCode::Char('B') | KeyCode::Esc => {
                if !self.is_running() {
                    self.outcome = Some(ScanOutcome::Back);
                }
            }
            KeyCode::Char('r') | KeyCode::Char('R') => {
                if !self.is_running() {
                    self.start();
                }
            }
            KeyCode::Tab => self.focus = self.focus.next(),
            KeyCode::BackTab => self.focus = self.focus.prev(),
            KeyCode::Char('1') => self.focus = Pane::Hosts,
            KeyCode::Char('2') => self.focus = Pane::Ports,
            KeyCode::Char('3') => self.focus = Pane::Output,
            KeyCode::Char('f') | KeyCode::Char('F') => {
                self.follow = !self.follow;
            }
            KeyCode::Char('v') | KeyCode::Char('V') => {
                self.show_stats = !self.show_stats;
                self.follow = true;
            }
            KeyCode::Char('j') | KeyCode::Char('J') | KeyCode::Down => self.scroll(1),
            KeyCode::Char('k') | KeyCode::Char('K') | KeyCode::Up => self.scroll(-1),
            KeyCode::PageDown => self.scroll(self.page()),
            KeyCode::PageUp => self.scroll(-self.page()),
            KeyCode::Char('g') | KeyCode::Home => self.scroll(isize::MIN / 2),
            KeyCode::Char('G') | KeyCode::End => self.scroll(isize::MAX / 2),
            _ => {}
        }
    }

    /// nmap's own output, as it would have appeared in the terminal without lazynmap
    fn nmap_output(&self) -> Vec<String> {
        self.log
            .iter()
            .filter(|line| line.kind != LineKind::Info && !line.stats)
            .map(|line| line.text.clone())
            .collect()
    }

    fn request_stop(&mut self) {
        let Some(process) = &self.process else {
            return;
        };
        // First request interrupts nmap gracefully, a second one terminates it
        if self.stop_requested {
            process.signal(libc::SIGTERM);
            self.push_info("Sent SIGTERM to nmap".to_string());
        } else {
            process.signal(libc::SIGINT);
            self.push_info("Sent SIGINT to nmap, press s again to force".to_string());
        }
        self.stop_requested = true;
        self.status = RunStatus::Stopping;
    }

    fn page(&self) -> isize {
        let height = match self.focus {
            Pane::Hosts => 10,
            Pane::Ports => self.ports_height,
            Pane::Output => self.log_height,
        };
        height.max(1) as isize
    }

    fn scroll(&mut self, delta: isize) {
        match self.focus {
            Pane::Hosts => {
                let count = self.progress.hosts.len();
                if count == 0 {
                    return;
                }
                let current = self.hosts_state.selected().unwrap_or(0) as isize;
                let next = (current + delta).clamp(0, count as isize - 1) as usize;
                if Some(next) != self.hosts_state.selected() {
                    self.ports_scroll = 0;
                }
                self.hosts_state.select(Some(next));
            }
            Pane::Ports => {
                self.ports_scroll = offset(self.ports_scroll, delta);
            }
            Pane::Output => {
                let max = self.visible_log_len().saturating_sub(self.log_height);
                let current = if self.follow { max } else { self.log_scroll };
                self.log_scroll = offset(current, delta).min(max);
                self.follow = self.log_scroll >= max;
            }
        }
    }

    fn visible_log_len(&self) -> usize {
        self.log
            .iter()
            .filter(|line| self.show_stats || !line.stats)
            .count()
    }

    fn elapsed(&self) -> Duration {
        self.finished.unwrap_or_else(|| self.started.elapsed())
    }

    fn spinner(&self) -> &'static str {
        SPINNER[(self.started.elapsed().as_millis() / 100) as usize % SPINNER.len()]
    }

    fn draw(&mut self, frame: &mut Frame) {
        let [header, progress, body, output, footer] = Layout::vertical([
            Constraint::Length(5),
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Percentage(30),
            Constraint::Length(1),
        ])
        .areas(frame.area());
        let [hosts, ports, phases] = Layout::horizontal([
            Constraint::Percentage(25),
            Constraint::Min(30),
            Constraint::Length(36),
        ])
        .areas(body);

        self.render_header(frame, header);
        self.render_progress(frame, progress);
        self.render_hosts(frame, hosts);
        self.render_ports(frame, ports);
        self.render_phases(frame, phases);
        self.render_output(frame, output);
        self.render_footer(frame, footer);
    }

    fn pane_block(&self, pane: Pane, title: Line<'static>) -> Block<'static> {
        let block = Block::bordered()
            .border_type(BorderType::Thick)
            .title(title);
        if self.focus == pane {
            block.border_style(Style::default().fg(Color::Yellow))
        } else {
            block
        }
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let (status, color) = match &self.status {
            RunStatus::Running => (format!("{} Running", self.spinner()), Color::Cyan),
            RunStatus::Stopping => (format!("{} Stopping", self.spinner()), Color::Yellow),
            RunStatus::Finished(exit) if self.stop_requested => {
                (format!("■ Stopped ({exit})"), Color::Yellow)
            }
            RunStatus::Finished(exit) if exit.success() => ("✓ Done".to_string(), Color::Green),
            RunStatus::Finished(exit) => (format!("✗ Failed ({exit})"), Color::Red),
            RunStatus::Failed(error) => (format!("✗ {error}"), Color::Red),
        };

        let mut command = Vec::new();
        if self.invocation.sudo {
            command.push(Span::from("sudo ").red());
        }
        command.push(Span::from(self.invocation.user_command.clone()).bold());

        let mut stats = vec![
            Span::from(status).fg(color).bold(),
            Span::from("   Elapsed ").dark_gray(),
            Span::from(format_duration(self.elapsed())),
        ];
        if let (Some(completed), Some(up)) = (self.progress.hosts_completed, self.progress.hosts_up)
        {
            stats.extend([
                Span::from("   Hosts ").dark_gray(),
                Span::from(format!("{completed} done, {up} up")),
            ]);
        } else {
            stats.extend([
                Span::from("   Hosts ").dark_gray(),
                Span::from(self.progress.hosts.len().to_string()),
            ]);
        }
        stats.extend([
            Span::from("   Open ports ").dark_gray(),
            Span::from(self.progress.total_open_ports().to_string()).green(),
        ]);
        if !self.progress.warnings.is_empty() {
            stats.extend([
                Span::from("   Warnings ").dark_gray(),
                Span::from(self.progress.warnings.len().to_string()).yellow(),
            ]);
        }

        let mut lines = vec![Line::from(command), Line::from(stats)];
        if !self.invocation.added_flags.is_empty() {
            lines.push(
                Line::from(format!(
                    "lazynmap added {} to track progress",
                    self.invocation.added_flags.join(" ")
                ))
                .dark_gray()
                .italic(),
            );
        }
        let block = Block::bordered()
            .border_type(BorderType::Thick)
            .title(Line::from(" lazynmap · scan ").centered());
        frame.render_widget(Paragraph::new(lines).block(block), area);
    }

    fn render_progress(&self, frame: &mut Frame, area: Rect) {
        let p = &self.progress;
        let done = matches!(self.status, RunStatus::Finished(exit) if exit.success())
            && !self.stop_requested;
        let (ratio, label, title, color) = if done {
            let summary = p.summary.clone().unwrap_or_else(|| "Done".to_string());
            (1.0, summary, "Finished".to_string(), Color::Green)
        } else if !self.is_running() {
            (
                p.percent.unwrap_or(0.0) / 100.0,
                "Not completed".to_string(),
                p.current_phase
                    .clone()
                    .unwrap_or_else(|| "Scan".to_string()),
                Color::Red,
            )
        } else {
            let phase = p
                .current_phase
                .clone()
                .unwrap_or_else(|| "Starting".to_string());
            let mut label = match p.percent {
                Some(percent) => format!("{percent:.2}%"),
                None => format!("{} working", self.spinner()),
            };
            if let Some(remaining) = &p.remaining {
                label.push_str(&format!("  ·  {remaining} left"));
            }
            if let Some(etc) = &p.etc {
                label.push_str(&format!("  ·  ETC {etc}"));
            }
            (p.percent.unwrap_or(0.0) / 100.0, label, phase, Color::Cyan)
        };
        let gauge = Gauge::default()
            .block(
                Block::bordered()
                    .border_type(BorderType::Thick)
                    .title(Line::from(format!(" {title} "))),
            )
            .gauge_style(Style::default().fg(color).bg(Color::Black))
            .ratio(ratio.clamp(0.0, 1.0))
            .label(Span::from(label).bold());
        frame.render_widget(gauge, area);
    }

    fn render_hosts(&mut self, frame: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = self
            .progress
            .hosts
            .iter()
            .map(|host| {
                let (icon, color) = match host.status {
                    HostStatus::Up(_) => ("●", Color::Green),
                    HostStatus::Down => ("●", Color::Red),
                    HostStatus::Unknown => ("○", Color::DarkGray),
                };
                let mut spans = vec![
                    Span::from(format!("{icon} ")).fg(color),
                    Span::from(host.label()),
                ];
                let open = host.open_ports();
                if open > 0 {
                    spans.push(Span::from(format!(" [{open}]")).green());
                }
                if !host.reported && self.is_running() {
                    spans.push(Span::from(" …").dark_gray());
                }
                ListItem::new(Line::from(spans))
            })
            .collect();
        let title = Line::from(format!(" 1 Hosts ({}) ", self.progress.hosts.len()));
        let list = if items.is_empty() {
            List::new([ListItem::new(
                Line::from(if self.is_running() {
                    "Waiting for hosts…"
                } else {
                    "No hosts found"
                })
                .dark_gray(),
            )])
        } else {
            List::new(items)
        };
        let list = list
            .block(self.pane_block(Pane::Hosts, title))
            .highlight_style(Style::default().bg(Color::Cyan).fg(Color::Black))
            .highlight_symbol("› ");
        frame.render_stateful_widget(list, area, &mut self.hosts_state);
    }

    fn render_ports(&mut self, frame: &mut Frame, area: Rect) {
        let host = self
            .hosts_state
            .selected()
            .and_then(|index| self.progress.hosts.get(index));
        let title = match host {
            Some(host) => format!(" 2 {} ", host.label()),
            None => " 2 Ports ".to_string(),
        };
        let block = self.pane_block(Pane::Ports, Line::from(title));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let lines = match host {
            Some(host) => host_lines(host),
            None => vec![Line::from("Select a host to see its ports").dark_gray()],
        };
        self.ports_height = inner.height as usize;
        let max = lines.len().saturating_sub(self.ports_height);
        self.ports_scroll = self.ports_scroll.min(max);
        frame.render_widget(
            Paragraph::new(lines.clone()).scroll((self.ports_scroll as u16, 0)),
            inner,
        );
        render_scrollbar(
            frame,
            area,
            lines.len(),
            self.ports_scroll,
            self.ports_height,
        );
    }

    fn render_phases(&self, frame: &mut Frame, area: Rect) {
        let height = area.height.saturating_sub(2) as usize;
        let phases = &self.progress.phases;
        let skip = phases.len().saturating_sub(height);
        let lines: Vec<Line> = phases
            .iter()
            .skip(skip)
            .map(|phase| match &phase.completed {
                Some(detail) => Line::from(vec![
                    Span::from("✓ ").green(),
                    Span::from(phase.name.clone()),
                    Span::from(format!(" {}", short_elapsed(detail))).dark_gray(),
                ]),
                None if self.is_running() => Line::from(vec![
                    Span::from(format!("{} ", self.spinner())).cyan(),
                    Span::from(phase.name.clone()).cyan().bold(),
                    Span::from(format!(" since {}", phase.started_at)).dark_gray(),
                ]),
                None => Line::from(vec![Span::from("✗ ").red(), Span::from(phase.name.clone())]),
            })
            .collect();
        let block = Block::bordered()
            .border_type(BorderType::Thick)
            .title(Line::from(format!(" Phases ({}) ", phases.len())));
        frame.render_widget(Paragraph::new(lines).block(block), area);
    }

    fn render_output(&mut self, frame: &mut Frame, area: Rect) {
        let mut title = vec![Span::from(" 3 Output ")];
        if self.follow {
            title.push(Span::from("[follow] ").green());
        }
        if self.show_stats {
            title.push(Span::from("[stats] ").cyan());
        }
        let block = self.pane_block(Pane::Output, Line::from(title));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        self.log_height = inner.height as usize;
        let visible: Vec<&LogLine> = self
            .log
            .iter()
            .filter(|line| self.show_stats || !line.stats)
            .collect();
        let max = visible.len().saturating_sub(self.log_height);
        if self.follow {
            self.log_scroll = max;
        }
        self.log_scroll = self.log_scroll.min(max);
        let lines: Vec<Line> = visible
            .iter()
            .skip(self.log_scroll)
            .take(self.log_height)
            .map(|line| log_line(line))
            .collect();
        frame.render_widget(Paragraph::new(lines), inner);
        render_scrollbar(frame, area, visible.len(), self.log_scroll, self.log_height);
    }

    fn render_footer(&self, frame: &mut Frame, area: Rect) {
        let key = |k: &'static str| Span::from(k).black().on_cyan();
        let label = |l: &'static str| Span::from(l);
        let mut spans = vec![
            key(" Tab "),
            label(" pane  "),
            key(" j/k "),
            label(" scroll  "),
            key(" g/G "),
            label(" top/end  "),
            key(" f "),
            label(" follow  "),
            key(" v "),
            label(" stats  "),
        ];
        if self.is_running() {
            spans.extend([key(" s "), label(" stop  ")]);
        } else {
            spans.extend([
                key(" b "),
                label(" back to builder  "),
                key(" r "),
                label(" rerun  "),
            ]);
        }
        spans.extend([key(" q "), label(" quit")]);
        frame.render_widget(Paragraph::new(Line::from(spans)), area);
    }
}

fn host_lines(host: &HostInfo) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let status = match &host.status {
        HostStatus::Up(Some(latency)) => Span::from(format!("up ({latency} latency)")).green(),
        HostStatus::Up(None) => Span::from("up").green(),
        HostStatus::Down => Span::from("down").red(),
        HostStatus::Unknown => Span::from("unknown").dark_gray(),
    };
    lines.push(Line::from(vec![Span::from("Status ").dark_gray(), status]));
    if let Some(mac) = &host.mac {
        lines.push(Line::from(vec![
            Span::from("MAC    ").dark_gray(),
            Span::from(mac.clone()),
        ]));
    }
    if let Some(os) = &host.os {
        lines.push(Line::from(vec![
            Span::from("OS     ").dark_gray(),
            Span::from(os.clone()),
        ]));
    }
    lines.push(Line::default());

    if host.ports.is_empty() {
        lines.push(Line::from("No ports reported yet").dark_gray());
    } else {
        lines.push(
            Line::from(format!(
                "{:<11} {:<15} {:<15} {}",
                "PORT", "STATE", "SERVICE", "VERSION"
            ))
            .bold()
            .underlined(),
        );
        for port in &host.ports {
            let color = match port.state.as_str() {
                "open" => Color::Green,
                "closed" => Color::Red,
                state if state.contains("filtered") => Color::Yellow,
                _ => Color::Gray,
            };
            lines.push(Line::from(vec![
                Span::from(format!(
                    "{:<11} ",
                    format!("{}/{}", port.port, port.protocol)
                ))
                .bold(),
                Span::from(format!("{:<15} ", port.state)).fg(color),
                Span::from(format!("{:<15} ", port.service)),
                Span::from(port.version.clone()).dark_gray(),
            ]));
            for script in &port.scripts {
                lines.push(Line::from(format!("  │ {script}")).cyan());
            }
        }
    }
    if !host.scripts.is_empty() {
        lines.push(Line::default());
        lines.push(Line::from("Host scripts").bold());
        for script in &host.scripts {
            lines.push(Line::from(format!("  │ {script}")).cyan());
        }
    }
    if !host.notes.is_empty() {
        lines.push(Line::default());
        for note in &host.notes {
            lines.push(Line::from(note.clone()).dark_gray());
        }
    }
    lines
}

fn log_line(line: &LogLine) -> Line<'static> {
    let text = line.text.clone();
    match line.kind {
        LineKind::Info => Line::from(text).magenta(),
        LineKind::Stderr => Line::from(text).red(),
        LineKind::Stdout if line.stats => Line::from(text).dark_gray(),
        LineKind::Stdout if text.starts_with("Discovered open port") => Line::from(text).green(),
        LineKind::Stdout if text.starts_with("Nmap scan report for") => Line::from(text).bold(),
        LineKind::Stdout if text.starts_with("WARNING") || text.starts_with("Warning") => {
            Line::from(text).yellow()
        }
        LineKind::Stdout => Line::from(text),
    }
}

fn render_scrollbar(frame: &mut Frame, area: Rect, total: usize, position: usize, height: usize) {
    if total <= height {
        return;
    }
    let mut state = ScrollbarState::new(total.saturating_sub(height)).position(position);
    frame.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight),
        area.inner(Margin {
            vertical: 1,
            horizontal: 0,
        }),
        &mut state,
    );
}

fn offset(current: usize, delta: isize) -> usize {
    current.saturating_add_signed(delta)
}

/// "18.40s elapsed (9000 total ports)" -> "18.40s"
fn short_elapsed(detail: &str) -> String {
    detail
        .split_once(" elapsed")
        .map(|(elapsed, _)| elapsed.to_string())
        .unwrap_or_else(|| detail.to_string())
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3600,
        (seconds / 60) % 60,
        seconds % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_secs(3725)), "01:02:05");
    }

    #[test]
    fn test_short_elapsed() {
        assert_eq!(short_elapsed("18.40s elapsed (9000 total ports)"), "18.40s");
        assert_eq!(short_elapsed("weird"), "weird");
    }
}
