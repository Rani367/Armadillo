//! TUI rendering. Immediate-mode: the whole UI is drawn from [`App`] each frame.

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, List, ListItem, Paragraph, Tabs, Wrap};
use ratatui::Frame;

use super::app::{App, Tab};
use crate::engine::verdict::{Severity, Verdict};
use crate::report::human_bytes;

const ACCENT: Color = Color::Cyan;

pub fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::vertical([
        Constraint::Length(3), // title + tabs
        Constraint::Min(0),    // body
        Constraint::Length(1), // status/help
    ])
    .split(f.area());

    draw_tabs(f, app, chunks[0]);
    match app.tab {
        Tab::Dashboard => draw_dashboard(f, app, chunks[1]),
        Tab::Threats => draw_threats(f, app, chunks[1]),
        Tab::Audit => draw_audit(f, app, chunks[1]),
        Tab::Quarantine => draw_quarantine(f, app, chunks[1]),
        Tab::Help => draw_help(f, chunks[1]),
    }
    draw_status(f, app, chunks[2]);
}

fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = Tab::ALL.iter().map(|t| Line::from(t.title())).collect();
    let tabs = Tabs::new(titles)
        .select(app.tab.index())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(
                    " 🛡  ARMADILLO ",
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                )),
        )
        .highlight_style(Style::default().fg(Color::Black).bg(ACCENT).add_modifier(Modifier::BOLD))
        .divider("│");
    f.render_widget(tabs, area);
}

fn draw_dashboard(f: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::vertical([
        Constraint::Length(3), // gauge
        Constraint::Length(7), // stats
        Constraint::Min(0),    // recent threats
    ])
    .split(area);

    // Progress gauge.
    let ratio = app.progress_ratio();
    let label = if app.scanning {
        format!("scanning… {}/{}", app.snapshot.scanned, app.total)
    } else if app.cancelled {
        "cancelled".to_string()
    } else {
        format!("complete — {}/{}", app.snapshot.scanned, app.total)
    };
    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title(" Quick scan "))
        .gauge_style(Style::default().fg(if app.scanning { ACCENT } else { Color::Green }))
        .ratio(ratio)
        .label(label);
    f.render_widget(gauge, rows[0]);

    // Stats.
    let mal = app.threats.iter().filter(|t| t.verdict == Verdict::Malicious).count();
    let sus = app.threats.iter().filter(|t| t.verdict == Verdict::Suspicious).count();
    let stat_lines = vec![
        kv("Files scanned", app.snapshot.scanned.to_string()),
        kv("Data scanned", human_bytes(app.snapshot.bytes)),
        Line::from(vec![
            Span::raw("  Threats        "),
            Span::styled(format!("{mal} malicious"), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::raw("  ·  "),
            Span::styled(format!("{sus} suspicious"), Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::raw("  Audit findings "),
            Span::styled(
                format!("{}", app.audit.findings.len()),
                Style::default().fg(if app.audit.findings.is_empty() { Color::Green } else { Color::Yellow }),
            ),
        ]),
        kv("Skipped / errors", format!("{} / {}", app.snapshot.skipped, app.snapshot.errors)),
        kv("Elapsed", format!("{:.1}s", app.start.elapsed().as_secs_f64())),
    ];
    let stats = Paragraph::new(stat_lines)
        .block(Block::default().borders(Borders::ALL).title(" Summary "));
    f.render_widget(stats, rows[1]);

    // Recent threats preview.
    let items: Vec<ListItem> = app
        .threats
        .iter()
        .rev()
        .take(rows[2].height.saturating_sub(2) as usize)
        .map(|t| ListItem::new(threat_line(t)))
        .collect();
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Recent detections "),
    );
    f.render_widget(list, rows[2]);
}

fn draw_threats(f: &mut Frame, app: &mut App, area: Rect) {
    if app.threats.is_empty() {
        let p = Paragraph::new("No threats detected.")
            .block(Block::default().borders(Borders::ALL).title(" Threats "))
            .alignment(Alignment::Center);
        f.render_widget(p, area);
        return;
    }
    let items: Vec<ListItem> = app
        .threats
        .iter()
        .map(|t| {
            let detail: Vec<Span> = t
                .detections
                .iter()
                .take(2)
                .map(|d| Span::styled(format!("  [{}:{}]", d.engine.label(), d.name), Style::default().fg(Color::DarkGray)))
                .collect();
            let mut spans = threat_line(t).spans;
            spans.extend(detail);
            ListItem::new(Line::from(spans))
        })
        .collect();
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Threats — [q]uarantine  [d]elete  ↑/↓ select "),
        )
        .highlight_style(Style::default().bg(Color::Rgb(40, 40, 60)).add_modifier(Modifier::BOLD))
        .highlight_symbol("▶ ");
    f.render_stateful_widget(list, area, &mut app.threat_state);
}

fn draw_audit(f: &mut Frame, app: &App, area: Rect) {
    if app.audit.findings.is_empty() {
        let p = Paragraph::new(format!(
            "✓ No suspicious persistence/adware artifacts.\n\n{} items inspected.",
            app.audit.inspected
        ))
        .style(Style::default().fg(Color::Green))
        .block(Block::default().borders(Borders::ALL).title(" macOS Audit "))
        .alignment(Alignment::Center);
        f.render_widget(p, area);
        return;
    }
    let items: Vec<ListItem> = app
        .audit
        .findings
        .iter()
        .map(|fnd| {
            let sev = sev_span(fnd.severity);
            let head = Line::from(vec![
                sev,
                Span::raw(" "),
                Span::styled(fnd.category.label().to_string(), Style::default().fg(ACCENT)),
                Span::raw("  "),
                Span::raw(fnd.title.clone()),
            ]);
            let mut lines = vec![head, Line::from(Span::styled(
                format!("    {}", fnd.location.display()),
                Style::default().fg(Color::DarkGray),
            ))];
            for r in &fnd.reasons {
                lines.push(Line::from(format!("    • {r}")));
            }
            ListItem::new(lines)
        })
        .collect();
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" macOS Audit — {} suspicious ", app.audit.findings.len())),
    );
    f.render_widget(list, area);
}

fn draw_quarantine(f: &mut Frame, app: &mut App, area: Rect) {
    if app.quarantine.is_empty() {
        let p = Paragraph::new("Quarantine is empty.")
            .block(Block::default().borders(Borders::ALL).title(" Quarantine "))
            .alignment(Alignment::Center);
        f.render_widget(p, area);
        return;
    }
    let items: Vec<ListItem> = app
        .quarantine
        .iter()
        .map(|e| {
            ListItem::new(Line::from(vec![
                Span::styled(format!("{} ", &e.id[..8]), Style::default().fg(ACCENT)),
                Span::styled(format!("[{}] ", e.verdict), Style::default().fg(Color::Red)),
                Span::raw(e.original_path.display().to_string()),
                Span::styled(format!("  {}", e.quarantined_at), Style::default().fg(Color::DarkGray)),
            ]))
        })
        .collect();
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Quarantine — [r]estore  [x]purge  ↑/↓ select "),
        )
        .highlight_style(Style::default().bg(Color::Rgb(40, 40, 60)).add_modifier(Modifier::BOLD))
        .highlight_symbol("▶ ");
    f.render_stateful_widget(list, area, &mut app.quar_state);
}

fn draw_help(f: &mut Frame, area: Rect) {
    let text = vec![
        Line::from(Span::styled("Armadillo — keyboard reference", Style::default().add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from("  Tab / Shift+Tab     switch views     1–5   jump to view"),
        Line::from("  ↑ / ↓  (or j / k)   move selection"),
        Line::from("  q                   quarantine selected threat"),
        Line::from("  d                   delete selected threat from disk"),
        Line::from("  r                   restore selected quarantined item"),
        Line::from("  x                   purge selected quarantined item"),
        Line::from("  Esc / Ctrl+C        quit"),
        Line::from(""),
        Line::from(Span::styled(
            "  Armadillo is defense-in-depth: hashes + YARA + heuristics + macOS audit.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "  No scanner can guarantee 100% detection — keep definitions updated.",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    let p = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title(" Help "))
        .wrap(Wrap { trim: true });
    f.render_widget(p, area);
}

fn draw_status(f: &mut Frame, app: &App, area: Rect) {
    let spinner = if app.scanning { "⠿ " } else { "" };
    let line = Line::from(vec![
        Span::styled(format!(" {spinner}"), Style::default().fg(ACCENT)),
        Span::raw(app.status.clone()),
    ]);
    f.render_widget(Paragraph::new(line).style(Style::default().bg(Color::Rgb(20, 20, 30))), area);
}

// --- helpers ---

fn kv(key: &str, value: String) -> Line<'static> {
    Line::from(vec![
        Span::raw(format!("  {key:<15}")),
        Span::styled(value, Style::default().add_modifier(Modifier::BOLD)),
    ])
}

fn threat_line(t: &crate::engine::verdict::Threat) -> Line<'static> {
    let (tag, color) = match t.verdict {
        Verdict::Malicious => (" MAL ", Color::Red),
        Verdict::Suspicious => (" SUS ", Color::Yellow),
        Verdict::Clean => (" OK  ", Color::Green),
    };
    Line::from(vec![
        Span::styled(tag, Style::default().bg(color).fg(Color::Black).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        Span::raw(t.path.display().to_string()),
    ])
}

fn sev_span(sev: Severity) -> Span<'static> {
    let (txt, color) = match sev {
        Severity::Critical => ("CRIT", Color::Red),
        Severity::High => ("HIGH", Color::Red),
        Severity::Medium => ("MED ", Color::Yellow),
        Severity::Low => ("LOW ", Color::Cyan),
        Severity::Info => ("INFO", Color::Blue),
    };
    Span::styled(txt.to_string(), Style::default().fg(color).add_modifier(Modifier::BOLD))
}
