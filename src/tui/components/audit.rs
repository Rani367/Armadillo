//! macOS persistence/adware audit panel — severity heatmap + card list.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Padding, Paragraph, Wrap},
    Frame,
};

use crate::engine::verdict::Severity;
use crate::macos::AuditFinding;
use crate::tui::{
    app::AppCtx,
    components::{card_slots, Component, EventResult},
    event::Event,
    gradient::{lerp, pulse},
    widgets::pill::Pill,
};

pub struct AuditView {
    pub selected: usize,
    pub scroll: usize,
}

impl AuditView {
    pub fn new() -> Self {
        Self {
            selected: 0,
            scroll: 0,
        }
    }
}

impl Default for AuditView {
    fn default() -> Self {
        Self::new()
    }
}

impl Component for AuditView {
    fn draw(&mut self, f: &mut Frame, area: Rect, focused: bool, ctx: &mut AppCtx) {
        let border = if focused {
            ctx.theme.accent_glow
        } else {
            ctx.theme.border
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(border))
            .padding(Padding::new(1, 1, 1, 1))
            .title(Span::styled(
                format!(
                    " {}  audit · {} findings · {} inspected ",
                    ctx.icons.shield(),
                    ctx.audit.findings.len(),
                    ctx.audit.inspected
                ),
                Style::default()
                    .fg(ctx.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ));
        let inner = block.inner(area);
        f.render_widget(block, area);

        if ctx.audit.findings.is_empty() {
            let phase = pulse(ctx.anim.elapsed_seconds(), 2.0);
            let glow = lerp(ctx.theme.success, ctx.theme.accent_glow, phase * 0.5);
            let lines = vec![
                Line::raw(""),
                Line::from(Span::styled(
                    format!("    {}  All clear", ctx.icons.check_circle()),
                    Style::default().fg(glow).add_modifier(Modifier::BOLD),
                )),
                Line::from(Span::styled(
                    "    No suspicious persistence or adware artifacts.",
                    Style::default().fg(ctx.theme.fg_dim),
                )),
            ];
            f.render_widget(Paragraph::new(lines), inner);
            return;
        }

        // Heatmap header strip (1 row) + spacer + card list.
        let split = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Min(0),
            ])
            .split(inner);
        draw_heatmap(f, split[0], &ctx.audit.findings, ctx);

        let list_area = split[2];
        let slots = card_slots(
            list_area,
            4,
            ctx.audit.findings.len(),
            self.selected,
            &mut self.scroll,
        );
        let mut hits: Vec<Rect> = Vec::with_capacity(slots.len());
        for slot in &slots {
            draw_finding_card(
                f,
                slot.rect,
                &ctx.audit.findings[slot.index],
                slot.selected,
                slot.peek,
                ctx,
            );
            hits.push(slot.rect);
        }
        ctx.row_hits = hits;
        ctx.row_hit_base = self.scroll;
    }

    fn handle_event(&mut self, event: &Event, ctx: &mut AppCtx) -> EventResult {
        if let Event::Key(k) = event {
            use crossterm::event::KeyCode::*;
            let len = ctx.audit.findings.len();
            match k.code {
                Down | Char('j') => {
                    if self.selected + 1 < len {
                        self.selected += 1;
                    }
                    return EventResult::Consumed;
                }
                Up | Char('k') => {
                    self.selected = self.selected.saturating_sub(1);
                    return EventResult::Consumed;
                }
                Home | Char('g') => {
                    self.selected = 0;
                    return EventResult::Consumed;
                }
                End | Char('G') => {
                    if len > 0 {
                        self.selected = len - 1;
                    }
                    return EventResult::Consumed;
                }
                _ => {}
            }
        }
        EventResult::NotHandled
    }
}

fn sev_bucket(sev: Severity) -> usize {
    match sev {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}

fn sev_color(sev: Severity, ctx: &AppCtx) -> ratatui::style::Color {
    match sev {
        Severity::Critical | Severity::High => ctx.theme.error,
        Severity::Medium => ctx.theme.warning,
        Severity::Low => ctx.theme.info,
        Severity::Info => ctx.theme.fg_dim,
    }
}

fn draw_heatmap(f: &mut Frame, area: Rect, findings: &[AuditFinding], ctx: &AppCtx) {
    let mut counts = [0usize; 5];
    for fnd in findings {
        counts[sev_bucket(fnd.severity)] += 1;
    }
    let total: usize = counts.iter().sum();
    if total == 0 {
        return;
    }
    let colors = [
        ctx.theme.error,
        ctx.theme.error,
        ctx.theme.warning,
        ctx.theme.info,
        ctx.theme.fg_dim,
    ];
    let labels = ["critical", "high", "medium", "low", "info"];
    let mut spans: Vec<Span> = Vec::new();
    for (i, c) in counts.iter().enumerate() {
        if *c == 0 {
            continue;
        }
        let cells =
            ((*c as f32 / total as f32) * area.width.saturating_sub(2) as f32).max(1.0) as usize;
        spans.push(Span::styled(
            "\u{2588}".repeat(cells),
            Style::default().fg(colors[i]),
        ));
        spans.push(Span::styled(
            format!(" {} {}  ", c, labels[i]),
            Style::default().fg(colors[i]),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_finding_card(
    f: &mut Frame,
    area: Rect,
    fnd: &AuditFinding,
    selected: bool,
    peek: bool,
    ctx: &AppCtx,
) {
    let bg = if selected {
        ctx.theme.surface_alt
    } else {
        ctx.theme.surface
    };
    let scolor = sev_color(fnd.severity, ctx);
    let border_color = if selected {
        ctx.theme.accent
    } else {
        ctx.theme.border
    };

    // The peek card has no bottom border so it reads as "continues below".
    let borders = if peek {
        Borders::TOP | Borders::LEFT | Borders::RIGHT
    } else {
        Borders::ALL
    };
    let block = Block::default()
        .borders(borders)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(border_color))
        .style(Style::default().bg(bg))
        .padding(Padding::horizontal(1));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let stripe = Rect::new(inner.x, inner.y, 1, inner.height);
    f.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled("\u{2588}", Style::default().fg(scolor))),
            Line::from(Span::styled("\u{2588}", Style::default().fg(scolor))),
        ]),
        stripe,
    );

    let body = Rect::new(
        inner.x + 2,
        inner.y,
        inner.width.saturating_sub(2),
        inner.height,
    );

    let line1 = Line::from(vec![
        Span::styled(
            fnd.category.label().to_string(),
            Style::default().fg(ctx.theme.accent),
        ),
        Span::raw("  "),
        Span::styled(
            fnd.title.clone(),
            Style::default().fg(ctx.theme.fg).add_modifier(Modifier::BOLD),
        ),
    ]);
    let line2 = Line::from(Span::styled(
        fnd.location.display().to_string(),
        Style::default().fg(ctx.theme.fg_dim),
    ));
    let mut pills: Vec<Span> = Vec::new();
    pills.extend(
        Pill::solid(fnd.severity.label(), ctx.theme.bg, scolor)
            .bold()
            .spans_plain(),
    );
    if let Some(reason) = fnd.reasons.first() {
        pills.push(Span::raw("  "));
        pills.push(Span::styled(
            format!("• {reason}"),
            Style::default().fg(ctx.theme.fg_dim),
        ));
    }
    let line3 = Line::from(pills);

    f.render_widget(
        Paragraph::new(vec![line1, line2, line3]).wrap(Wrap { trim: true }),
        body,
    );
}
