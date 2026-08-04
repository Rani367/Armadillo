//! Threats panel — selectable card list with quarantine/delete action buttons.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Padding, Paragraph, Wrap},
    Frame,
};
use unicode_width::UnicodeWidthStr;

use crate::engine::verdict::{Threat, Verdict};
use crate::report::human_bytes;
use crate::tui::{
    app::AppCtx,
    components::{card_slots, ButtonAction, Component, EventResult},
    event::Event,
    widgets::pill::Pill,
};

pub struct ThreatsView {
    pub selected: usize,
    pub scroll: usize,
}

impl ThreatsView {
    pub fn new() -> Self {
        Self {
            selected: 0,
            scroll: 0,
        }
    }
}

impl Default for ThreatsView {
    fn default() -> Self {
        Self::new()
    }
}

impl Component for ThreatsView {
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
                    " {}  threats · {} malicious · {} suspicious ",
                    ctx.icons.fire(),
                    ctx.mal_count,
                    ctx.sus_count
                ),
                Style::default()
                    .fg(ctx.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ));
        let inner = block.inner(area);
        f.render_widget(block, area);

        if ctx.threats.is_empty() {
            let msg = if ctx.scanning {
                "scanning…  no threats yet"
            } else {
                "✓ no threats detected"
            };
            let color = if ctx.scanning {
                ctx.theme.fg_dim
            } else {
                ctx.theme.success
            };
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    format!("  {msg}"),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ))),
                inner,
            );
            return;
        }

        // Body = scrolling card list + a one-row action footer.
        let split = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(1)])
            .split(inner);
        let list_area = split[0];

        let slots = card_slots(list_area, 4, ctx.threats.len(), self.selected, &mut self.scroll);
        let mut hits: Vec<Rect> = Vec::with_capacity(slots.len());
        for slot in &slots {
            draw_threat_card(
                f,
                slot.rect,
                &ctx.threats[slot.index],
                slot.selected,
                slot.peek,
                ctx,
            );
            hits.push(slot.rect);
        }
        ctx.row_hits = hits;
        ctx.row_hit_base = self.scroll;

        draw_action_buttons(
            f,
            split[1],
            ctx,
            &[
                (ButtonAction::Quarantine, "Enter quarantine"),
                (ButtonAction::Delete, "d delete"),
            ],
        );
    }

    fn handle_event(&mut self, event: &Event, ctx: &mut AppCtx) -> EventResult {
        if let Event::Key(k) = event {
            use crossterm::event::KeyCode::*;
            let len = ctx.threats.len();
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

fn draw_threat_card(f: &mut Frame, area: Rect, t: &Threat, selected: bool, peek: bool, ctx: &AppCtx) {
    let bg = if selected {
        ctx.theme.surface_alt
    } else {
        ctx.theme.surface
    };
    let (sev_color, verdict_label) = match t.verdict {
        Verdict::Malicious => (ctx.theme.error, "malicious"),
        Verdict::Suspicious => (ctx.theme.warning, "suspicious"),
        Verdict::Clean => (ctx.theme.success, "clean"),
    };
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

    // Severity left stripe.
    let stripe = Rect::new(inner.x, inner.y, 1, inner.height);
    f.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled("\u{2588}", Style::default().fg(sev_color))),
            Line::from(Span::styled("\u{2588}", Style::default().fg(sev_color))),
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
            t.path.display().to_string(),
            Style::default().fg(ctx.theme.fg).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(human_bytes(t.size), Style::default().fg(ctx.theme.fg_dim)),
    ]);

    let det: String = t
        .detections
        .iter()
        .take(2)
        .map(|d| format!("{}:{}", d.engine.label(), d.name))
        .collect::<Vec<_>>()
        .join("  ");
    let line2 = Line::from(Span::styled(det, Style::default().fg(ctx.theme.fg_dim)));

    let mut pills: Vec<Span> = Vec::new();
    pills.extend(
        Pill::solid(verdict_label, ctx.theme.bg, sev_color)
            .bold()
            .spans_plain(),
    );
    pills.push(Span::raw("  "));
    pills.extend(
        Pill::soft(
            format!("score {}", t.score),
            ctx.theme.fg_dim,
            ctx.theme.surface_alt,
        )
        .spans_plain(),
    );
    pills.push(Span::raw("  "));
    pills.extend(
        Pill::soft(t.trust.label(), ctx.theme.info, ctx.theme.surface_alt).spans_plain(),
    );
    let line3 = Line::from(pills);

    f.render_widget(
        Paragraph::new(vec![line1, line2, line3]).wrap(Wrap { trim: true }),
        body,
    );
}

/// Draw a row of clickable action pills and record their hit-rects in `ctx`.
pub(crate) fn draw_action_buttons(
    f: &mut Frame,
    area: Rect,
    ctx: &mut AppCtx,
    buttons: &[(ButtonAction, &str)],
) {
    let mut spans: Vec<Span> = Vec::new();
    let mut hits: Vec<(ButtonAction, Rect)> = Vec::new();
    let mut x = area.x;
    let right_edge = area.x.saturating_add(area.width);
    for (action, label) in buttons {
        let text = format!(" {label} ");
        let w = UnicodeWidthStr::width(text.as_str()) as u16;
        spans.extend(
            Pill::solid(*label, ctx.theme.bg, ctx.theme.accent)
                .bold()
                .spans_plain(),
        );
        spans.push(Span::raw("  "));
        if x < right_edge {
            let vw = w.min(right_edge - x);
            hits.push((*action, Rect::new(x, area.y, vw, 1)));
        }
        x = x.saturating_add(w).saturating_add(2);
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
    ctx.button_hits = hits;
}
