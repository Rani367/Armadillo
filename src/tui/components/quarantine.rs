//! Quarantine panel — selectable vault list with restore/purge action buttons.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Padding, Paragraph, Wrap},
    Frame,
};

use crate::quarantine::QuarantineEntry;
use crate::report::human_bytes;
use crate::tui::{
    app::AppCtx,
    components::{card_slots, threats::draw_action_buttons, ButtonAction, Component, EventResult},
    event::Event,
    widgets::pill::Pill,
};

pub struct QuarantinePanel {
    pub selected: usize,
    pub scroll: usize,
}

impl QuarantinePanel {
    pub fn new() -> Self {
        Self {
            selected: 0,
            scroll: 0,
        }
    }
}

impl Default for QuarantinePanel {
    fn default() -> Self {
        Self::new()
    }
}

impl Component for QuarantinePanel {
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
                    " {}  quarantine · {} item(s) ",
                    ctx.icons.lock(),
                    ctx.quarantine.len()
                ),
                Style::default()
                    .fg(ctx.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ));
        let inner = block.inner(area);
        f.render_widget(block, area);

        if ctx.quarantine.is_empty() {
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    "  quarantine is empty",
                    Style::default().fg(ctx.theme.fg_dim),
                ))),
                inner,
            );
            return;
        }

        let split = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(1)])
            .split(inner);
        let list_area = split[0];

        let slots = card_slots(list_area, 4, ctx.quarantine.len(), self.selected, &mut self.scroll);
        let mut hits: Vec<Rect> = Vec::with_capacity(slots.len());
        for slot in &slots {
            draw_entry_card(
                f,
                slot.rect,
                &ctx.quarantine[slot.index],
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
                (ButtonAction::Restore, "Enter restore"),
                (ButtonAction::Purge, "x purge"),
            ],
        );
    }

    fn handle_event(&mut self, event: &Event, ctx: &mut AppCtx) -> EventResult {
        if let Event::Key(k) = event {
            use crossterm::event::KeyCode::*;
            let len = ctx.quarantine.len();
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

fn draw_entry_card(
    f: &mut Frame,
    area: Rect,
    e: &QuarantineEntry,
    selected: bool,
    peek: bool,
    ctx: &AppCtx,
) {
    let bg = if selected {
        ctx.theme.surface_alt
    } else {
        ctx.theme.surface
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

    let short = e.id.get(..8).unwrap_or(&e.id);
    let line1 = Line::from(vec![
        Span::styled(
            short.to_string(),
            Style::default().fg(ctx.theme.accent).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            e.original_path.display().to_string(),
            Style::default().fg(ctx.theme.fg),
        ),
    ]);
    let line2 = Line::from(Span::styled(
        e.quarantined_at.clone(),
        Style::default().fg(ctx.theme.fg_dim),
    ));
    let mut pills: Vec<Span> = Vec::new();
    pills.extend(
        Pill::solid(&e.verdict, ctx.theme.bg, ctx.theme.error)
            .bold()
            .spans_plain(),
    );
    pills.push(Span::raw("  "));
    pills.extend(
        Pill::soft(human_bytes(e.size), ctx.theme.fg_dim, ctx.theme.surface_alt).spans_plain(),
    );
    let line3 = Line::from(pills);

    f.render_widget(
        Paragraph::new(vec![line1, line2, line3]).wrap(Wrap { trim: true }),
        inner,
    );
}
