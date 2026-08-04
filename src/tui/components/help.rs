//! Help overlay (`?`) — 3-column kbd grid.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Padding, Paragraph, Wrap},
    Frame,
};

use crate::tui::{app::AppCtx, components::Panel, widgets::kbd::kbd};

#[derive(Default)]
pub struct HelpOverlay;

impl HelpOverlay {
    pub fn new() -> Self {
        HelpOverlay
    }

    pub fn draw_overlay(&self, f: &mut Frame, area: Rect, ctx: &AppCtx, focused: Panel) {
        let w = (area.width as f32 * 0.78) as u16;
        let h = (area.height as f32 * 0.75) as u16;
        let x = area.x + (area.width.saturating_sub(w)) / 2;
        let y = area.y + (area.height.saturating_sub(h)) / 2;
        let dialog = Rect::new(x, y, w, h);
        f.render_widget(Clear, dialog);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(ctx.theme.accent_glow))
            .padding(Padding::new(2, 2, 1, 1))
            .style(Style::default().bg(ctx.theme.surface))
            .title(Span::styled(
                format!(" {}  help · ? or Esc closes ", ctx.icons.question()),
                Style::default()
                    .fg(ctx.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ));
        let inner = block.inner(dialog);
        f.render_widget(block, dialog);

        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(33),
                Constraint::Percentage(33),
                Constraint::Percentage(34),
            ])
            .split(inner);

        let global = vec![
            section(ctx, "Global"),
            kv(ctx, "q", "quit"),
            kv(ctx, "Tab", "next panel"),
            kv(ctx, "S-Tab", "prev panel"),
            kv(ctx, "1-4", "jump panel"),
            kv(ctx, "?", "help"),
            kv(ctx, "Esc", "quit / close"),
            kv(ctx, "Ctrl-C", "quit"),
        ];
        let nav = vec![
            section(ctx, "Navigation"),
            kv(ctx, "j / ↓", "down"),
            kv(ctx, "k / ↑", "up"),
            kv(ctx, "g", "first"),
            kv(ctx, "G", "last"),
            Line::raw(""),
            section(ctx, "Mouse"),
            kv(ctx, "click", "tab / row / button"),
            kv(ctx, "wheel", "scroll list"),
        ];
        let mut panel_section = vec![section(ctx, &format!("{} keys", focused.title()))];
        match focused {
            Panel::Threats => {
                panel_section.push(kv(ctx, "Enter", "quarantine"));
                panel_section.push(kv(ctx, "d", "delete from disk"));
            }
            Panel::Quarantine => {
                panel_section.push(kv(ctx, "Enter", "restore"));
                panel_section.push(kv(ctx, "x", "purge (permanent)"));
            }
            Panel::Audit | Panel::Dashboard => {
                panel_section.push(Line::from(Span::styled(
                    "  (read-only)",
                    Style::default().fg(ctx.theme.fg_dim),
                )));
            }
        }

        f.render_widget(Paragraph::new(global).wrap(Wrap { trim: false }), cols[0]);
        f.render_widget(Paragraph::new(nav).wrap(Wrap { trim: false }), cols[1]);
        f.render_widget(
            Paragraph::new(panel_section).wrap(Wrap { trim: false }),
            cols[2],
        );
    }
}

fn section<'a>(ctx: &AppCtx, label: &str) -> Line<'a> {
    Line::from(vec![
        Span::raw(""),
        Span::styled(
            label.to_string(),
            Style::default()
                .fg(ctx.theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(""),
    ])
}

fn kv<'a>(ctx: &AppCtx, key: &'a str, val: &str) -> Line<'a> {
    let mut spans = kbd(&ctx.theme, key);
    spans.push(Span::raw("  "));
    spans.push(Span::styled(val.to_string(), Style::default().fg(ctx.theme.fg)));
    Line::from(spans)
}
