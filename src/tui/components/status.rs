//! Bottom status bar: breadcrumb + activity pulse + key hints.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

use crate::tui::{
    app::AppCtx,
    components::Panel,
    gradient::{lerp, pulse},
};

#[derive(Default)]
pub struct StatusBar;

impl StatusBar {
    pub fn new() -> Self {
        StatusBar
    }

    pub fn draw_with(&self, f: &mut Frame, area: Rect, ctx: &AppCtx, focused: Panel) {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(20), Constraint::Length(40)])
            .split(area);

        // Left: breadcrumb + last notification.
        let left_spans = breadcrumb_spans(ctx, focused);
        let left = Paragraph::new(Line::from(left_spans));
        f.render_widget(left, cols[0]);

        // Right: activity pulse + key hints.
        let phase = pulse(ctx.anim.elapsed_seconds(), 1.4);
        let dot_color = lerp(ctx.theme.fg_dim, ctx.theme.accent_glow, phase);
        let busy = ctx.anim.is_running() || ctx.scanning;
        let dot = if busy {
            Span::styled("\u{2022} ", Style::default().fg(dot_color))
        } else {
            Span::styled("\u{2022} ", Style::default().fg(ctx.theme.fg_dim))
        };

        let mut hint_spans: Vec<Span> = vec![dot];
        for (k, v) in [("q", "quit"), ("?", "help"), ("Tab", "next")] {
            hint_spans.push(Span::styled(
                format!(" {} ", k),
                Style::default()
                    .fg(ctx.theme.fg)
                    .bg(ctx.theme.surface)
                    .add_modifier(Modifier::BOLD),
            ));
            hint_spans.push(Span::styled(
                format!(" {}  ", v),
                Style::default().fg(ctx.theme.fg_dim),
            ));
        }
        let right =
            Paragraph::new(Line::from(hint_spans)).alignment(ratatui::layout::Alignment::Right);
        f.render_widget(right, cols[1]);
    }
}

fn breadcrumb_spans<'a>(ctx: &'a AppCtx, focused: Panel) -> Vec<Span<'a>> {
    let last_notif = ctx.notifications.last();
    if let Some(n) = last_notif {
        let icon = match n.level {
            crate::tui::app::NotifLevel::Info => ctx.icons.info(),
            crate::tui::app::NotifLevel::Success => ctx.icons.check_circle(),
            crate::tui::app::NotifLevel::Warn => ctx.icons.warn(),
            crate::tui::app::NotifLevel::Error => ctx.icons.err(),
        };
        let color = match n.level {
            crate::tui::app::NotifLevel::Info => ctx.theme.info,
            crate::tui::app::NotifLevel::Success => ctx.theme.success,
            crate::tui::app::NotifLevel::Warn => ctx.theme.warning,
            crate::tui::app::NotifLevel::Error => ctx.theme.error,
        };
        return vec![
            Span::styled(format!(" {} ", icon), Style::default().fg(color)),
            Span::styled(n.message.clone(), Style::default().fg(color)),
        ];
    }
    vec![
        Span::styled(
            format!(" {} ", ctx.icons.rust()),
            Style::default()
                .fg(ctx.theme.bg)
                .bg(ctx.theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "\u{E0B0}",
            Style::default().fg(ctx.theme.accent).bg(ctx.theme.surface),
        ),
        Span::styled(
            format!(" {} ", focused.title()),
            Style::default()
                .fg(ctx.theme.fg)
                .bg(ctx.theme.surface)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("\u{E0B0}", Style::default().fg(ctx.theme.surface)),
    ]
}
