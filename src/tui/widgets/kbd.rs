//! Keyboard-key glyph chip.

use ratatui::{
    style::{Modifier, Style},
    text::Span,
};

use crate::tui::theme::Theme;

pub fn kbd<'a>(theme: &Theme, label: &'a str) -> Vec<Span<'a>> {
    let cap = Style::default().fg(theme.surface);
    let body = Style::default()
        .fg(theme.fg)
        .bg(theme.surface)
        .add_modifier(Modifier::BOLD);
    vec![
        Span::styled("\u{E0B6}", cap),
        Span::styled(format!(" {} ", label), body),
        Span::styled("\u{E0B4}", cap),
    ]
}
