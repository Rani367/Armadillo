//! Rounded chip/pill: short colored label.

use ratatui::{
    style::{Color, Modifier, Style},
    text::Span,
};

pub struct Pill {
    pub label: String,
    pub fg: Color,
    pub bg: Color,
    pub bold: bool,
}

impl Pill {
    pub fn solid(label: impl Into<String>, fg: Color, bg: Color) -> Self {
        Self {
            label: label.into(),
            fg,
            bg,
            bold: false,
        }
    }
    pub fn soft(label: impl Into<String>, fg: Color, bg: Color) -> Self {
        Self {
            label: label.into(),
            fg,
            bg,
            bold: false,
        }
    }
    pub fn bold(mut self) -> Self {
        self.bold = true;
        self
    }

    /// Render without round caps, plain rectangular background.
    pub fn spans_plain(self) -> Vec<Span<'static>> {
        let mut style = Style::default().fg(self.fg).bg(self.bg);
        if self.bold {
            style = style.add_modifier(Modifier::BOLD);
        }
        vec![Span::styled(format!(" {} ", self.label), style)]
    }
}
