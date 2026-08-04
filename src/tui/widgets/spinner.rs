//! Thin wrapper around throbber-widgets-tui for ergonomic re-use.

use ratatui::{
    style::{Modifier, Style},
    widgets::StatefulWidget,
};
use throbber_widgets_tui::{Set, Throbber, ThrobberState, BRAILLE_SIX_DOUBLE};

#[derive(Default)]
pub struct AnimSpinner {
    state: ThrobberState,
}

impl AnimSpinner {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn tick(&mut self) {
        self.state.calc_next();
    }
}

pub struct SpinnerView {
    pub color: ratatui::style::Color,
    pub set: Set,
}

impl Default for SpinnerView {
    fn default() -> Self {
        Self {
            color: ratatui::style::Color::Cyan,
            set: BRAILLE_SIX_DOUBLE,
        }
    }
}

impl SpinnerView {
    pub fn color(mut self, c: ratatui::style::Color) -> Self {
        self.color = c;
        self
    }
}

impl StatefulWidget for SpinnerView {
    type State = AnimSpinner;
    fn render(
        self,
        area: ratatui::layout::Rect,
        buf: &mut ratatui::buffer::Buffer,
        state: &mut Self::State,
    ) {
        let t = Throbber::default()
            .style(Style::default().fg(self.color).add_modifier(Modifier::BOLD))
            .throbber_set(self.set);
        StatefulWidget::render(t, area, buf, &mut state.state);
    }
}
