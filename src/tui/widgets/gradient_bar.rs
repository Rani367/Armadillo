//! Horizontal progress bar with heatmap gradient fill.

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    widgets::Widget,
};

use crate::tui::gradient;

pub struct GradientBar {
    pub value: f32,
    pub max: f32,
    pub palette: BarPalette,
}

#[derive(Clone, Copy)]
pub enum BarPalette {
    /// Cool→hot (blue → red).
    Heat,
    /// Solid color (single hue).
    Solid(Color),
    /// Lerp between two specific colors.
    Lerp(Color, Color),
}

impl GradientBar {
    pub fn new(value: f32, max: f32) -> Self {
        Self {
            value,
            max,
            palette: BarPalette::Heat,
        }
    }
    pub fn palette(mut self, p: BarPalette) -> Self {
        self.palette = p;
        self
    }
}

impl Widget for GradientBar {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width == 0 || area.height == 0 {
            return;
        }
        let pct = (self.value / self.max).clamp(0.0, 1.0);
        let filled = (area.width as f32 * pct).round() as u16;
        let total = area.width;

        // Use partial-block characters for sub-cell smoothing.
        let frac = (area.width as f32 * pct).fract();
        let partials = [
            '\u{2588}', '\u{2589}', '\u{258a}', '\u{258b}', '\u{258c}', '\u{258d}', '\u{258e}',
            '\u{258f}',
        ];
        let partial_idx = ((frac * 7.0).round() as usize).min(7);

        for y in 0..area.height {
            for x in 0..total {
                let t = (x as f32 + 0.5) / total as f32;
                let color = match self.palette {
                    BarPalette::Heat => gradient::heat(t),
                    BarPalette::Solid(c) => c,
                    BarPalette::Lerp(a, b) => gradient::lerp(a, b, t),
                };
                let cell = buf.cell_mut((area.x + x, area.y + y));
                if let Some(cell) = cell {
                    if x < filled {
                        cell.set_char('\u{2588}')
                            .set_style(Style::default().fg(color));
                    } else if x == filled && frac > 0.0 {
                        cell.set_char(partials[partial_idx])
                            .set_style(Style::default().fg(color));
                    } else {
                        cell.set_char('\u{2591}')
                            .set_style(Style::default().fg(color));
                    }
                }
            }
        }
    }
}
