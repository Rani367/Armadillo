//! Top header: animated 3D ASCII-art logo banner + tab pills + scan stats.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};
use unicode_width::UnicodeWidthStr;

use crate::tui::{
    app::AppCtx,
    components::Panel,
    gradient::{lerp, pulse},
};

/// "Armadillo" in the Big-Money figlet font — chunky 3D coin blocks.
const LOGO: &[&str] = &[
    r"  /$$$$$$                                          /$$ /$$ /$$ /$$          ",
    r" /$$__  $$                                        | $$|__/| $$| $$          ",
    r"| $$  \ $$  /$$$$$$  /$$$$$$/$$$$   /$$$$$$   /$$$$$$$ /$$| $$| $$  /$$$$$$ ",
    r"| $$$$$$$$ /$$__  $$| $$_  $$_  $$ |____  $$ /$$__  $$| $$| $$| $$ /$$__  $$",
    r"| $$__  $$| $$  \__/| $$ \ $$ \ $$  /$$$$$$$| $$  | $$| $$| $$| $$| $$  \ $$",
    r"| $$  | $$| $$      | $$ | $$ | $$ /$$__  $$| $$  | $$| $$| $$| $$| $$  | $$",
    r"| $$  | $$| $$      | $$ | $$ | $$|  $$$$$$$|  $$$$$$$| $$| $$| $$|  $$$$$$/",
    r"|__/  |__/|__/      |__/ |__/ |__/ \_______/ \_______/|__/|__/|__/ \______/ ",
];

pub struct HeaderView;

impl HeaderView {
    pub fn new() -> Self {
        HeaderView
    }

    /// Rows the logo banner occupies (used by the root layout).
    pub const LOGO_ROWS: u16 = LOGO.len() as u16;

    /// Draw the animated logo banner across the full width — the exact art,
    /// every character clearly visible, with a left-to-right gradient that
    /// drifts over time so the whole word shimmers.
    pub fn draw_banner(&self, f: &mut Frame, area: Rect, ctx: &AppCtx) {
        let phase = pulse(ctx.anim.elapsed_seconds(), 6.0);
        // Width of the art block (ignoring trailing padding) so we can center the
        // whole banner by a single uniform offset — centering each line on its own
        // width would skew the art since the lines differ in length.
        let art_width = LOGO
            .iter()
            .map(|l| l.trim_end().chars().count())
            .max()
            .unwrap_or(1) as u16;
        let maxw = art_width.max(1) as f32;

        let lines: Vec<Line> = LOGO
            .iter()
            .map(|row| {
                let spans: Vec<Span<'static>> = row
                    .chars()
                    .enumerate()
                    .map(|(x, c)| {
                        if c == ' ' {
                            return Span::raw(" ");
                        }
                        let t = ((x as f32 / maxw) + phase).rem_euclid(1.0);
                        let tt = if t < 0.5 { t * 2.0 } else { (1.0 - t) * 2.0 };
                        let color = lerp(ctx.theme.accent, ctx.theme.accent_glow, tt);
                        Span::styled(
                            c.to_string(),
                            Style::default().fg(color).add_modifier(Modifier::BOLD),
                        )
                    })
                    .collect();
                Line::from(spans)
            })
            .collect();

        // Center the whole block by shifting every line the same amount.
        let offset = area.width.saturating_sub(art_width) / 2;
        let target = Rect::new(
            area.x + offset,
            area.y,
            area.width.saturating_sub(offset),
            area.height,
        );
        f.render_widget(Paragraph::new(lines), target);
    }

    /// Draw the nav row: tab pills on the left, compact scan stats on the right.
    pub fn draw_navbar(&self, f: &mut Frame, area: Rect, ctx: &mut AppCtx, focused: Panel) {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(tab_strip_width()), // tabs (always fit)
                Constraint::Min(0),                    // stats (remainder)
            ])
            .split(area);
        self.draw_tabs(f, cols[0], ctx, focused);
        draw_stats(f, cols[1], ctx);
    }

    fn draw_tabs(&self, f: &mut Frame, area: Rect, ctx: &mut AppCtx, focused: Panel) {
        // Compact pill row (number + label), recording hit-rects for clicks.
        let mut spans = Vec::with_capacity(Panel::ALL.len() * 3);
        let mut x = area.x;
        let right_edge = area.x.saturating_add(area.width);
        for (i, p) in Panel::ALL.iter().enumerate() {
            let active = *p == focused;
            let body_text = format!("{} {}", i + 1, p.title());
            let pill_width: u16;
            if active {
                let cap_style = Style::default().fg(ctx.theme.accent);
                let body_style = Style::default()
                    .fg(ctx.theme.bg)
                    .bg(ctx.theme.accent)
                    .add_modifier(Modifier::BOLD);
                spans.push(Span::styled("\u{E0B6}", cap_style));
                spans.push(Span::styled(body_text.clone(), body_style));
                spans.push(Span::styled("\u{E0B4}", cap_style));
                pill_width = (UnicodeWidthStr::width(body_text.as_str()) as u16).saturating_add(2);
            } else {
                let s = format!(" {body_text} ");
                pill_width = UnicodeWidthStr::width(s.as_str()) as u16;
                spans.push(Span::styled(s, Style::default().fg(ctx.theme.fg_dim)));
            }
            if x < right_edge {
                let w = pill_width.min(right_edge - x);
                ctx.tab_hits.push((*p, Rect::new(x, area.y, w, 1)));
            }
            x = x.saturating_add(pill_width);
        }
        f.render_widget(Paragraph::new(Line::from(spans)), area);
    }
}

fn draw_stats(f: &mut Frame, area: Rect, ctx: &AppCtx) {
    let threats = ctx.mal_count + ctx.sus_count;
    let (state_icon, state_text, state_color) = if ctx.scanning {
        (ctx.icons.running(), "scanning…", ctx.theme.accent)
    } else if ctx.cancelled {
        (ctx.icons.warn(), "cancelled", ctx.theme.warning)
    } else {
        (ctx.icons.check_circle(), "complete", ctx.theme.success)
    };
    let threat_color = if threats > 0 {
        ctx.theme.error
    } else {
        ctx.theme.fg_dim
    };

    let spans = vec![
        Span::styled(format!("{state_icon} "), Style::default().fg(state_color)),
        Span::styled(
            state_text.to_string(),
            Style::default().fg(state_color).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  ·  {} scanned  ·  ", ctx.snapshot.scanned),
            Style::default().fg(ctx.theme.fg_dim),
        ),
        Span::styled(format!("{} ", ctx.icons.fire()), Style::default().fg(threat_color)),
        Span::styled(
            format!("{threats} threats "),
            Style::default().fg(threat_color),
        ),
    ];
    f.render_widget(
        Paragraph::new(Line::from(spans)).alignment(ratatui::layout::Alignment::Right),
        area,
    );
}

/// Total width of the tab strip — each pill is `"<n> <title>"` plus 2 cells
/// (powerline caps when active, leading+trailing space when inactive), so the
/// width is independent of which tab is focused. Kept in sync with `draw_tabs`.
fn tab_strip_width() -> u16 {
    Panel::ALL
        .iter()
        .enumerate()
        .map(|(i, p)| {
            UnicodeWidthStr::width(format!("{} {}", i + 1, p.title()).as_str()) as u16 + 2
        })
        .sum()
}

impl Default for HeaderView {
    fn default() -> Self {
        Self::new()
    }
}
