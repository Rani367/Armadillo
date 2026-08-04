//! Dashboard panel — scan progress gauge, summary, recent detections.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Padding, Paragraph, Widget},
    Frame,
};

use crate::engine::verdict::{Threat, Verdict};
use crate::report::human_bytes;
use crate::tui::{
    app::AppCtx,
    components::Component,
    widgets::{
        gradient_bar::{BarPalette, GradientBar},
        spinner::SpinnerView,
    },
};

pub struct DashboardView;

impl DashboardView {
    pub fn new() -> Self {
        DashboardView
    }
}

impl Default for DashboardView {
    fn default() -> Self {
        Self::new()
    }
}

impl Component for DashboardView {
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
                format!(" {}  Dashboard ", ctx.icons.graph()),
                Style::default()
                    .fg(ctx.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ));
        let inner = block.inner(area);
        f.render_widget(block, area);

        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2), // gauge label + bar
                Constraint::Length(8), // summary
                Constraint::Min(0),    // recent detections
            ])
            .split(inner);

        self.draw_gauge(f, rows[0], ctx);
        draw_summary(f, rows[1], ctx);
        draw_recent(f, rows[2], ctx);
    }
}

impl DashboardView {
    fn draw_gauge(&self, f: &mut Frame, area: Rect, ctx: &mut AppCtx) {
        let ratio = if ctx.total > 0 {
            (ctx.snapshot.scanned as f32 / ctx.total as f32).clamp(0.0, 1.0)
        } else if ctx.scanning {
            0.0
        } else {
            1.0
        };

        let split = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Length(1)])
            .split(area);

        // Label line (spinner while scanning).
        let label = if ctx.scanning {
            format!("scanning… {}/{}", ctx.snapshot.scanned, ctx.total)
        } else if ctx.cancelled {
            "cancelled".to_string()
        } else {
            format!("complete — {}/{}", ctx.snapshot.scanned, ctx.total)
        };
        let label_color = if ctx.scanning {
            ctx.theme.accent
        } else if ctx.cancelled {
            ctx.theme.warning
        } else {
            ctx.theme.success
        };
        if ctx.scanning {
            // Spinner glyph + label.
            let spin_area = Rect::new(split[0].x, split[0].y, 2, 1);
            let s = SpinnerView::default().color(ctx.theme.accent);
            ratatui::widgets::StatefulWidget::render(s, spin_area, f.buffer_mut(), &mut ctx.spinner);
            let text_area = Rect::new(
                split[0].x + 2,
                split[0].y,
                split[0].width.saturating_sub(2),
                1,
            );
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    label,
                    Style::default().fg(label_color).add_modifier(Modifier::BOLD),
                ))),
                text_area,
            );
        } else {
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    label,
                    Style::default().fg(label_color).add_modifier(Modifier::BOLD),
                ))),
                split[0],
            );
        }

        // Progress bar.
        let palette = if ctx.scanning {
            BarPalette::Lerp(ctx.theme.accent, ctx.theme.accent_glow)
        } else {
            BarPalette::Solid(ctx.theme.success)
        };
        let bar = GradientBar::new(ratio, 1.0).palette(palette);
        bar.render(split[1], f.buffer_mut());
    }
}

fn draw_summary(f: &mut Frame, area: Rect, ctx: &AppCtx) {
    let mal = ctx.mal_count;
    let sus = ctx.sus_count;
    let audit_n = ctx.audit.findings.len();
    let audit_color = if audit_n == 0 {
        ctx.theme.success
    } else {
        ctx.theme.warning
    };

    let lines = vec![
        kv(ctx, "Files scanned", ctx.snapshot.scanned.to_string()),
        kv(ctx, "Data scanned", human_bytes(ctx.snapshot.bytes)),
        Line::from(vec![
            Span::styled("  Threats        ", Style::default().fg(ctx.theme.fg_dim)),
            Span::styled(
                format!("{mal} malicious"),
                Style::default().fg(ctx.theme.error).add_modifier(Modifier::BOLD),
            ),
            Span::styled("  ·  ", Style::default().fg(ctx.theme.fg_dim)),
            Span::styled(format!("{sus} suspicious"), Style::default().fg(ctx.theme.warning)),
        ]),
        Line::from(vec![
            Span::styled("  Audit findings ", Style::default().fg(ctx.theme.fg_dim)),
            Span::styled(audit_n.to_string(), Style::default().fg(audit_color)),
            Span::styled("    Quarantined ", Style::default().fg(ctx.theme.fg_dim)),
            Span::styled(ctx.quarantine.len().to_string(), Style::default().fg(ctx.theme.fg)),
        ]),
        kv(
            ctx,
            "Skipped / errors",
            format!("{} / {}", ctx.snapshot.skipped, ctx.snapshot.errors),
        ),
        kv(
            ctx,
            "Elapsed",
            format!("{:.1}s", ctx.start.elapsed().as_secs_f64()),
        ),
    ];
    f.render_widget(Paragraph::new(lines), area);
}

fn draw_recent(f: &mut Frame, area: Rect, ctx: &AppCtx) {
    let block = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(ctx.theme.border))
        .title(Span::styled(
            " Recent detections ",
            Style::default().fg(ctx.theme.accent),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if ctx.threats.is_empty() {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "  no detections yet",
                Style::default().fg(ctx.theme.fg_dim),
            ))),
            inner,
        );
        return;
    }

    let cap = inner.height as usize;
    let lines: Vec<Line> = ctx
        .threats
        .iter()
        .rev()
        .take(cap)
        .map(|t| threat_line(ctx, t))
        .collect();
    f.render_widget(Paragraph::new(lines), inner);
}

fn threat_line<'a>(ctx: &AppCtx, t: &'a Threat) -> Line<'a> {
    let (tag, color) = match t.verdict {
        Verdict::Malicious => (" MAL ", ctx.theme.error),
        Verdict::Suspicious => (" SUS ", ctx.theme.warning),
        Verdict::Clean => (" OK  ", ctx.theme.success),
    };
    Line::from(vec![
        Span::styled(
            tag,
            Style::default()
                .bg(color)
                .fg(ctx.theme.bg)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(t.path.display().to_string(), Style::default().fg(ctx.theme.fg)),
    ])
}

fn kv<'a>(ctx: &AppCtx, key: &str, value: String) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("  {key:<18}"), Style::default().fg(ctx.theme.fg_dim)),
        Span::styled(
            value,
            Style::default().fg(ctx.theme.fg).add_modifier(Modifier::BOLD),
        ),
    ])
}
