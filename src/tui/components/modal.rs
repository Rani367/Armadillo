//! Modal dialog (confirmation / info).

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Padding, Paragraph, Wrap},
    Frame,
};

use crate::tui::{app::AppCtx, widgets::pill::Pill};

#[derive(Debug, Clone)]
pub struct Modal {
    pub title: String,
    pub message: String,
    pub kind: ModalKind,
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // `Info` modals are part of the kit; Armadillo only uses Confirm so far.
pub enum ModalKind {
    Confirm { payload: String },
    Info,
}

#[derive(Debug, Clone)]
pub enum ModalAction {
    Close,
    Confirm(String),
}

impl Modal {
    pub fn handle_key(ctx: &mut AppCtx, key: KeyEvent) -> Option<ModalAction> {
        let modal = ctx.active_modal.as_ref()?.clone();
        match key.code {
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('q') => Some(ModalAction::Close),
            KeyCode::Enter | KeyCode::Char('y') => match modal.kind {
                ModalKind::Confirm { payload } => Some(ModalAction::Confirm(payload)),
                ModalKind::Info => Some(ModalAction::Close),
            },
            _ => None,
        }
    }

    pub fn draw_overlay(&self, f: &mut Frame, area: Rect, ctx: &AppCtx) {
        let w = (area.width as f32 * 0.45) as u16;
        let h = 10u16.min(area.height);
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
                format!(" {} ", self.title),
                Style::default()
                    .fg(ctx.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ));
        let inner = block.inner(dialog);
        f.render_widget(block, dialog);

        let parts = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(0),
                Constraint::Length(1),
                Constraint::Length(1),
            ])
            .split(inner);

        let msg = Paragraph::new(Line::from(Span::styled(
            self.message.clone(),
            Style::default().fg(ctx.theme.fg),
        )))
        .wrap(Wrap { trim: false });
        f.render_widget(msg, parts[0]);

        // Button row.
        let mut buttons: Vec<Span> = Vec::new();
        match self.kind {
            ModalKind::Confirm { .. } => {
                buttons.extend(
                    Pill::solid("Enter / y", ctx.theme.bg, ctx.theme.accent)
                        .bold()
                        .spans_plain(),
                );
                buttons.push(Span::raw("  confirm    "));
                buttons.extend(
                    Pill::soft("Esc / n", ctx.theme.fg_dim, ctx.theme.surface_alt).spans_plain(),
                );
                buttons.push(Span::raw("  cancel"));
            }
            ModalKind::Info => {
                buttons.extend(
                    Pill::solid("Enter", ctx.theme.bg, ctx.theme.accent)
                        .bold()
                        .spans_plain(),
                );
                buttons.push(Span::raw("  dismiss"));
            }
        }
        let btn = Paragraph::new(Line::from(buttons));
        f.render_widget(btn, parts[2]);
    }
}
