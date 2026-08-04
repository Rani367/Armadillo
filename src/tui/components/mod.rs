//! UI components. Each panel implements [`Component`] and is owned by `App`.

use ratatui::{layout::Rect, Frame};

use crate::tui::{app::AppCtx, event::Event};

pub mod audit;
pub mod dashboard;
pub mod header;
pub mod help;
pub mod modal;
pub mod quarantine;
pub mod status;
pub mod threats;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // `Quit` is part of the Component contract; not all panels use it.
pub enum EventResult {
    Consumed,
    NotHandled,
    Quit,
}

/// A clickable action button recorded during draw and dispatched on click.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonAction {
    Quarantine,
    Delete,
    Restore,
    Purge,
}

/// Top-level panels reachable via number keys / Tab cycle / tab clicks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Panel {
    Dashboard,
    Threats,
    Audit,
    Quarantine,
}

impl Panel {
    pub const ALL: &'static [Panel] = &[
        Panel::Dashboard,
        Panel::Threats,
        Panel::Audit,
        Panel::Quarantine,
    ];

    pub fn next(self) -> Self {
        let idx = Self::ALL.iter().position(|p| *p == self).unwrap_or(0);
        Self::ALL[(idx + 1) % Self::ALL.len()]
    }
    pub fn prev(self) -> Self {
        let idx = Self::ALL.iter().position(|p| *p == self).unwrap_or(0);
        let n = Self::ALL.len();
        Self::ALL[(idx + n - 1) % n]
    }
    pub fn from_digit(c: char) -> Option<Self> {
        let i = c.to_digit(10)? as usize;
        if i == 0 {
            return None;
        }
        Self::ALL.get(i - 1).copied()
    }
    pub fn title(self) -> &'static str {
        match self {
            Panel::Dashboard => "Dashboard",
            Panel::Threats => "Threats",
            Panel::Audit => "Audit",
            Panel::Quarantine => "Quarantine",
        }
    }
}

/// One card's placement, produced by [`card_slots`].
#[derive(Debug, Clone, Copy)]
pub struct CardSlot {
    pub index: usize,
    pub rect: Rect,
    pub selected: bool,
    /// The partially-revealed card at the bottom that hints "more below".
    pub peek: bool,
}

/// Lay out a vertical list of fixed-height cards within `area`, keeping the
/// selected card fully visible and revealing a partial "peek" of the next card
/// whenever more items exist below — so the user can see there's more to scroll.
/// Mutates `scroll` to follow the selection.
pub fn card_slots(
    area: Rect,
    row_h: u16,
    count: usize,
    selected: usize,
    scroll: &mut usize,
) -> Vec<CardSlot> {
    if count == 0 || area.height == 0 || row_h == 0 {
        *scroll = 0;
        return Vec::new();
    }
    // Reserve at least one row beyond the full cards so the next one can always
    // peek; `fit` is the number of fully-visible cards.
    let fit = ((area.height.saturating_sub(1)) / row_h).max(1) as usize;

    if selected < *scroll {
        *scroll = selected;
    } else if selected >= *scroll + fit {
        *scroll = selected + 1 - fit;
    }
    *scroll = (*scroll).min(count.saturating_sub(1));

    let bottom = area.y + area.height;
    let mut slots = Vec::new();
    let mut y = area.y;
    for index in *scroll..(*scroll + fit).min(count) {
        slots.push(CardSlot {
            index,
            rect: Rect::new(area.x, y, area.width, row_h),
            selected: index == selected,
            peek: false,
        });
        y += row_h;
    }
    // Partial peek of the next card, if any, in whatever rows are left.
    let next = *scroll + fit;
    if next < count && y < bottom {
        let avail = bottom - y;
        let ph = avail.min(row_h.saturating_sub(1)).max(1);
        slots.push(CardSlot {
            index: next,
            rect: Rect::new(area.x, y, area.width, ph),
            selected: false,
            peek: true,
        });
    }
    slots
}

/// Component trait implemented by every panel.
pub trait Component {
    fn draw(&mut self, f: &mut Frame, area: Rect, focused: bool, ctx: &mut AppCtx);
    fn handle_event(&mut self, _event: &Event, _ctx: &mut AppCtx) -> EventResult {
        EventResult::NotHandled
    }
}
