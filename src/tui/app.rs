//! Top-level application state, focus routing, mouse handling, async main loop.

use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Position, Rect},
    Frame,
};
use tokio::sync::mpsc;

use crate::engine::verdict::{Threat, Verdict};
use crate::macos::AuditReport;
use crate::quarantine::{self, QuarantineEntry};
use crate::scan::progress::{CounterSnapshot, Counters, ScanEvent};

use crate::tui::{
    anim::{self, AnimState, EffectKey},
    components::{
        audit::AuditView,
        dashboard::DashboardView,
        header::HeaderView,
        help::HelpOverlay,
        modal::{Modal, ModalAction, ModalKind},
        quarantine::QuarantinePanel,
        status::StatusBar,
        threats::ThreatsView,
        ButtonAction, Component, EventResult, Panel,
    },
    event::{Event, EventBus},
    icons::IconSet,
    theme::Theme,
    widgets::spinner::AnimSpinner,
    Tui,
};

const TICK_MS: u64 = 250;
const FPS: f32 = 60.0;

#[derive(Debug, Clone)]
pub struct Notification {
    pub level: NotifLevel,
    pub message: String,
    pub created_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifLevel {
    Info,
    Success,
    Warn,
    Error,
}

/// Shared context passed to every component during draw/event handling.
pub struct AppCtx {
    pub theme: Theme,
    pub icons: IconSet,
    pub event_tx: mpsc::UnboundedSender<Event>,
    pub anim: AnimState,
    pub spinner: AnimSpinner,
    pub should_quit: bool,
    pub active_modal: Option<Modal>,
    pub help_open: bool,
    pub notifications: Vec<Notification>,

    // --- scan state (sampled on Tick / updated on Scan) ---
    pub counters: Arc<Counters>,
    pub snapshot: CounterSnapshot,
    pub total: u64,
    pub scanning: bool,
    pub cancelled: bool,
    pub start: Instant,

    // --- domain data owned centrally so every panel can read it ---
    pub threats: Vec<Threat>,
    pub quarantine: Vec<QuarantineEntry>,
    pub audit: AuditReport,

    // --- derived summary counts ---
    pub mal_count: usize,
    pub sus_count: usize,

    // --- mouse hit-test rects, cleared & refilled every frame ---
    pub tab_hits: Vec<(Panel, Rect)>,
    pub row_hits: Vec<Rect>,
    pub row_hit_base: usize,
    pub button_hits: Vec<(ButtonAction, Rect)>,
}

impl AppCtx {
    pub fn push_notif(&mut self, level: NotifLevel, msg: impl Into<String>) {
        self.notifications.push(Notification {
            level,
            message: msg.into(),
            created_at: Instant::now(),
        });
    }
}

pub struct App {
    pub ctx: AppCtx,
    pub focused: Panel,
    pub header: HeaderView,
    pub dashboard: DashboardView,
    pub threats: ThreatsView,
    pub audit: AuditView,
    pub quarantine: QuarantinePanel,
    pub help: HelpOverlay,
    pub status: StatusBar,
    /// Body rect cached from the last draw, used to scope the panel-switch effect.
    body_area: Rect,
}

impl App {
    pub fn new(
        theme: Theme,
        counters: Arc<Counters>,
        audit: AuditReport,
        quarantine: Vec<QuarantineEntry>,
    ) -> Self {
        let (placeholder_tx, _placeholder_rx) = mpsc::unbounded_channel();
        Self {
            ctx: AppCtx {
                theme,
                icons: IconSet::detect(),
                event_tx: placeholder_tx,
                anim: AnimState::new(),
                spinner: AnimSpinner::new(),
                should_quit: false,
                active_modal: None,
                help_open: false,
                notifications: Vec::new(),
                counters,
                snapshot: CounterSnapshot::default(),
                total: 0,
                scanning: true,
                cancelled: false,
                start: Instant::now(),
                threats: Vec::new(),
                quarantine,
                audit,
                mal_count: 0,
                sus_count: 0,
                tab_hits: Vec::new(),
                row_hits: Vec::new(),
                row_hit_base: 0,
                button_hits: Vec::new(),
            },
            focused: Panel::Dashboard,
            header: HeaderView::new(),
            dashboard: DashboardView::new(),
            threats: ThreatsView::new(),
            audit: AuditView::new(),
            quarantine: QuarantinePanel::new(),
            help: HelpOverlay::new(),
            status: StatusBar::new(),
            body_area: Rect::default(),
        }
    }

    pub async fn run(
        mut self,
        terminal: &mut Tui,
        scan_rx: crossbeam_channel::Receiver<ScanEvent>,
    ) -> Result<()> {
        let mut bus = EventBus::new(TICK_MS, FPS);
        self.ctx.event_tx = bus.sender();

        // Bridge the (blocking) crossbeam scan channel into the async event bus.
        {
            let tx = bus.sender();
            std::thread::spawn(move || {
                while let Ok(ev) = scan_rx.recv() {
                    if tx.send(Event::Scan(ev)).is_err() {
                        break;
                    }
                }
            });
        }

        // Boot intro animation.
        let intro = anim::boot_intro(&self.ctx.theme);
        self.ctx.anim.add_unique(EffectKey::Boot, intro);

        while !self.ctx.should_quit {
            match bus.next().await {
                Some(Event::Quit) => break,
                Some(Event::Render) => {
                    terminal.draw(|f| self.draw(f))?;
                }
                Some(ev) => self.handle_event(ev),
                None => break,
            }
        }
        bus.shutdown();
        Ok(())
    }

    // ====================================================================
    // Event handling
    // ====================================================================

    fn handle_event(&mut self, ev: Event) {
        match ev {
            Event::Tick => self.on_tick(),
            Event::Scan(s) => self.handle_scan(s),
            Event::Key(k) => self.on_key(k),
            Event::Mouse(m) => self.on_mouse(m),
            _ => {}
        }
    }

    fn on_tick(&mut self) {
        self.ctx.snapshot = self.ctx.counters.snapshot();
        if self.ctx.scanning {
            self.ctx.spinner.tick();
        }
    }

    fn handle_scan(&mut self, ev: ScanEvent) {
        match ev {
            ScanEvent::Started { total } => self.ctx.total = total,
            ScanEvent::Threat(t) => {
                match t.verdict {
                    Verdict::Malicious => self.ctx.mal_count += 1,
                    Verdict::Suspicious => self.ctx.sus_count += 1,
                    Verdict::Clean => {}
                }
                if self.ctx.threats.is_empty() {
                    self.threats.selected = 0;
                }
                self.ctx.threats.push(*t);
                let shake = anim::shake();
                self.ctx.anim.add_unique(EffectKey::Shake, shake);
            }
            ScanEvent::Error { .. } => {}
            ScanEvent::Finished { cancelled } => {
                self.ctx.scanning = false;
                self.ctx.cancelled = cancelled;
                if cancelled {
                    self.ctx.push_notif(NotifLevel::Warn, "Scan cancelled");
                } else if self.ctx.threats.is_empty() {
                    let confetti = anim::confetti();
                    self.ctx.anim.add_unique(EffectKey::Confetti, confetti);
                    self.ctx
                        .push_notif(NotifLevel::Success, "Scan complete — no threats");
                } else {
                    let n = self.ctx.threats.len();
                    self.ctx
                        .push_notif(NotifLevel::Info, format!("Scan complete — {n} threat(s)"));
                }
            }
        }
    }

    fn on_key(&mut self, k: KeyEvent) {
        if k.kind != KeyEventKind::Press {
            return; // ignore key-release (avoids double-firing on some platforms)
        }

        // Modal absorbs everything until resolved.
        if self.ctx.active_modal.is_some() {
            if let Some(action) = Modal::handle_key(&mut self.ctx, k) {
                self.dispatch_modal_action(action);
            }
            return;
        }

        // Help overlay absorbs everything until closed.
        if self.ctx.help_open {
            if matches!(k.code, KeyCode::Esc | KeyCode::Char('?')) {
                self.ctx.help_open = false;
            }
            return;
        }

        // Global quit.
        if (k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c'))
            || matches!(k.code, KeyCode::Esc | KeyCode::Char('q'))
        {
            self.ctx.should_quit = true;
            return;
        }

        // Global navigation / overlays.
        match k.code {
            KeyCode::Char('?') => {
                self.ctx.help_open = true;
                return;
            }
            KeyCode::Tab | KeyCode::Right => {
                self.focused = self.focused.next();
                self.queue_panel_switch_effect();
                return;
            }
            KeyCode::BackTab | KeyCode::Left => {
                self.focused = self.focused.prev();
                self.queue_panel_switch_effect();
                return;
            }
            KeyCode::Char(c @ '1'..='9') => {
                if let Some(p) = Panel::from_digit(c) {
                    if p != self.focused {
                        self.focused = p;
                        self.queue_panel_switch_effect();
                    }
                    return;
                }
            }
            _ => {}
        }

        // Panel action keys (centralized so they can mutate shared state).
        match (self.focused, k.code) {
            (Panel::Threats, KeyCode::Enter) => {
                self.quarantine_selected();
                return;
            }
            (Panel::Threats, KeyCode::Char('d')) => {
                self.confirm_delete_selected();
                return;
            }
            (Panel::Quarantine, KeyCode::Enter) => {
                self.restore_selected();
                return;
            }
            (Panel::Quarantine, KeyCode::Char('x')) => {
                self.confirm_purge_selected();
                return;
            }
            _ => {}
        }

        // Otherwise route navigation to the focused panel.
        let event = Event::Key(k);
        let result = match self.focused {
            Panel::Dashboard => self.dashboard.handle_event(&event, &mut self.ctx),
            Panel::Threats => self.threats.handle_event(&event, &mut self.ctx),
            Panel::Audit => self.audit.handle_event(&event, &mut self.ctx),
            Panel::Quarantine => self.quarantine.handle_event(&event, &mut self.ctx),
        };
        if matches!(result, EventResult::Quit) {
            self.ctx.should_quit = true;
        }
    }

    fn on_mouse(&mut self, m: MouseEvent) {
        if self.ctx.active_modal.is_some() || self.ctx.help_open {
            return;
        }
        let pos = Position {
            x: m.column,
            y: m.row,
        };
        match m.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                // 1. Tab click → switch panel.
                if let Some((panel, _)) = self
                    .ctx
                    .tab_hits
                    .iter()
                    .copied()
                    .find(|(_, r)| r.contains(pos))
                {
                    if panel != self.focused {
                        self.focused = panel;
                        self.queue_panel_switch_effect();
                    }
                    return;
                }
                // 2. Action button click.
                if let Some((action, _)) = self
                    .ctx
                    .button_hits
                    .iter()
                    .copied()
                    .find(|(_, r)| r.contains(pos))
                {
                    self.dispatch_button(action);
                    return;
                }
                // 3. Row click → select.
                if let Some(i) = self.ctx.row_hits.iter().position(|r| r.contains(pos)) {
                    let idx = self.ctx.row_hit_base + i;
                    self.select_in_focused(idx);
                }
            }
            MouseEventKind::ScrollDown => self.scroll_focused(1),
            MouseEventKind::ScrollUp => self.scroll_focused(-1),
            _ => {}
        }
    }

    // ====================================================================
    // Selection helpers (shared by keyboard + mouse)
    // ====================================================================

    fn focused_len(&self) -> usize {
        match self.focused {
            Panel::Dashboard => 0,
            Panel::Threats => self.ctx.threats.len(),
            Panel::Audit => self.ctx.audit.findings.len(),
            Panel::Quarantine => self.ctx.quarantine.len(),
        }
    }

    fn select_in_focused(&mut self, idx: usize) {
        let len = self.focused_len();
        if len == 0 {
            return;
        }
        let idx = idx.min(len - 1);
        match self.focused {
            Panel::Threats => self.threats.selected = idx,
            Panel::Audit => self.audit.selected = idx,
            Panel::Quarantine => self.quarantine.selected = idx,
            Panel::Dashboard => {}
        }
    }

    fn scroll_focused(&mut self, delta: i32) {
        let len = self.focused_len();
        if len == 0 {
            return;
        }
        let cur = match self.focused {
            Panel::Threats => self.threats.selected,
            Panel::Audit => self.audit.selected,
            Panel::Quarantine => self.quarantine.selected,
            Panel::Dashboard => return,
        } as i32;
        let next = (cur + delta).clamp(0, len as i32 - 1) as usize;
        self.select_in_focused(next);
    }

    fn queue_panel_switch_effect(&mut self) {
        if self.body_area.width == 0 || self.body_area.height == 0 {
            return;
        }
        let fx = anim::panel_switch(&self.ctx.theme).with_area(self.body_area);
        self.ctx.anim.add_unique(EffectKey::PanelSwitch, fx);
    }

    // ====================================================================
    // Actions
    // ====================================================================

    fn dispatch_button(&mut self, action: ButtonAction) {
        match action {
            ButtonAction::Quarantine => self.quarantine_selected(),
            ButtonAction::Delete => self.confirm_delete_selected(),
            ButtonAction::Restore => self.restore_selected(),
            ButtonAction::Purge => self.confirm_purge_selected(),
        }
    }

    fn quarantine_selected(&mut self) {
        let i = self.threats.selected;
        let Some(threat) = self.ctx.threats.get(i).cloned() else {
            return;
        };
        match quarantine::quarantine_threat(&threat) {
            Ok(entry) => {
                self.remove_threat(i, threat.verdict);
                self.refresh_quarantine();
                self.ctx.push_notif(
                    NotifLevel::Success,
                    format!("quarantined {} (id {})", threat.path.display(), &entry.id[..8]),
                );
            }
            Err(e) => self
                .ctx
                .push_notif(NotifLevel::Error, format!("quarantine failed: {e}")),
        }
    }

    fn confirm_delete_selected(&mut self) {
        let i = self.threats.selected;
        let Some(threat) = self.ctx.threats.get(i) else {
            return;
        };
        self.ctx.active_modal = Some(Modal {
            title: " Delete from disk ".into(),
            message: format!(
                "Permanently delete {} from disk? This cannot be undone.",
                threat.path.display()
            ),
            kind: ModalKind::Confirm {
                payload: format!("delete:{i}"),
            },
        });
        let fx = anim::modal_open();
        self.ctx.anim.add_unique(EffectKey::Modal, fx);
    }

    fn restore_selected(&mut self) {
        let i = self.quarantine.selected;
        let Some(entry) = self.ctx.quarantine.get(i).cloned() else {
            return;
        };
        match quarantine::restore(&entry.id) {
            Ok(path) => {
                self.refresh_quarantine();
                self.ctx
                    .push_notif(NotifLevel::Success, format!("restored {}", path.display()));
            }
            Err(e) => self
                .ctx
                .push_notif(NotifLevel::Error, format!("restore failed: {e}")),
        }
    }

    fn confirm_purge_selected(&mut self) {
        let i = self.quarantine.selected;
        let Some(entry) = self.ctx.quarantine.get(i) else {
            return;
        };
        self.ctx.active_modal = Some(Modal {
            title: " Purge ".into(),
            message: format!(
                "Permanently purge quarantined item {} ? This cannot be undone.",
                &entry.id[..8]
            ),
            kind: ModalKind::Confirm {
                payload: format!("purge:{}", entry.id),
            },
        });
        let fx = anim::modal_open();
        self.ctx.anim.add_unique(EffectKey::Modal, fx);
    }

    fn dispatch_modal_action(&mut self, action: ModalAction) {
        match action {
            ModalAction::Close => self.ctx.active_modal = None,
            ModalAction::Confirm(payload) => {
                self.ctx.active_modal = None;
                self.run_modal_payload(&payload);
            }
        }
    }

    fn run_modal_payload(&mut self, payload: &str) {
        let (kind, rest) = payload.split_once(':').unwrap_or((payload, ""));
        match kind {
            "delete" => {
                if let Ok(idx) = rest.parse::<usize>() {
                    self.do_delete(idx);
                }
            }
            "purge" => self.do_purge(rest),
            _ => {}
        }
    }

    fn do_delete(&mut self, idx: usize) {
        let Some(threat) = self.ctx.threats.get(idx).cloned() else {
            return;
        };
        match std::fs::remove_file(&threat.path) {
            Ok(()) => {
                self.remove_threat(idx, threat.verdict);
                self.ctx
                    .push_notif(NotifLevel::Success, format!("deleted {}", threat.path.display()));
            }
            Err(e) => self
                .ctx
                .push_notif(NotifLevel::Error, format!("delete failed: {e}")),
        }
    }

    fn do_purge(&mut self, id: &str) {
        match quarantine::delete(id) {
            Ok(()) => {
                self.refresh_quarantine();
                let short = id.get(..8).unwrap_or(id);
                self.ctx
                    .push_notif(NotifLevel::Success, format!("purged {short}"));
            }
            Err(e) => self
                .ctx
                .push_notif(NotifLevel::Error, format!("purge failed: {e}")),
        }
    }

    fn remove_threat(&mut self, idx: usize, verdict: Verdict) {
        if idx >= self.ctx.threats.len() {
            return;
        }
        self.ctx.threats.remove(idx);
        match verdict {
            Verdict::Malicious => self.ctx.mal_count = self.ctx.mal_count.saturating_sub(1),
            Verdict::Suspicious => self.ctx.sus_count = self.ctx.sus_count.saturating_sub(1),
            Verdict::Clean => {}
        }
        let len = self.ctx.threats.len();
        if len == 0 {
            self.threats.selected = 0;
        } else if self.threats.selected >= len {
            self.threats.selected = len - 1;
        }
    }

    fn refresh_quarantine(&mut self) {
        self.ctx.quarantine = quarantine::list().unwrap_or_default();
        let len = self.ctx.quarantine.len();
        if len == 0 {
            self.quarantine.selected = 0;
        } else if self.quarantine.selected >= len {
            self.quarantine.selected = len - 1;
        }
    }

    fn expire_notifications(&mut self) {
        let now = Instant::now();
        self.ctx
            .notifications
            .retain(|n| now.duration_since(n.created_at) < std::time::Duration::from_secs(5));
    }

    // ====================================================================
    // Rendering
    // ====================================================================

    pub fn draw(&mut self, f: &mut Frame) {
        self.expire_notifications();
        self.ctx.tab_hits.clear();
        self.ctx.row_hits.clear();
        self.ctx.button_hits.clear();

        let area = f.area();
        let root = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(HeaderView::LOGO_ROWS), // 3D ASCII-art banner
                Constraint::Length(1),                     // nav row (tabs + stats)
                Constraint::Min(0),                        // body
                Constraint::Length(1),                     // status bar
            ])
            .split(area);

        self.body_area = root[2];
        self.header.draw_banner(f, root[0], &self.ctx);
        self.header.draw_navbar(f, root[1], &mut self.ctx, self.focused);
        self.draw_body(f, root[2]);
        self.status.draw_with(f, root[3], &self.ctx, self.focused);

        if self.ctx.help_open {
            self.help.draw_overlay(f, area, &self.ctx, self.focused);
        }
        if let Some(modal) = self.ctx.active_modal.clone() {
            modal.draw_overlay(f, area, &self.ctx);
        }

        // Post-render: advance any registered effects across the whole frame.
        self.ctx.anim.tick_frame(area, f.buffer_mut());
    }

    fn draw_body(&mut self, f: &mut Frame, area: Rect) {
        match self.focused {
            Panel::Dashboard => self.dashboard.draw(f, area, true, &mut self.ctx),
            Panel::Threats => self.threats.draw(f, area, true, &mut self.ctx),
            Panel::Audit => self.audit.draw(f, area, true, &mut self.ctx),
            Panel::Quarantine => self.quarantine.draw(f, area, true, &mut self.ctx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::verdict::{Detection, Engine, Severity, Threat, TrustTier};
    use crate::macos::{AuditCategory, AuditFinding};
    use crossterm::event::{MouseButton, MouseEventKind};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn sample_threat() -> Threat {
        Threat {
            path: "/Users/x/Downloads/evil.app/Contents/MacOS/evil".into(),
            sha256: "deadbeef".repeat(8),
            size: 4096,
            trust: TrustTier::Unsigned,
            score: 95,
            verdict: Verdict::Malicious,
            severity: Severity::High,
            detections: vec![Detection::new(
                Engine::Yara,
                "MacOS.Trojan.Generic",
                80,
                Severity::High,
                true,
                "matched bundled rule",
            )],
        }
    }

    fn sample_app() -> App {
        let counters = Counters::new();
        let audit = AuditReport {
            findings: vec![AuditFinding {
                category: AuditCategory::LaunchAgent,
                location: "/Users/x/Library/LaunchAgents/com.evil.plist".into(),
                title: "Auto-restarting agent from a temp path".into(),
                severity: Severity::Medium,
                reasons: vec!["RunAtLoad + KeepAlive".into(), "program in /tmp".into()],
            }],
            inspected: 42,
        };
        let quarantine = vec![QuarantineEntry {
            id: "abcd1234 effff".replace(' ', ""),
            original_path: "/Users/x/bad.sh".into(),
            sha256: "h".into(),
            size: 256,
            original_mode: 0o644,
            quarantined_at: "2026-01-01T00:00:00+00:00".into(),
            verdict: "malicious".into(),
            detections: vec!["script:obfuscation".into()],
        }];
        let mut app = App::new(Theme::for_name("default"), counters, audit, quarantine);
        app.ctx.threats.push(sample_threat());
        app.ctx.mal_count = 1;
        app.ctx.total = 100;
        app.ctx.snapshot.scanned = 37;
        app
    }

    fn draw_once(app: &mut App) -> Terminal<TestBackend> {
        let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        terminal
    }

    #[test]
    fn every_panel_renders_without_panic() {
        let mut app = sample_app();
        for panel in Panel::ALL.iter().copied() {
            app.focused = panel;
            draw_once(&mut app);
            // The header always records one hit-rect per tab.
            assert_eq!(app.ctx.tab_hits.len(), Panel::ALL.len());
        }
    }

    fn row_text(term: &Terminal<TestBackend>, y: u16) -> String {
        let buf = term.backend().buffer();
        let w = buf.area().width;
        (0..w)
            .map(|x| buf.cell((x, y)).map(|c| c.symbol()).unwrap_or(" "))
            .collect()
    }

    #[test]
    fn overflowing_list_reveals_a_peek_card() {
        use crate::tui::components::card_slots;
        let area = Rect::new(0, 0, 40, 9); // room for 2 full 4-row cards + a sliver
        let mut scroll = 0;
        // Plenty of items, selection at the top.
        let slots = card_slots(area, 4, 20, 0, &mut scroll);
        assert!(slots.len() >= 2, "expected full cards plus a peek");
        let last = slots.last().unwrap();
        assert!(last.peek, "the bottom card should be a partial peek");
        assert!(!last.selected, "the peek is never the selected row");
        assert!(last.rect.height < 4, "the peek is shorter than a full card");
        // Selected card is fully visible (not the peek).
        assert!(slots.iter().any(|s| s.selected && !s.peek));

        // When everything fits, there is no peek.
        let tall = Rect::new(0, 0, 40, 40);
        let mut s2 = 0;
        let slots2 = card_slots(tall, 4, 3, 0, &mut s2);
        assert_eq!(slots2.len(), 3);
        assert!(slots2.iter().all(|s| !s.peek));
    }

    #[test]
    fn all_four_tabs_fit_on_a_narrow_terminal() {
        // Regression: the tab strip used to clip after "Threats" (hiding Audit /
        // Quarantine), and later clipped the final "e" of Quarantine when the
        // stats column was over-reserved. The strip now reserves exactly its own
        // width, so all four tabs render in full even on tight terminals.
        for width in [120, 101, 96, 90] {
            let mut app = sample_app();
            let mut terminal = Terminal::new(TestBackend::new(width, 40)).unwrap();
            terminal.draw(|f| app.draw(f)).unwrap();
            // Tab strip is the nav row directly beneath the logo banner.
            let tabs = row_text(&terminal, HeaderView::LOGO_ROWS);
            for label in ["Dashboard", "Threats", "Audit", "Quarantine"] {
                assert!(
                    tabs.contains(label),
                    "tab '{label}' clipped at width {width} in: {tabs:?}"
                );
            }
            assert_eq!(app.ctx.tab_hits.len(), 4);
        }
    }

    #[test]
    fn threats_panel_records_row_and_button_hits() {
        let mut app = sample_app();
        app.focused = Panel::Threats;
        draw_once(&mut app);
        assert!(!app.ctx.row_hits.is_empty(), "threat rows should be clickable");
        assert_eq!(app.ctx.button_hits.len(), 2, "quarantine + delete buttons");
    }

    #[test]
    fn overlays_render_without_panic() {
        let mut app = sample_app();
        app.ctx.help_open = true;
        draw_once(&mut app);
        app.ctx.help_open = false;
        app.confirm_delete_selected(); // opens a Confirm modal
        assert!(app.ctx.active_modal.is_some());
        draw_once(&mut app);
    }

    #[test]
    fn clicking_a_tab_switches_panel() {
        let mut app = sample_app();
        draw_once(&mut app); // populate tab_hits
        let (target_panel, rect) = app.ctx.tab_hits[2];
        assert_ne!(target_panel, app.focused);
        let click = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: rect.x,
            row: rect.y,
            modifiers: crossterm::event::KeyModifiers::NONE,
        };
        app.on_mouse(click);
        assert_eq!(app.focused, target_panel);
    }

    #[test]
    fn clicking_a_threat_row_selects_it() {
        let mut app = sample_app();
        app.ctx.threats.push(sample_threat());
        app.ctx.threats.push(sample_threat());
        app.focused = Panel::Threats;
        draw_once(&mut app);
        // Click the 3rd row (index 2) if it was laid out.
        if app.ctx.row_hits.len() >= 3 {
            let rect = app.ctx.row_hits[2];
            let click = MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: rect.x,
                row: rect.y,
                modifiers: crossterm::event::KeyModifiers::NONE,
            };
            app.on_mouse(click);
            assert_eq!(app.threats.selected, app.ctx.row_hit_base + 2);
        }
    }
}
