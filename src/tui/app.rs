//! TUI application state and update logic (immediate-mode: every frame is drawn
//! from this struct).

use std::sync::Arc;
use std::time::Instant;

use ratatui::widgets::ListState;

use crate::engine::verdict::Threat;
use crate::macos::AuditReport;
use crate::quarantine::{self, QuarantineEntry};
use crate::scan::progress::{CounterSnapshot, Counters, ScanEvent};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Threats,
    Audit,
    Quarantine,
    Help,
}

impl Tab {
    pub const ALL: [Tab; 5] = [
        Tab::Dashboard,
        Tab::Threats,
        Tab::Audit,
        Tab::Quarantine,
        Tab::Help,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Threats => "Threats",
            Tab::Audit => "Audit",
            Tab::Quarantine => "Quarantine",
            Tab::Help => "Help",
        }
    }

    pub fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }
}

pub struct App {
    pub tab: Tab,
    pub counters: Arc<Counters>,
    pub snapshot: CounterSnapshot,
    pub total: u64,
    pub scanning: bool,
    pub cancelled: bool,

    pub threats: Vec<Threat>,
    pub threat_state: ListState,

    pub audit: AuditReport,

    pub quarantine: Vec<QuarantineEntry>,
    pub quar_state: ListState,

    pub status: String,
    pub should_quit: bool,
    pub start: Instant,
}

impl App {
    pub fn new(counters: Arc<Counters>, audit: AuditReport, quarantine: Vec<QuarantineEntry>) -> Self {
        let mut quar_state = ListState::default();
        if !quarantine.is_empty() {
            quar_state.select(Some(0));
        }
        Self {
            tab: Tab::Dashboard,
            counters,
            snapshot: CounterSnapshot::default(),
            total: 0,
            scanning: true,
            cancelled: false,
            threats: Vec::new(),
            threat_state: ListState::default(),
            audit,
            quarantine,
            quar_state,
            status: "scanning… press Tab to switch views, Esc to quit".into(),
            should_quit: false,
            start: Instant::now(),
        }
    }

    pub fn on_tick(&mut self) {
        self.snapshot = self.counters.snapshot();
    }

    pub fn on_scan_event(&mut self, event: ScanEvent) {
        match event {
            ScanEvent::Started { total } => self.total = total,
            ScanEvent::Threat(t) => {
                if self.threat_state.selected().is_none() {
                    self.threat_state.select(Some(0));
                }
                self.threats.push(*t);
            }
            ScanEvent::Error { .. } => {}
            ScanEvent::Finished { cancelled } => {
                self.scanning = false;
                self.cancelled = cancelled;
                self.status = format!(
                    "scan complete — {} threat(s) found. Esc to quit.",
                    self.threats.len()
                );
            }
        }
    }

    pub fn progress_ratio(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        (self.snapshot.scanned as f64 / self.total as f64).clamp(0.0, 1.0)
    }

    // --- navigation ---

    pub fn next_tab(&mut self) {
        let i = (self.tab.index() + 1) % Tab::ALL.len();
        self.tab = Tab::ALL[i];
    }

    pub fn prev_tab(&mut self) {
        let i = (self.tab.index() + Tab::ALL.len() - 1) % Tab::ALL.len();
        self.tab = Tab::ALL[i];
    }

    pub fn select_tab(&mut self, idx: usize) {
        if idx < Tab::ALL.len() {
            self.tab = Tab::ALL[idx];
        }
    }

    pub fn move_down(&mut self) {
        match self.tab {
            Tab::Threats => Self::step(&mut self.threat_state, self.threats.len(), 1),
            Tab::Quarantine => Self::step(&mut self.quar_state, self.quarantine.len(), 1),
            _ => {}
        }
    }

    pub fn move_up(&mut self) {
        match self.tab {
            Tab::Threats => Self::step(&mut self.threat_state, self.threats.len(), -1),
            Tab::Quarantine => Self::step(&mut self.quar_state, self.quarantine.len(), -1),
            _ => {}
        }
    }

    fn step(state: &mut ListState, len: usize, delta: i32) {
        if len == 0 {
            state.select(None);
            return;
        }
        let cur = state.selected().unwrap_or(0) as i32;
        let next = (cur + delta).rem_euclid(len as i32);
        state.select(Some(next as usize));
    }

    // --- actions ---

    /// Quarantine the selected threat (Threats tab).
    pub fn quarantine_selected(&mut self) {
        let Some(i) = self.threat_state.selected() else { return };
        let Some(threat) = self.threats.get(i).cloned() else { return };
        match quarantine::quarantine_threat(&threat) {
            Ok(entry) => {
                self.status = format!("quarantined {} (id {})", threat.path.display(), &entry.id[..8]);
                self.threats.remove(i);
                self.refresh_quarantine();
                self.clamp_threat_selection();
            }
            Err(e) => self.status = format!("quarantine failed: {e}"),
        }
    }

    /// Delete the selected threat from disk (Threats tab).
    pub fn delete_selected_threat(&mut self) {
        let Some(i) = self.threat_state.selected() else { return };
        let Some(threat) = self.threats.get(i).cloned() else { return };
        match std::fs::remove_file(&threat.path) {
            Ok(()) => {
                self.status = format!("deleted {}", threat.path.display());
                self.threats.remove(i);
                self.clamp_threat_selection();
            }
            Err(e) => self.status = format!("delete failed: {e}"),
        }
    }

    /// Restore the selected quarantined item.
    pub fn restore_selected(&mut self) {
        let Some(i) = self.quar_state.selected() else { return };
        let Some(entry) = self.quarantine.get(i).cloned() else { return };
        match quarantine::restore(&entry.id) {
            Ok(path) => {
                self.status = format!("restored {}", path.display());
                self.refresh_quarantine();
            }
            Err(e) => self.status = format!("restore failed: {e}"),
        }
    }

    /// Permanently delete the selected quarantined item.
    pub fn purge_selected(&mut self) {
        let Some(i) = self.quar_state.selected() else { return };
        let Some(entry) = self.quarantine.get(i).cloned() else { return };
        match quarantine::delete(&entry.id) {
            Ok(()) => {
                self.status = format!("purged {}", &entry.id[..8]);
                self.refresh_quarantine();
            }
            Err(e) => self.status = format!("purge failed: {e}"),
        }
    }

    fn refresh_quarantine(&mut self) {
        self.quarantine = quarantine::list().unwrap_or_default();
        if self.quarantine.is_empty() {
            self.quar_state.select(None);
        } else {
            let sel = self.quar_state.selected().unwrap_or(0).min(self.quarantine.len() - 1);
            self.quar_state.select(Some(sel));
        }
    }

    fn clamp_threat_selection(&mut self) {
        if self.threats.is_empty() {
            self.threat_state.select(None);
        } else {
            let sel = self.threat_state.selected().unwrap_or(0).min(self.threats.len() - 1);
            self.threat_state.select(Some(sel));
        }
    }
}
