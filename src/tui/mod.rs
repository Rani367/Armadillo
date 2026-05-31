//! Interactive TUI dashboard. Wires a background quick-scan and the macOS audit
//! to a ratatui front-end via the same `ScanEvent` channel + `Counters` the CLI
//! uses. Input, scan events, and a redraw tick are multiplexed with
//! `crossbeam_channel::select!`.

mod app;
mod ui;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use crossbeam_channel::{select, tick, unbounded};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};

use app::{App, Tab};

use crate::engine::ScanEngine;
use crate::macos;
use crate::quarantine;
use crate::scan::progress::{Counters, ScanEvent};
use crate::scan::{self, targets, ScanRequest};

pub fn run(engine: Arc<ScanEngine>) -> Result<()> {
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "the TUI needs an interactive terminal — run `armadillo tui` directly in a terminal \
             (use `armadillo scan` / `armadillo audit` for non-interactive use)"
        );
    }

    let counters = Counters::new();
    let cancel = Arc::new(AtomicBool::new(false));
    let (tx, scan_rx) = unbounded::<ScanEvent>();

    // Background quick scan.
    {
        let engine = engine.clone();
        let counters = counters.clone();
        let cancel = cancel.clone();
        std::thread::spawn(move || {
            let request = ScanRequest::new(targets::quick_targets());
            scan::run_scan(engine, request, tx, counters, cancel);
        });
    }

    // Run the (fast) macOS audit up front.
    let audit = macos::run_audit();
    let quarantined = quarantine::list().unwrap_or_default();
    let mut app = App::new(counters, audit, quarantined);

    // Dedicated input thread feeding a channel (so we can select! over it).
    let (input_tx, input_rx) = unbounded::<Event>();
    std::thread::spawn(move || loop {
        match event::poll(Duration::from_millis(200)) {
            Ok(true) => {
                if let Ok(ev) = event::read() {
                    if input_tx.send(ev).is_err() {
                        break;
                    }
                }
            }
            Ok(false) => {}
            Err(_) => break,
        }
    });

    let ticker = tick(Duration::from_millis(100));
    let mut terminal = ratatui::init();

    let result = run_loop(&mut terminal, &mut app, &scan_rx, &input_rx, &ticker);

    cancel.store(true, Ordering::Relaxed);
    ratatui::restore();
    result
}

fn run_loop(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    scan_rx: &crossbeam_channel::Receiver<ScanEvent>,
    input_rx: &crossbeam_channel::Receiver<Event>,
    ticker: &crossbeam_channel::Receiver<std::time::Instant>,
) -> Result<()> {
    while !app.should_quit {
        terminal.draw(|f| ui::draw(f, app))?;
        select! {
            recv(scan_rx) -> msg => if let Ok(ev) = msg { app.on_scan_event(ev); },
            recv(input_rx) -> ev => if let Ok(ev) = ev { handle_input(app, ev); },
            recv(ticker) -> _ => app.on_tick(),
        }
    }
    Ok(())
}

fn handle_input(app: &mut App, event: Event) {
    let Event::Key(key) = event else { return };
    if key.kind != KeyEventKind::Press {
        return; // ignore key-release (avoids double-firing on some platforms)
    }

    // Global quit.
    if key.code == KeyCode::Esc
        || (key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c'))
    {
        app.should_quit = true;
        return;
    }

    match key.code {
        KeyCode::Tab => app.next_tab(),
        KeyCode::BackTab => app.prev_tab(),
        KeyCode::Char(c @ '1'..='5') => app.select_tab(c as usize - '1' as usize),
        KeyCode::Down | KeyCode::Char('j') => app.move_down(),
        KeyCode::Up | KeyCode::Char('k') => app.move_up(),
        KeyCode::Char('q') if app.tab == Tab::Threats => app.quarantine_selected(),
        KeyCode::Char('d') if app.tab == Tab::Threats => app.delete_selected_threat(),
        KeyCode::Char('r') if app.tab == Tab::Quarantine => app.restore_selected(),
        KeyCode::Char('x') if app.tab == Tab::Quarantine => app.purge_selected(),
        _ => {}
    }
}
