//! Interactive TUI dashboard.
//!
//! Wires a background quick-scan and the macOS audit to a ratatui front-end via
//! the same `ScanEvent` channel + `Counters` the CLI uses. Input, scan events,
//! ticks, and 60fps render frames are multiplexed by an async `EventBus`
//! (tokio) running inside a runtime owned by [`run`] — so the public entry stays
//! synchronous and the rest of the CLI is untouched.
//!
//! The look and animations mirror the `lazycargo` TUI: animated big-text logo,
//! pill tabs, boot/panel-switch effects, and a theme system. Unlike lazycargo,
//! this TUI is fully mouse-interactive (click tabs/rows/buttons, scroll wheel).

// These modules are a reusable UI kit ported from lazycargo; not every helper,
// icon glyph, theme field, or effect builder is exercised by Armadillo yet.
#[allow(dead_code)]
mod anim;
mod app;
mod components;
#[allow(dead_code)]
mod event;
#[allow(dead_code)]
mod gradient;
#[allow(dead_code)]
mod icons;
#[allow(dead_code)]
mod theme;
#[allow(dead_code)]
mod widgets;

use std::io::Stdout;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use crossbeam_channel::unbounded;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

use app::App;
use theme::Theme;

use crate::engine::ScanEngine;
use crate::macos;
use crate::quarantine;
use crate::scan::progress::{Counters, ScanEvent};
use crate::scan::{self, targets, ScanRequest};

/// The concrete terminal type used throughout the TUI.
pub type Tui = Terminal<CrosstermBackend<Stdout>>;

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

    // Background quick scan (rayon) streaming ScanEvents over a crossbeam channel.
    {
        let engine = engine.clone();
        let counters = counters.clone();
        let cancel = cancel.clone();
        std::thread::spawn(move || {
            let request = ScanRequest::new(targets::quick_targets());
            scan::run_scan(engine, request, tx, counters, cancel);
        });
    }

    // Run the (fast) macOS audit and load the quarantine vault up front.
    let audit = macos::run_audit();
    let quarantined = quarantine::list().unwrap_or_default();
    let theme = Theme::for_name("default");

    // Own a tokio runtime locally so `run` stays callable from the sync CLI.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(async move {
        let mut terminal = init_terminal()?;
        let app = App::new(theme, counters, audit, quarantined);
        let res = app.run(&mut terminal, scan_rx).await;
        let _ = restore_terminal();
        res
    });

    cancel.store(true, Ordering::Relaxed); // stop the rayon scan
    result
}

fn init_terminal() -> Result<Tui> {
    let mut stdout = std::io::stdout();
    enable_raw_mode()?;
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    install_panic_hook();
    Ok(terminal)
}

fn restore_terminal() -> Result<()> {
    execute!(std::io::stdout(), LeaveAlternateScreen, DisableMouseCapture)?;
    disable_raw_mode()?;
    Ok(())
}

fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = restore_terminal();
        prev(info);
    }));
}
