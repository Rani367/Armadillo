//! Async event loop: multiplexes crossterm input, periodic ticks,
//! render frames at 60fps, and background scan events onto one mpsc.

use std::time::Duration;

use crossterm::event::{Event as CtEvent, EventStream, KeyEvent, MouseEvent};
use futures::StreamExt;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::scan::progress::ScanEvent;

#[derive(Debug)]
pub enum Event {
    /// Periodic data refresh (counter sampling, notification expiry).
    Tick,
    /// High-frequency render frame (60fps default).
    Render,
    Key(KeyEvent),
    Mouse(MouseEvent),
    Resize(u16, u16),
    Paste(String),
    FocusGained,
    FocusLost,
    /// A discrete event from the background scan (threat found, finished, …).
    Scan(ScanEvent),
    Quit,
}

pub struct EventBus {
    rx: mpsc::UnboundedReceiver<Event>,
    pub tx: mpsc::UnboundedSender<Event>,
    pub cancel: CancellationToken,
}

impl EventBus {
    pub fn new(tick_ms: u64, frame_rate: f32) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let cancel = CancellationToken::new();

        spawn_input_task(tx.clone(), cancel.clone());
        spawn_tick_task(tx.clone(), cancel.clone(), tick_ms);
        spawn_render_task(tx.clone(), cancel.clone(), frame_rate.max(1.0));

        Self { rx, tx, cancel }
    }

    pub async fn next(&mut self) -> Option<Event> {
        self.rx.recv().await
    }

    pub fn sender(&self) -> mpsc::UnboundedSender<Event> {
        self.tx.clone()
    }

    pub fn shutdown(&self) {
        self.cancel.cancel();
    }
}

fn spawn_input_task(tx: mpsc::UnboundedSender<Event>, cancel: CancellationToken) {
    tokio::spawn(async move {
        let mut stream = EventStream::new();
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                maybe = stream.next() => match maybe {
                    Some(Ok(evt)) => {
                        let mapped = match evt {
                            CtEvent::Key(k) => Some(Event::Key(k)),
                            CtEvent::Mouse(m) => Some(Event::Mouse(m)),
                            CtEvent::Resize(w, h) => Some(Event::Resize(w, h)),
                            CtEvent::Paste(s) => Some(Event::Paste(s)),
                            CtEvent::FocusGained => Some(Event::FocusGained),
                            CtEvent::FocusLost => Some(Event::FocusLost),
                        };
                        if let Some(e) = mapped {
                            if tx.send(e).is_err() {
                                break;
                            }
                        }
                    }
                    Some(Err(e)) => {
                        tracing::warn!("input stream error: {e}");
                    }
                    None => break,
                }
            }
        }
    });
}

fn spawn_tick_task(tx: mpsc::UnboundedSender<Event>, cancel: CancellationToken, tick_ms: u64) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(tick_ms));
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = interval.tick() => {
                    if tx.send(Event::Tick).is_err() {
                        break;
                    }
                }
            }
        }
    });
}

fn spawn_render_task(tx: mpsc::UnboundedSender<Event>, cancel: CancellationToken, fps: f32) {
    tokio::spawn(async move {
        let period = Duration::from_secs_f32(1.0 / fps);
        let mut interval = tokio::time::interval(period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = interval.tick() => {
                    if tx.send(Event::Render).is_err() {
                        break;
                    }
                }
            }
        }
    });
}
