//! Animation registry — wraps `tachyonfx`.

use std::time::Instant;

use ratatui::{
    buffer::Buffer,
    layout::{Offset, Rect},
};
use tachyonfx::{
    fx, Duration as FxDuration, Effect, EffectManager, EffectTimer, Interpolation, Motion,
};

use crate::tui::theme::Theme;

/// Tags grouping effects so they can be replaced atomically.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EffectKey {
    #[default]
    Boot,
    PanelSwitch,
    Modal,
    Confetti,
    Shake,
    Toast,
}

pub struct AnimState {
    pub started_at: Instant,
    pub last_frame: Instant,
    pub manager: EffectManager<EffectKey>,
    pub boot_done: bool,
}

impl Default for AnimState {
    fn default() -> Self {
        Self::new()
    }
}

impl AnimState {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            last_frame: Instant::now(),
            manager: EffectManager::<EffectKey>::default(),
            boot_done: false,
        }
    }

    pub fn elapsed_seconds(&self) -> f32 {
        self.started_at.elapsed().as_secs_f32()
    }

    /// Advance the effect manager by the time since last frame.
    pub fn tick_frame(&mut self, area: Rect, buf: &mut Buffer) {
        let now = Instant::now();
        let dt = now.duration_since(self.last_frame);
        self.last_frame = now;
        let fx_dt = FxDuration::from_millis(dt.as_millis().min(u32::MAX as u128) as u32);
        self.manager.process_effects(fx_dt, buf, area);
    }

    /// Push an effect onto the queue.
    pub fn add(&mut self, effect: Effect) {
        self.manager.add_effect(effect);
    }

    /// Push an effect tagged with a key, replacing any existing one with the same key.
    pub fn add_unique(&mut self, key: EffectKey, effect: Effect) {
        self.manager.add_unique_effect(key, effect);
    }

    pub fn is_running(&self) -> bool {
        self.manager.is_running()
    }
}

// ============================================================================
// Effect builders
// ============================================================================

fn t(ms: u32, easing: Interpolation) -> EffectTimer {
    EffectTimer::from_ms(ms, easing)
}

/// Boot intro — sweep + coalesce across the whole screen.
pub fn boot_intro(theme: &Theme) -> Effect {
    fx::parallel(&[
        fx::coalesce(t(700, Interpolation::CubicOut)),
        fx::sweep_in(
            Motion::LeftToRight,
            14,
            0,
            theme.bg,
            t(550, Interpolation::CubicOut),
        ),
    ])
}

/// Panel switch — just the coalesce part of the boot intro (no bg sweep), so
/// the new panel materializes in place. Scope to the body area at the call
/// site via `Effect::with_area(...)` so it only paints the region that changed.
pub fn panel_switch(_theme: &Theme) -> Effect {
    fx::coalesce(t(380, Interpolation::CubicOut))
}

/// Modal open: quick coalesce.
pub fn modal_open() -> Effect {
    fx::coalesce(t(180, Interpolation::CubicOut))
}

/// Confetti: dissolve with HSL hue spin.
pub fn confetti() -> Effect {
    fx::parallel(&[
        fx::hsl_shift(
            Some([180.0, 30.0, 0.0]),
            None,
            t(450, Interpolation::QuadOut),
        ),
        fx::dissolve(t(700, Interpolation::QuadIn)),
    ])
}

/// Shake: small horizontal jitter for failure / threat-found.
pub fn shake() -> Effect {
    fx::translate(
        fx::sleep(t(220, Interpolation::Linear)),
        Offset { x: 2, y: 0 },
        t(220, Interpolation::CubicOut),
    )
}

/// Toast pop-in.
pub fn toast(theme: &Theme) -> Effect {
    fx::fade_from_fg(theme.bg, t(220, Interpolation::CubicOut))
}
