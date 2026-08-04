//! Color gradient helpers (RGB linear interpolation + HSL ramps).

use palette::{FromColor, Hsl, Srgb};
use ratatui::style::Color;

/// Linear-RGB lerp between two ratatui colors. Falls back to `a` if either is non-RGB.
pub fn lerp(a: Color, b: Color, t: f32) -> Color {
    let (ar, ag, ab) = to_rgb(a);
    let (br, bg, bb) = to_rgb(b);
    let t = t.clamp(0.0, 1.0);
    Color::Rgb(
        ((ar as f32) * (1.0 - t) + (br as f32) * t) as u8,
        ((ag as f32) * (1.0 - t) + (bg as f32) * t) as u8,
        ((ab as f32) * (1.0 - t) + (bb as f32) * t) as u8,
    )
}

/// Sample an HSL ramp at `t` in [0, 1]. Hue goes from `h0` → `h1` (degrees),
/// constant saturation/lightness.
pub fn hsl_ramp(h0: f32, h1: f32, s: f32, l: f32, t: f32) -> Color {
    let t = t.clamp(0.0, 1.0);
    let h = h0 + (h1 - h0) * t;
    let hsl: Hsl = Hsl::new(h, s, l);
    let rgb: Srgb<f32> = Srgb::from_color(hsl);
    let (r, g, b) = (
        (rgb.red.clamp(0.0, 1.0) * 255.0) as u8,
        (rgb.green.clamp(0.0, 1.0) * 255.0) as u8,
        (rgb.blue.clamp(0.0, 1.0) * 255.0) as u8,
    );
    Color::Rgb(r, g, b)
}

/// Cool→hot heatmap ramp (blue 230° → red 0°) — useful for binary-size, latency, etc.
pub fn heat(t: f32) -> Color {
    hsl_ramp(230.0, 0.0, 0.65, 0.55, t)
}

/// Pulse: 0..1..0 sinusoid based on absolute time in seconds.
pub fn pulse(elapsed_seconds: f32, period_seconds: f32) -> f32 {
    let phase = (elapsed_seconds % period_seconds) / period_seconds;
    0.5 - 0.5 * (phase * std::f32::consts::TAU).cos()
}

fn to_rgb(c: Color) -> (u8, u8, u8) {
    match c {
        Color::Rgb(r, g, b) => (r, g, b),
        Color::Reset => (0, 0, 0),
        Color::Black => (0, 0, 0),
        Color::Red => (205, 49, 49),
        Color::Green => (13, 188, 121),
        Color::Yellow => (229, 229, 16),
        Color::Blue => (36, 114, 200),
        Color::Magenta => (188, 63, 188),
        Color::Cyan => (17, 168, 205),
        Color::Gray => (200, 200, 200),
        Color::DarkGray => (102, 102, 102),
        Color::LightRed => (241, 76, 76),
        Color::LightGreen => (35, 209, 139),
        Color::LightYellow => (245, 245, 67),
        Color::LightBlue => (59, 142, 234),
        Color::LightMagenta => (214, 112, 214),
        Color::LightCyan => (41, 184, 219),
        Color::White => (229, 229, 229),
        Color::Indexed(_) => (128, 128, 128),
    }
}
