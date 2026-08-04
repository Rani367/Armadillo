//! Built-in themes and the [`Theme`] struct.
//!
//! Each theme defines a cohesive palette tuned for a glowing,
//! gradient-friendly visual style.

use ratatui::style::Color;

#[derive(Debug, Clone)]
pub struct Theme {
    pub name: &'static str,

    // Base
    pub bg: Color,
    pub fg: Color,
    pub fg_dim: Color,
    pub border: Color,

    // Brand
    pub accent: Color,
    pub accent_alt: Color,
    pub accent_glow: Color,

    // Surfaces
    pub surface: Color,
    pub surface_alt: Color,
    pub highlight_bg: Color,

    // Semantics
    pub warning: Color,
    pub error: Color,
    pub success: Color,
    pub info: Color,
}

impl Theme {
    pub fn for_name(name: &str) -> Self {
        match name {
            "dracula" => DRACULA,
            "catppuccin" | "catppuccin-mocha" => CATPPUCCIN,
            "nord" => NORD,
            "gruvbox" => GRUVBOX,
            "tokyo-night" | "tokyo" => TOKYO_NIGHT,
            "dark" => DEFAULT,
            _ => DEFAULT,
        }
    }

    pub fn all_names() -> &'static [&'static str] {
        &[
            "default",
            "dracula",
            "catppuccin",
            "nord",
            "gruvbox",
            "tokyo-night",
        ]
    }
}

pub const DEFAULT: Theme = Theme {
    name: "default",
    bg: Color::Rgb(20, 22, 30),
    fg: Color::Rgb(210, 215, 230),
    fg_dim: Color::Rgb(112, 120, 140),
    border: Color::Rgb(60, 64, 80),
    accent: Color::Rgb(122, 162, 247),
    accent_alt: Color::Rgb(187, 154, 247),
    accent_glow: Color::Rgb(168, 198, 255),
    surface: Color::Rgb(32, 36, 50),
    surface_alt: Color::Rgb(40, 44, 60),
    highlight_bg: Color::Rgb(46, 52, 72),
    warning: Color::Rgb(245, 199, 82),
    error: Color::Rgb(247, 118, 142),
    success: Color::Rgb(158, 206, 106),
    info: Color::Rgb(125, 207, 255),
};

pub const DRACULA: Theme = Theme {
    name: "dracula",
    bg: Color::Rgb(40, 42, 54),
    fg: Color::Rgb(248, 248, 242),
    fg_dim: Color::Rgb(98, 114, 164),
    border: Color::Rgb(68, 71, 90),
    accent: Color::Rgb(189, 147, 249),
    accent_alt: Color::Rgb(255, 121, 198),
    accent_glow: Color::Rgb(232, 198, 255),
    surface: Color::Rgb(52, 55, 70),
    surface_alt: Color::Rgb(68, 71, 90),
    highlight_bg: Color::Rgb(80, 80, 110),
    warning: Color::Rgb(255, 184, 108),
    error: Color::Rgb(255, 85, 85),
    success: Color::Rgb(80, 250, 123),
    info: Color::Rgb(139, 233, 253),
};

pub const CATPPUCCIN: Theme = Theme {
    name: "catppuccin",
    bg: Color::Rgb(30, 30, 46),
    fg: Color::Rgb(205, 214, 244),
    fg_dim: Color::Rgb(127, 132, 156),
    border: Color::Rgb(69, 71, 90),
    accent: Color::Rgb(203, 166, 247),
    accent_alt: Color::Rgb(245, 194, 231),
    accent_glow: Color::Rgb(224, 200, 255),
    surface: Color::Rgb(49, 50, 68),
    surface_alt: Color::Rgb(58, 60, 78),
    highlight_bg: Color::Rgb(69, 71, 90),
    warning: Color::Rgb(249, 226, 175),
    error: Color::Rgb(243, 139, 168),
    success: Color::Rgb(166, 227, 161),
    info: Color::Rgb(137, 220, 235),
};

pub const NORD: Theme = Theme {
    name: "nord",
    bg: Color::Rgb(46, 52, 64),
    fg: Color::Rgb(216, 222, 233),
    fg_dim: Color::Rgb(110, 117, 132),
    border: Color::Rgb(76, 86, 106),
    accent: Color::Rgb(136, 192, 208),
    accent_alt: Color::Rgb(143, 188, 187),
    accent_glow: Color::Rgb(180, 220, 230),
    surface: Color::Rgb(59, 66, 82),
    surface_alt: Color::Rgb(67, 76, 94),
    highlight_bg: Color::Rgb(67, 76, 94),
    warning: Color::Rgb(235, 203, 139),
    error: Color::Rgb(191, 97, 106),
    success: Color::Rgb(163, 190, 140),
    info: Color::Rgb(129, 161, 193),
};

pub const GRUVBOX: Theme = Theme {
    name: "gruvbox",
    bg: Color::Rgb(40, 40, 40),
    fg: Color::Rgb(235, 219, 178),
    fg_dim: Color::Rgb(146, 131, 116),
    border: Color::Rgb(80, 73, 69),
    accent: Color::Rgb(254, 128, 25),
    accent_alt: Color::Rgb(250, 189, 47),
    accent_glow: Color::Rgb(255, 175, 80),
    surface: Color::Rgb(50, 48, 47),
    surface_alt: Color::Rgb(60, 56, 54),
    highlight_bg: Color::Rgb(60, 56, 54),
    warning: Color::Rgb(250, 189, 47),
    error: Color::Rgb(251, 73, 52),
    success: Color::Rgb(184, 187, 38),
    info: Color::Rgb(131, 165, 152),
};

pub const TOKYO_NIGHT: Theme = Theme {
    name: "tokyo-night",
    bg: Color::Rgb(26, 27, 38),
    fg: Color::Rgb(192, 202, 245),
    fg_dim: Color::Rgb(86, 95, 137),
    border: Color::Rgb(65, 72, 104),
    accent: Color::Rgb(122, 162, 247),
    accent_alt: Color::Rgb(187, 154, 247),
    accent_glow: Color::Rgb(168, 198, 255),
    surface: Color::Rgb(32, 33, 47),
    surface_alt: Color::Rgb(41, 46, 66),
    highlight_bg: Color::Rgb(41, 46, 66),
    warning: Color::Rgb(224, 175, 104),
    error: Color::Rgb(247, 118, 142),
    success: Color::Rgb(158, 206, 106),
    info: Color::Rgb(125, 207, 255),
};
