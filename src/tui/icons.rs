//! Nerd-font icon set with ASCII fallback.

use std::env;

#[derive(Debug, Clone, Copy)]
pub enum IconKind {
    NerdFont,
    Ascii,
}

#[derive(Debug, Clone, Copy)]
pub struct IconSet {
    pub kind: IconKind,
}

impl IconSet {
    pub fn detect() -> Self {
        if let Ok(v) = env::var("ARMADILLO_NERD_FONT") {
            return match v.to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => Self {
                    kind: IconKind::NerdFont,
                },
                _ => Self {
                    kind: IconKind::Ascii,
                },
            };
        }
        // Heuristic: most modern dev terminals ship nerd-font glyphs.
        let term_program = env::var("TERM_PROGRAM").unwrap_or_default();
        let lc_terminal = env::var("LC_TERMINAL").unwrap_or_default();
        let term = env::var("TERM").unwrap_or_default();
        let likely = matches!(
            term_program.as_str(),
            "WezTerm" | "ghostty" | "Kitty" | "iTerm.app" | "Alacritty"
        ) || lc_terminal == "iTerm2"
            || term.contains("kitty")
            || term.contains("ghostty")
            || term.contains("alacritty");
        Self {
            kind: if likely {
                IconKind::NerdFont
            } else {
                IconKind::Ascii
            },
        }
    }

    pub fn is_nf(self) -> bool {
        matches!(self.kind, IconKind::NerdFont)
    }
}

macro_rules! icon {
    ($name:ident, $nf:expr, $ascii:expr) => {
        pub fn $name(self) -> &'static str {
            if self.is_nf() {
                $nf
            } else {
                $ascii
            }
        }
    };
}

impl IconSet {
    icon!(package, "\u{f487}", "[pkg]");
    icon!(rust, "\u{e7a8}", "av");
    icon!(ok, "\u{f00c}", "ok");
    icon!(err, "\u{f00d}", "x");
    icon!(warn, "\u{f071}", "!");
    icon!(info, "\u{f05a}", "i");
    icon!(running, "\u{f04b}", ">");
    icon!(fire, "\u{f490}", "!!");
    icon!(clock, "\u{f017}", "@");
    icon!(disk, "\u{f0a0}", "#");
    icon!(graph, "\u{f201}", "~");
    icon!(arrow_right, "\u{f061}", "->");
    icon!(arrow_up, "\u{f062}", "^");
    icon!(arrow_down, "\u{f063}", "v");
    icon!(bullet, "\u{f111}", "*");
    icon!(shield, "\u{f3ed}", "#");
    icon!(book, "\u{f02d}", "D");
    icon!(folder, "\u{f07b}", "/");
    icon!(skull, "\u{f0f8}", "X");
    icon!(lock, "\u{f023}", "[L]");
    icon!(trash, "\u{f1f8}", "[del]");
    icon!(check_circle, "\u{f058}", "(ok)");
    icon!(x_circle, "\u{f057}", "(x)");
    icon!(question, "\u{f128}", "?");
}
