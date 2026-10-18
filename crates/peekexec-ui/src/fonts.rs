//! egui's built-in fonts lack arrows and warning signs. DejaVu, installed
//! almost everywhere, is added as a fallback when found at a root-owned
//! system path; otherwise the dialog uses ASCII stand-ins.

use std::os::unix::fs::MetadataExt;
use std::sync::Arc;

use eframe::egui::{self, FontData, FontDefinitions, FontFamily};

pub struct Glyphs {
    pub arrow: &'static str,
    pub warn: &'static str,
    pub ok: &'static str,
    pub cont: char,
}

const UNICODE: Glyphs = Glyphs {
    arrow: " ← ",
    warn: "⚠",
    ok: "✔",
    cont: '↳',
};

const ASCII: Glyphs = Glyphs {
    arrow: " < ",
    warn: "!",
    ok: "ok:",
    cont: '+',
};

const DIRS: &[&str] = &[
    "/usr/share/fonts/truetype/dejavu",        // Debian, Ubuntu
    "/usr/share/fonts/dejavu-sans-fonts",      // Fedora
    "/usr/share/fonts/dejavu-sans-mono-fonts", // Fedora
    "/usr/share/fonts/TTF",                    // Arch
    "/usr/share/fonts/dejavu",                 // Alpine, openSUSE
];

fn load(file: &str) -> Option<Vec<u8>> {
    DIRS.iter().find_map(|dir| {
        let path = format!("{dir}/{file}");
        let meta = std::fs::metadata(&path).ok()?;
        (meta.uid() == 0 && meta.mode() & 0o022 == 0)
            .then(|| std::fs::read(&path).ok())
            .flatten()
    })
}

pub fn install(ctx: &egui::Context) -> &'static Glyphs {
    let (Some(sans), Some(mono)) = (load("DejaVuSans.ttf"), load("DejaVuSansMono.ttf")) else {
        return &ASCII;
    };
    let mut fonts = FontDefinitions::default();
    fonts
        .font_data
        .insert("dejavu-sans".into(), Arc::new(FontData::from_owned(sans)));
    fonts
        .font_data
        .insert("dejavu-mono".into(), Arc::new(FontData::from_owned(mono)));
    for (family, name) in [
        (FontFamily::Proportional, "dejavu-sans"),
        (FontFamily::Monospace, "dejavu-mono"),
    ] {
        fonts.families.entry(family).or_default().push(name.into());
    }
    ctx.set_fonts(fonts);
    &UNICODE
}
