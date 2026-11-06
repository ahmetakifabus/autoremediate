/// Karakter sınırında güvenli kısaltma (UTF-8 bölünmesi olmaz).
pub fn truncate_chars(s: &str, max: usize) -> String {
    let mut out: String = s.chars().take(max).collect();
    if s.chars().count() > max {
        out.push('…');
    }
    out
}

/// Dizin taramalarında atlanan (üretilmiş / üçüncü taraf) dizinler
pub const SKIP_DIRS: &[&str] = &[
    ".git", "target", "node_modules", "vendor", ".next", ".nuxt", ".svelte-kit", "dist", "build", "out",
    "coverage", "bower_components", ".turbo", ".vercel",
];
