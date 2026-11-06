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
    "coverage", "bower_components", ".turbo", ".vercel", "venv", ".venv", "__pycache__", ".tox",
    "site-packages", ".mypy_cache",
];

/// Kabuksuz komut. Windows'ta `npm`, `npx`, `yarn`, `composer` gibi araçlar
/// `.cmd`/`.bat` kabuklarıdır ve uzantısız adla bulunamaz; PATH + PATHEXT
/// üzerinden gerçek dosya çözülür.
pub fn command(prog: &str) -> tokio::process::Command {
    tokio::process::Command::new(resolve_program(prog))
}

fn resolve_program(prog: &str) -> std::path::PathBuf {
    let p = std::path::Path::new(prog);
    if !cfg!(windows) || p.extension().is_some() || p.components().count() > 1 {
        return p.to_path_buf();
    }
    let exts = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into());
    let paths = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&paths) {
        for ext in exts.split(';').filter(|e| !e.is_empty()) {
            let cand = dir.join(format!("{prog}{}", ext.to_ascii_lowercase()));
            if cand.is_file() {
                return cand;
            }
        }
    }
    p.to_path_buf()
}
