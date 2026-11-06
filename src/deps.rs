//! 4) Bağımlılık (tedarik zinciri) denetimi
//!
//! React2Shell (CVE-2025-55182) gibi açıklar uygulama kodunda değil,
//! framework'ün kendisindedir; kod taraması bunları göremez. Bu modül kilit
//! dosyalarındaki (package-lock.json, yarn.lock, pnpm-lock.yaml,
//! composer.lock, Cargo.lock) kesin sürümleri çıkarır ve:
//!   * çevrimdışı çalışan yerleşik kritik açık tablosuyla (`ADVISORIES`),
//!   * isteğe bağlı olarak OSV veritabanıyla (`osv` modülü, `--osv`)
//! karşılaştırır.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use tracing::warn;

use crate::scanner::Severity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum Ecosystem {
    #[serde(rename = "npm")]
    Npm,
    #[serde(rename = "Packagist")]
    Packagist,
    #[serde(rename = "crates.io")]
    Crates,
    #[serde(rename = "PyPI")]
    PyPI,
    #[serde(rename = "Go")]
    Go,
}

impl Ecosystem {
    pub fn osv_name(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Packagist => "Packagist",
            Ecosystem::Crates => "crates.io",
            Ecosystem::PyPI => "PyPI",
            Ecosystem::Go => "Go",
        }
    }

    pub fn upgrade_hint(self, name: &str, version: &str) -> String {
        match self {
            Ecosystem::Npm => format!("npm install {name}@{version}"),
            Ecosystem::Packagist => format!("composer require \"{name}:^{version}\" -W"),
            Ecosystem::Crates => format!("cargo update -p {name} --precise {version}"),
            Ecosystem::PyPI => format!("pip install \"{name}=={version}\"  (requirements dosyasını da güncelleyin)"),
            Ecosystem::Go => format!("go get {name}@v{version} && go mod tidy"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dependency {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    pub manifest: PathBuf,
    /// Kilit dosyası yoktu; sürüm package.json aralığının alt sınırından tahmin edildi
    pub approximate: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DepFinding {
    pub ecosystem: Ecosystem,
    pub package: String,
    pub version: String,
    pub manifest: PathBuf,
    pub approximate: bool,
    pub id: String,
    pub aliases: Vec<String>,
    pub severity: Severity,
    pub summary: String,
    /// Bu sürümü düzelten en küçük sürüm
    pub fixed: Option<String>,
    /// "yerleşik" | "osv"
    pub origin: &'static str,
}

// ---- Sürüm karşılaştırma (semver + Next.js canary / composer biçimleri) ---

#[derive(Debug, Clone, PartialEq, Eq)]
enum Pre {
    Num(u64),
    Alpha(String),
}

impl Ord for Pre {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Pre::Num(a), Pre::Num(b)) => a.cmp(b),
            (Pre::Num(_), Pre::Alpha(_)) => Ordering::Less,
            (Pre::Alpha(_), Pre::Num(_)) => Ordering::Greater,
            (Pre::Alpha(a), Pre::Alpha(b)) => a.cmp(b),
        }
    }
}
impl PartialOrd for Pre {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone)]
pub struct Version {
    core: Vec<u64>,
    pre: Vec<Pre>,
}

impl Version {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().trim_start_matches(['v', 'V', '=']);
        let s = s.split('+').next()?;
        let (core_s, pre_s) = match s.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (s, None),
        };
        let core: Vec<u64> = core_s.split('.').map(|p| p.parse().ok()).collect::<Option<_>>()?;
        if core.is_empty() || core.len() > 4 {
            return None;
        }
        let pre = pre_s
            .map(|p| {
                p.split('.')
                    .map(|id| id.parse::<u64>().map(Pre::Num).unwrap_or_else(|_| Pre::Alpha(id.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        Some(Self { core, pre })
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        let n = self.core.len().max(other.core.len());
        for i in 0..n {
            let (a, b) = (self.core.get(i).copied().unwrap_or(0), other.core.get(i).copied().unwrap_or(0));
            match a.cmp(&b) {
                Ordering::Equal => {}
                o => return o,
            }
        }
        // Ön sürüm (canary/rc) < kararlı sürüm
        match (self.pre.is_empty(), other.pre.is_empty()) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => self.pre.cmp(&other.pre),
        }
    }
}
impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for Version {}
impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// ---- Yerleşik (çevrimdışı) kritik açık tablosu ----------------------------
//
// Aralıklar [başlangıç, üst sınır) biçimindedir; üçüncü alan önerilen sürümdür.
// Kaynak: react.dev ve nextjs.org güvenlik bültenleri (Aralık 2025, Mart 2025).
// Tablo bilerek küçük tutuldu; kapsamlı ve güncel kontrol için `--osv`.

struct Advisory {
    ids: &'static str,
    title: &'static str,
    ecosystem: Ecosystem,
    packages: &'static [&'static str],
    severity: Severity,
    ranges: &'static [(&'static str, &'static str, &'static str)],
}

const RSC_PACKAGES: &[&str] =
    &["react-server-dom-webpack", "react-server-dom-parcel", "react-server-dom-turbopack"];

const ADVISORIES: &[Advisory] = &[
    Advisory {
        ids: "CVE-2025-55182",
        title: "React2Shell: React Server Components (Flight) güvensiz serileştirme çözümü → kimlik doğrulamasız uzaktan kod çalıştırma",
        ecosystem: Ecosystem::Npm,
        packages: RSC_PACKAGES,
        severity: Severity::Critical,
        ranges: &[("19.0.0", "19.0.1", "19.0.3"), ("19.1.0", "19.1.2", "19.1.4"), ("19.2.0", "19.2.1", "19.2.3")],
    },
    Advisory {
        ids: "CVE-2025-66478",
        title: "React2Shell (Next.js App Router): RSC protokolü üzerinden kimlik doğrulamasız uzaktan kod çalıştırma",
        ecosystem: Ecosystem::Npm,
        packages: &["next"],
        severity: Severity::Critical,
        ranges: &[
            ("14.3.0-canary.77", "15.0.0-0", "15.0.7"),
            ("15.0.0-0", "15.0.5", "15.0.7"),
            ("15.1.0-0", "15.1.9", "15.1.11"),
            ("15.2.0-0", "15.2.6", "15.2.8"),
            ("15.3.0-0", "15.3.6", "15.3.8"),
            ("15.4.0-0", "15.4.8", "15.4.10"),
            ("15.5.0-0", "15.5.7", "15.5.9"),
            ("16.0.0-0", "16.0.7", "16.0.10"),
        ],
    },
    Advisory {
        ids: "CVE-2025-55184, CVE-2025-67779, CVE-2025-55183",
        title: "React Server Components: hizmet reddi (DoS) ve Server Function kaynak kodu sızıntısı (React2Shell sonrası yamalar)",
        ecosystem: Ecosystem::Npm,
        packages: RSC_PACKAGES,
        severity: Severity::High,
        ranges: &[("19.0.0", "19.0.3", "19.0.3"), ("19.1.0", "19.1.4", "19.1.4"), ("19.2.0", "19.2.3", "19.2.3")],
    },
    Advisory {
        ids: "CVE-2025-55184, CVE-2025-67779, CVE-2025-55183",
        title: "Next.js App Router: hizmet reddi (DoS) ve Server Action kaynak kodu sızıntısı (React2Shell sonrası yamalar)",
        ecosystem: Ecosystem::Npm,
        packages: &["next"],
        severity: Severity::High,
        ranges: &[
            ("13.0.0", "14.2.35", "14.2.35"),
            ("14.3.0-0", "15.0.0-0", "15.0.7"),
            ("15.0.0-0", "15.0.7", "15.0.7"),
            ("15.1.0-0", "15.1.11", "15.1.11"),
            ("15.2.0-0", "15.2.8", "15.2.8"),
            ("15.3.0-0", "15.3.8", "15.3.8"),
            ("15.4.0-0", "15.4.10", "15.4.10"),
            ("15.5.0-0", "15.5.9", "15.5.9"),
            ("16.0.0-0", "16.0.10", "16.0.10"),
        ],
    },
    Advisory {
        ids: "CVE-2025-29927",
        title: "Next.js middleware yetkilendirme atlatma (x-middleware-subrequest başlığı)",
        ecosystem: Ecosystem::Npm,
        packages: &["next"],
        severity: Severity::Critical,
        ranges: &[
            ("11.1.4", "12.3.5", "12.3.5"),
            ("13.0.0", "13.5.9", "13.5.9"),
            ("14.0.0", "14.2.25", "14.2.25"),
            ("15.0.0", "15.2.3", "15.2.3"),
        ],
    },
];

pub fn check_builtin(deps: &[Dependency]) -> Vec<DepFinding> {
    let mut out = Vec::new();
    for d in deps {
        let Some(v) = Version::parse(&d.version) else { continue };
        for a in ADVISORIES.iter().filter(|a| a.ecosystem == d.ecosystem && a.packages.contains(&d.name.as_str())) {
            let hit = a.ranges.iter().find(|(lo, hi, _)| {
                matches!((Version::parse(lo), Version::parse(hi)), (Some(lo), Some(hi)) if v >= lo && v < hi)
            });
            if let Some((_, _, fix)) = hit {
                out.push(DepFinding {
                    ecosystem: d.ecosystem,
                    package: d.name.clone(),
                    version: d.version.clone(),
                    manifest: d.manifest.clone(),
                    approximate: d.approximate,
                    id: a.ids.to_string(),
                    aliases: Vec::new(),
                    severity: a.severity,
                    summary: a.title.to_string(),
                    fixed: Some(fix.to_string()),
                    origin: "yerleşik",
                });
            }
        }
    }
    out
}

/// OSV sonuçları önceliklidir; aynı CVE'yi anlatan yerleşik kayıt atılır.
pub fn merge(builtin: Vec<DepFinding>, osv: Vec<DepFinding>) -> Vec<DepFinding> {
    let mut out = osv;
    for b in builtin {
        let b_ids: Vec<&str> = b.id.split(", ").collect();
        let dup = out.iter().any(|o| {
            o.package == b.package
                && o.version == b.version
                && (b_ids.contains(&o.id.as_str()) || o.aliases.iter().any(|a| b_ids.contains(&a.as_str())))
        });
        if !dup {
            out.push(b);
        }
    }
    out.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.package.cmp(&b.package))
            .then_with(|| a.version.cmp(&b.version))
    });
    out
}

/// Paket başına, bulunan TÜM açıkları kapatan en düşük sürüm (= düzeltmelerin en büyüğü).
pub fn recommendations(findings: &[DepFinding]) -> Vec<(Ecosystem, String, String)> {
    let mut best: BTreeMap<(Ecosystem, String), String> = BTreeMap::new();
    for f in findings {
        let Some(fix) = &f.fixed else { continue };
        let key = (f.ecosystem, f.package.clone());
        let better = match best.get(&key) {
            Some(cur) => match (Version::parse(fix), Version::parse(cur)) {
                (Some(a), Some(b)) => a > b,
                _ => false,
            },
            None => true,
        };
        if better {
            best.insert(key, fix.clone());
        }
    }
    best.into_iter()
        .map(|((e, p), mut v)| {
            // Önerilen sürüm başka bir dalın açık aralığına düşebilir (ör. 15.2.3
            // middleware açığını kapatır ama React2Shell'e açıktır): güvenli olana kadar yükselt.
            for _ in 0..10 {
                match builtin_fix_for(e, &p, &v) {
                    Some(next) if next != v => v = next,
                    _ => break,
                }
            }
            (e, p, v)
        })
        .collect()
}

/// Sürüm yerleşik tablodaki bir aralığa düşüyorsa o aralığın önerilen sürümü.
fn builtin_fix_for(eco: Ecosystem, name: &str, version: &str) -> Option<String> {
    let v = Version::parse(version)?;
    ADVISORIES
        .iter()
        .filter(|a| a.ecosystem == eco && a.packages.contains(&name))
        .flat_map(|a| a.ranges.iter())
        .filter(|(lo, hi, _)| {
            matches!((Version::parse(lo), Version::parse(hi)), (Some(lo), Some(hi)) if v >= lo && v < hi)
        })
        .filter_map(|(_, _, fix)| Version::parse(fix).map(|fv| (fv, *fix)))
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, s)| s.to_string())
}

// ---- Kilit dosyası ayrıştırıcıları ----------------------------------------

const NPM_LOCKS: &[&str] = &["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"];
pub const MANIFEST_NAMES: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "package.json",
    "composer.lock",
    "Cargo.lock",
    "requirements.txt",
    "poetry.lock",
    "Pipfile.lock",
    "go.mod",
];

pub fn is_manifest(path: &Path) -> bool {
    path.file_name().and_then(|n| n.to_str()).is_some_and(|n| MANIFEST_NAMES.contains(&n))
}

type Raw = (String, String);

/// Manifest dosyalarından bağımlılık listesi çıkarır. Bozuk dosyalar uyarı
/// verilip atlanır; denetimin geri kalanı durmaz.
pub fn load(manifests: &[PathBuf]) -> Vec<Dependency> {
    let lock_dirs: HashSet<&Path> = manifests
        .iter()
        .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| NPM_LOCKS.contains(&n)))
        .filter_map(|p| p.parent())
        .collect();

    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for path in manifests {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
        if name == "package.json" && path.parent().is_some_and(|d| lock_dirs.contains(d)) {
            continue; // kilit dosyası daha kesin bilgi verir
        }
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                warn!("{} okunamadı: {e}", path.display());
                continue;
            }
        };
        let (eco, approx, parsed): (Ecosystem, bool, std::result::Result<Vec<Raw>, String>) = match name {
            "package-lock.json" | "npm-shrinkwrap.json" => (Ecosystem::Npm, false, parse_package_lock(&text)),
            "yarn.lock" => (Ecosystem::Npm, false, Ok(parse_yarn_lock(&text))),
            "pnpm-lock.yaml" => (Ecosystem::Npm, false, Ok(parse_pnpm_lock(&text))),
            "package.json" => (Ecosystem::Npm, true, parse_package_json(&text)),
            "composer.lock" => (Ecosystem::Packagist, false, parse_composer_lock(&text)),
            "Cargo.lock" => (Ecosystem::Crates, false, Ok(parse_cargo_lock(&text))),
            "requirements.txt" => (Ecosystem::PyPI, false, Ok(parse_requirements(&text))),
            "poetry.lock" => (Ecosystem::PyPI, false, Ok(parse_cargo_lock(&text))),
            "Pipfile.lock" => (Ecosystem::PyPI, false, parse_pipfile_lock(&text)),
            "go.mod" => (Ecosystem::Go, false, Ok(parse_go_mod(&text))),
            _ => continue,
        };
        match parsed {
            Ok(list) => {
                for (n, v) in list {
                    if seen.insert((eco, n.clone(), v.clone(), path.clone())) {
                        out.push(Dependency { ecosystem: eco, name: n, version: v, manifest: path.clone(), approximate: approx });
                    }
                }
            }
            Err(e) => warn!("{} ayrıştırılamadı: {e}", path.display()),
        }
    }
    out
}

fn parse_package_lock(text: &str) -> std::result::Result<Vec<Raw>, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    if let Some(pkgs) = v.get("packages").and_then(Value::as_object) {
        // lockfileVersion 2/3: "node_modules/a/node_modules/next": { "version": ... }
        for (key, info) in pkgs {
            if key.is_empty() || info.get("link").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            let name = info
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| key.rsplit_once("node_modules/").map(|(_, n)| n.to_string()));
            if let (Some(n), Some(ver)) = (name, info.get("version").and_then(Value::as_str)) {
                out.push((n, ver.to_string()));
            }
        }
    } else if let Some(deps) = v.get("dependencies") {
        // lockfileVersion 1: iç içe "dependencies"
        fn walk(deps: &Value, out: &mut Vec<Raw>) {
            let Some(map) = deps.as_object() else { return };
            for (name, info) in map {
                if let Some(ver) = info.get("version").and_then(Value::as_str) {
                    out.push((name.clone(), ver.to_string()));
                }
                if let Some(sub) = info.get("dependencies") {
                    walk(sub, out);
                }
            }
        }
        walk(deps, &mut out);
    }
    Ok(out)
}

fn yarn_name(spec: &str) -> Option<String> {
    let spec = spec.trim().trim_matches('"');
    let at = spec.get(1..)?.find('@')? + 1;
    Some(spec[..at].to_string())
}

fn parse_yarn_lock(text: &str) -> Vec<Raw> {
    let mut out = Vec::new();
    let mut current: Vec<String> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') && line.trim_end().ends_with(':') {
            current = line.trim_end().trim_end_matches(':').split(", ").filter_map(yarn_name).collect();
            current.dedup();
        } else if line.starts_with("  ") && !line.starts_with("   ") {
            if let Some(rest) = line.trim_start().strip_prefix("version") {
                let v = rest.trim_start_matches(':').trim().trim_matches('"');
                for n in current.drain(..) {
                    out.push((n, v.to_string()));
                }
            }
        }
    }
    out
}

fn parse_pnpm_lock(text: &str) -> Vec<Raw> {
    let mut out = Vec::new();
    let mut in_pkgs = false;
    for line in text.lines() {
        if !line.starts_with(' ') && !line.trim().is_empty() {
            in_pkgs = matches!(line.trim_end(), "packages:" | "snapshots:");
            continue;
        }
        if !in_pkgs || !line.starts_with("  ") || line.starts_with("   ") || !line.trim_end().ends_with(':') {
            continue;
        }
        let key = line.trim().trim_end_matches(':').trim_matches(|c| c == '\'' || c == '"');
        let key = key.strip_prefix('/').unwrap_or(key);
        let key = key.split('(').next().unwrap_or(key);
        // v6+/v9: name@1.2.3   v5: name/1.2.3
        let split = if key.get(1..).is_some_and(|k| k.contains('@')) { key.rsplit_once('@') } else { key.rsplit_once('/') };
        if let Some((n, v)) = split {
            if v.starts_with(|c: char| c.is_ascii_digit()) {
                out.push((n.to_string(), v.split('_').next().unwrap_or(v).to_string()));
            }
        }
    }
    out
}

fn parse_package_json(text: &str) -> std::result::Result<Vec<Raw>, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let ver = Regex::new(r"\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?").map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for section in ["dependencies", "devDependencies", "optionalDependencies"] {
        let Some(map) = v.get(section).and_then(Value::as_object) else { continue };
        for (name, spec) in map {
            if let Some(m) = spec.as_str().and_then(|s| ver.find(s)) {
                out.push((name.clone(), m.as_str().to_string()));
            }
        }
    }
    Ok(out)
}

fn parse_composer_lock(text: &str) -> std::result::Result<Vec<Raw>, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for section in ["packages", "packages-dev"] {
        for p in v.get(section).and_then(Value::as_array).into_iter().flatten() {
            if let (Some(n), Some(ver)) = (p.get("name").and_then(Value::as_str), p.get("version").and_then(Value::as_str)) {
                out.push((n.to_string(), ver.trim_start_matches('v').to_string()));
            }
        }
    }
    Ok(out)
}

fn parse_cargo_lock(text: &str) -> Vec<Raw> {
    let mut out = Vec::new();
    let mut name: Option<String> = None;
    for line in text.lines().map(str::trim) {
        if line == "[[package]]" {
            name = None;
        } else if let Some(v) = line.strip_prefix("name = ") {
            name = Some(v.trim_matches('"').to_string());
        } else if let Some(v) = line.strip_prefix("version = ") {
            if let Some(n) = name.take() {
                out.push((n, v.trim_matches('"').to_string()));
            }
        }
    }
    out
}

/// requirements.txt: yalnızca kesin sabitlenmiş (`==`) sürümler alınır.
fn parse_requirements(text: &str) -> Vec<Raw> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty() && !l.starts_with('-'))
        .filter_map(|l| {
            let l = l.split(';').next()?.trim();
            let (name, ver) = l.split_once("==")?;
            let name = name.split('[').next()?.trim().to_ascii_lowercase();
            let ver = ver.split(',').next()?.trim();
            (!name.is_empty() && !ver.is_empty()).then(|| (name, ver.to_string()))
        })
        .collect()
}

fn parse_pipfile_lock(text: &str) -> std::result::Result<Vec<Raw>, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for section in ["default", "develop"] {
        let Some(map) = v.get(section).and_then(Value::as_object) else { continue };
        for (name, info) in map {
            if let Some(ver) = info.get("version").and_then(Value::as_str) {
                out.push((name.to_ascii_lowercase(), ver.trim_start_matches("==").to_string()));
            }
        }
    }
    Ok(out)
}

/// go.mod `require` satırları (tek satırlık ve blok biçimi). `// indirect` dahil.
fn parse_go_mod(text: &str) -> Vec<Raw> {
    let mut out = Vec::new();
    let mut in_block = false;
    for line in text.lines().map(|l| l.split("//").next().unwrap_or("").trim()) {
        let spec = if in_block {
            if line == ")" {
                in_block = false;
                continue;
            }
            line
        } else if line == "require (" {
            in_block = true;
            continue;
        } else if let Some(rest) = line.strip_prefix("require ") {
            rest
        } else {
            continue;
        };
        let mut parts = spec.split_whitespace();
        if let (Some(m), Some(v)) = (parts.next(), parts.next()) {
            // OSV Go sürümlerini "v" öneki olmadan karşılaştırır
            let v = v.trim_start_matches('v').split("+incompatible").next().unwrap_or("");
            if !v.is_empty() {
                out.push((m.to_string(), v.to_string()));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(name: &str, version: &str) -> Dependency {
        Dependency {
            ecosystem: Ecosystem::Npm,
            name: name.into(),
            version: version.into(),
            manifest: PathBuf::from("package-lock.json"),
            approximate: false,
        }
    }

    #[test]
    fn version_ordering() {
        let v = |s| Version::parse(s).unwrap();
        assert!(v("14.3.0-canary.80") > v("14.3.0-canary.77"));
        assert!(v("14.3.0-canary.8") < v("14.3.0-canary.77"));
        assert!(v("15.0.0-rc.1") < v("15.0.0"));
        assert!(v("15.0.0-0") < v("15.0.0-canary.1"));
        assert!(v("v1.2") == v("1.2.0"));
        assert!(Version::parse("dev-main").is_none());
    }

    #[test]
    fn react2shell_is_detected() {
        let f = check_builtin(&[dep("next", "15.1.0"), dep("react-server-dom-webpack", "19.0.0")]);
        let ids: Vec<_> = f.iter().map(|x| x.id.as_str()).collect();
        assert!(ids.contains(&"CVE-2025-66478"), "{ids:?}");
        assert!(ids.contains(&"CVE-2025-55182"), "{ids:?}");
        assert!(ids.contains(&"CVE-2025-29927"), "{ids:?}");
        let rec = recommendations(&f);
        // 15.2.3 (middleware düzeltmesi) hâlâ React2Shell'e açık → 15.2.8'e kadar yükseltilmeli
        assert!(rec.contains(&(Ecosystem::Npm, "next".into(), "15.2.8".into())), "{rec:?}");
        assert!(rec.contains(&(Ecosystem::Npm, "react-server-dom-webpack".into(), "19.0.3".into())), "{rec:?}");
    }

    #[test]
    fn patched_versions_are_clean() {
        let deps = [dep("next", "15.5.9"), dep("next", "16.0.10"), dep("next", "14.2.35"), dep("react-server-dom-webpack", "19.2.3"), dep("react", "19.0.0")];
        assert!(check_builtin(&deps).is_empty(), "{:?}", check_builtin(&deps));
    }

    #[test]
    fn canary_versions_are_detected() {
        let f = check_builtin(&[dep("next", "14.3.0-canary.90")]);
        assert!(f.iter().any(|x| x.id == "CVE-2025-66478"));
    }

    #[test]
    fn parses_lockfiles() {
        let lock = r#"{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/next":{"version":"15.1.0"},"node_modules/a/node_modules/@scope/b":{"version":"1.0.0"}}}"#;
        let mut d = parse_package_lock(lock).unwrap();
        d.sort();
        assert_eq!(d, vec![("@scope/b".into(), "1.0.0".into()), ("next".into(), "15.1.0".into())]);

        let yarn = "# yarn\n\"next@^15.1.0\", next@15:\n  version \"15.1.2\"\n  resolved \"x\"\n\n\"@a/b@npm:^1\":\n  version: 1.4.0\n";
        assert_eq!(parse_yarn_lock(yarn), vec![("next".into(), "15.1.2".into()), ("@a/b".into(), "1.4.0".into())]);

        let pnpm = "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\npackages:\n  next@15.1.0:\n    resolution: {}\n  '@next/env@15.1.0':\n    resolution: {}\nsnapshots:\n  /react-server-dom-webpack@19.0.0(react@19.0.0):\n    dependencies: {}\n";
        let p = parse_pnpm_lock(pnpm);
        assert!(p.contains(&("next".into(), "15.1.0".into())), "{p:?}");
        assert!(p.contains(&("@next/env".into(), "15.1.0".into())), "{p:?}");
        assert!(p.contains(&("react-server-dom-webpack".into(), "19.0.0".into())), "{p:?}");

        let composer = r#"{"packages":[{"name":"guzzlehttp/guzzle","version":"v7.4.0"}],"packages-dev":[]}"#;
        assert_eq!(parse_composer_lock(composer).unwrap(), vec![("guzzlehttp/guzzle".into(), "7.4.0".into())]);

        let cargo = "[[package]]\nname = \"regex\"\nversion = \"1.10.0\"\nsource = \"registry\"\n";
        assert_eq!(parse_cargo_lock(cargo), vec![("regex".into(), "1.10.0".into())]);

        let req = "Flask==2.2.0  # web
requests[socks]==2.19.0 ; python_version > '3'
numpy>=1.0
-r other.txt
";
        assert_eq!(parse_requirements(req), vec![("flask".into(), "2.2.0".into()), ("requests".into(), "2.19.0".into())]);

        let gomod = "module x

go 1.22

require github.com/gin-gonic/gin v1.9.0
require (
	golang.org/x/net v0.17.0 // indirect
	github.com/a/b v2.0.0+incompatible
)
";
        assert_eq!(
            parse_go_mod(gomod),
            vec![
                ("github.com/gin-gonic/gin".into(), "1.9.0".into()),
                ("golang.org/x/net".into(), "0.17.0".into()),
                ("github.com/a/b".into(), "2.0.0".into())
            ]
        );

        let pj = r#"{"dependencies":{"next":"^15.1.0","x":"latest"}}"#;
        assert_eq!(parse_package_json(pj).unwrap(), vec![("next".into(), "15.1.0".into())]);
    }
}
