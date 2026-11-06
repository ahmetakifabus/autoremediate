#![forbid(unsafe_code)] // bu crate'te unsafe yazmak derleme hatasıdır

mod ai;
mod deps;
mod error;
mod gemini;
mod orchestrator;
mod osv;
mod patcher;
mod scanner;
mod util;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use tracing::{error, info, warn};

use crate::ai::{AnthropicClient, LlmConfig, PatchProvider};
use crate::deps::DepFinding;
use crate::error::{Error, Result};
use crate::gemini::{GeminiClient, GeminiConfig};
use crate::orchestrator::{Config, Orchestrator, Outcome};
use crate::patcher::Patcher;
use crate::scanner::{Finding, Lang, Scanner};

const USAGE: &str = "\
Kullanım: autoremediate <dosya|dizin> [seçenekler]

Kaynak kod:  Rust (.rs), PHP (.php .phtml ...), JavaScript/TypeScript (.js .mjs .cjs .jsx .ts .tsx)
Bağımlılık:  package-lock.json, yarn.lock, pnpm-lock.yaml, package.json, composer.lock, Cargo.lock

  --scan-only            Sadece tara ve raporla (API anahtarı gerekmez)
  --dry-run              Yamayı üret ve göster, dosyaya yazma
  --provider <ad>        gemini | anthropic (verilmezse anahtarı tanımlı olan seçilir)
  --max-iter <N>         En fazla döngü sayısı (varsayılan 5, üst sınır 20)
  --validate \"<komut>\"   Her yamadan sonra çalışacak doğrulama (örn. \"cargo check -q\", \"npx tsc --noEmit\")
  --validate-dir <dizin> Doğrulama komutunun çalışma dizini
  --osv                  Bağımlılıkları canlı OSV veritabanında da sorgula
                         (osv.dev'e yalnızca paket adı + sürüm gönderilir)
  --no-deps              Bağımlılık denetimini atla
  --json                 --scan-only çıktısını JSON olarak ver (CI için)

Ortam: GEMINI_API_KEY (+ GEMINI_MODEL) veya ANTHROPIC_API_KEY (+ AUTOFIX_MODEL); --scan-only için gerekmez";

/// Dizin taramasında atlanan (üretilmiş / üçüncü taraf) dizinler
const SKIP_DIRS: &[&str] = &[
    ".git", "target", "node_modules", "vendor", ".next", ".nuxt", ".svelte-kit", "dist", "build", "out",
    "coverage", "bower_components", ".turbo", ".vercel",
];
/// Bundan büyük kaynak dosyaları (genelde paketlenmiş çıktı) atlanır
const MAX_SOURCE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone, Copy)]
enum Provider {
    Gemini,
    Anthropic,
}

struct Cli {
    target: PathBuf,
    provider: Option<Provider>,
    dry_run: bool,
    scan_only: bool,
    max_iter: u32,
    validate: Option<Vec<String>>,
    validate_dir: Option<PathBuf>,
    osv: bool,
    deps: bool,
    json: bool,
}

fn parse_args() -> Result<Cli> {
    let mut args = std::env::args().skip(1);
    let (mut target, mut dry_run, mut scan_only) = (None, false, false);
    let (mut max_iter, mut validate, mut validate_dir) = (5u32, None, None);
    let (mut osv, mut deps, mut json) = (false, true, false);
    let mut provider: Option<Provider> = None;
    let need = |name: &str| Error::Config(format!("{name} bir değer bekliyor"));

    while let Some(a) = args.next() {
        match a.as_str() {
            "--dry-run" => dry_run = true,
            "--scan-only" => scan_only = true,
            "--osv" => osv = true,
            "--no-deps" => deps = false,
            "--json" => json = true,
            "--provider" => {
                provider = Some(match args.next().ok_or_else(|| need("--provider"))?.as_str() {
                    "gemini" => Provider::Gemini,
                    "anthropic" => Provider::Anthropic,
                    other => return Err(Error::Config(format!("bilinmeyen sağlayıcı: {other}"))),
                });
            }
            "--max-iter" => {
                let v = args.next().ok_or_else(|| need("--max-iter"))?;
                max_iter = v
                    .parse::<u32>()
                    .map_err(|_| Error::Config(format!("geçersiz --max-iter: {v}")))?
                    .clamp(1, 20);
            }
            "--validate" => {
                let v = args.next().ok_or_else(|| need("--validate"))?;
                validate = Some(v.split_whitespace().map(String::from).collect());
            }
            "--validate-dir" => {
                validate_dir = Some(PathBuf::from(args.next().ok_or_else(|| need("--validate-dir"))?));
            }
            "-h" | "--help" => return Err(Error::Config(USAGE.into())),
            o if o.starts_with("--") => return Err(Error::Config(format!("bilinmeyen seçenek: {o}\n\n{USAGE}"))),
            o => {
                if target.replace(PathBuf::from(o)).is_some() {
                    return Err(Error::Config("yalnızca tek hedef verilebilir".into()));
                }
            }
        }
    }
    let target = target.ok_or_else(|| Error::Config(USAGE.into()))?;
    if json && !scan_only {
        return Err(Error::Config("--json yalnızca --scan-only ile kullanılabilir".into()));
    }
    Ok(Cli { target, provider, dry_run, scan_only, max_iter, validate, validate_dir, osv, deps, json })
}

#[derive(Default)]
struct Targets {
    sources: Vec<(PathBuf, Lang)>,
    manifests: Vec<PathBuf>,
}

impl Targets {
    fn add(&mut self, path: PathBuf, len: u64) {
        if deps::is_manifest(&path) {
            self.manifests.push(path);
        } else if let Some(lang) = Lang::from_path(&path) {
            if len <= MAX_SOURCE_BYTES {
                self.sources.push((path, lang));
            } else {
                warn!("{} çok büyük ({len} bayt), atlandı", path.display());
            }
        }
    }
}

/// Hedef dosya ya da dizin; desteklenen kaynaklar ve bağımlılık manifestleri
/// toplanır (symlink'ler izlenmez, üretilmiş/üçüncü taraf dizinler atlanır).
fn collect_files(root: &Path) -> Result<Targets> {
    let meta = std::fs::symlink_metadata(root).map_err(|e| Error::io(root, e))?;
    if meta.file_type().is_symlink() {
        return Err(Error::Config("sembolik bağlantı hedef olarak kabul edilmez".into()));
    }
    let mut t = Targets::default();
    if meta.is_file() {
        t.add(root.to_path_buf(), meta.len());
        return Ok(t);
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).map_err(|e| Error::io(&dir, e))? {
            let entry = entry.map_err(|e| Error::io(&dir, e))?;
            let path = entry.path();
            let ft = entry.file_type().map_err(|e| Error::io(&path, e))?;
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                if entry.file_name().to_str().is_some_and(|n| SKIP_DIRS.contains(&n)) {
                    continue;
                }
                stack.push(path);
            } else if ft.is_file() {
                let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
                t.add(path, len);
            }
        }
    }
    t.sources.sort_by(|a, b| a.0.cmp(&b.0));
    t.manifests.sort();
    Ok(t)
}

/// Yerleşik tablo + (istenirse) OSV ile bağımlılık denetimi.
async fn audit_deps(manifests: &[PathBuf], use_osv: bool) -> Vec<DepFinding> {
    let deps = deps::load(manifests);
    if deps.is_empty() {
        return Vec::new();
    }
    info!("{} manifestte {} bağımlılık bulundu", manifests.len(), deps.len());
    let builtin = deps::check_builtin(&deps);
    let osv = if use_osv {
        match osv::audit(&deps).await {
            Ok(f) => f,
            Err(e) => {
                warn!("OSV sorgusu başarısız, yalnızca yerleşik tablo kullanıldı: {e}");
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    deps::merge(builtin, osv)
}

fn print_deps(findings: &[DepFinding]) {
    if findings.is_empty() {
        return;
    }
    println!("\nBağımlılık açıkları:");
    for f in findings {
        let aliases = if f.aliases.is_empty() { String::new() } else { format!(" ({})", f.aliases.join(", ")) };
        let fix = f.fixed.as_deref().map(|v| format!(" → düzeltilmiş: {v}")).unwrap_or_default();
        let approx = if f.approximate { " [kilit dosyası yok; sürüm tahmini]" } else { "" };
        println!(
            "  {} : {}@{} [{}] {}{} — {}{}{}",
            f.manifest.display(),
            f.package,
            f.version,
            f.severity,
            f.id,
            aliases,
            f.summary,
            fix,
            approx
        );
    }
    let rec = deps::recommendations(findings);
    if !rec.is_empty() {
        println!("\nÖnerilen yükseltmeler (yükselttikten sonra tekrar tarayın):");
        for (eco, pkg, ver) in rec {
            println!("  {}", eco.upgrade_hint(&pkg, &ver));
        }
    }
}

fn print_suppressed(file: &Path, list: &[Finding]) {
    for x in list {
        println!(
            "  ⚠ {}:{} [{}] {} bastırıldı (autoremediate-ignore) — elle doğrulayın",
            file.display(),
            x.line,
            x.severity,
            x.rule_id
        );
    }
}

async fn run() -> Result<ExitCode> {
    let cli = parse_args()?;
    let targets = collect_files(&cli.target)?;
    if targets.sources.is_empty() && (targets.manifests.is_empty() || !cli.deps) {
        info!("Taranacak dosya bulunamadı");
        return Ok(ExitCode::SUCCESS);
    }
    let dep_findings = if cli.deps { audit_deps(&targets.manifests, cli.osv).await } else { Vec::new() };

    if cli.scan_only {
        return Ok(scan_report(&cli, &targets, &dep_findings)?);
    }

    let mut code = 0u8;
    if !targets.sources.is_empty() {
        let provider = match cli.provider {
            Some(p) => p,
            None => detect_provider()?,
        };
        code = match provider {
            Provider::Gemini => {
                let cfg = GeminiConfig::from_env()?;
                info!("Sağlayıcı: Gemini ({})", cfg.model());
                drive(GeminiClient::new(cfg)?, &cli, &targets.sources).await?
            }
            Provider::Anthropic => {
                drive(AnthropicClient::new(LlmConfig::from_env()?)?, &cli, &targets.sources).await?
            }
        };
    }
    if !dep_findings.is_empty() {
        print_deps(&dep_findings);
        println!("Not: bağımlılıklar otomatik yükseltilmez; yukarıdaki komutları çalıştırıp testleri koşun.");
        code = code.max(1);
    }
    Ok(ExitCode::from(code))
}

fn scan_report(cli: &Cli, targets: &Targets, dep_findings: &[DepFinding]) -> Result<ExitCode> {
    let scanner = Scanner::new()?;
    let mut code_findings: Vec<(PathBuf, Finding)> = Vec::new();
    let mut suppressed: Vec<(PathBuf, Finding)> = Vec::new();
    for (f, lang) in &targets.sources {
        let src = match std::fs::read_to_string(f) {
            Ok(s) => s,
            Err(e) => {
                warn!("{} okunamadı: {e}", f.display());
                continue;
            }
        };
        let r = scanner.scan_full(&src, *lang);
        code_findings.extend(r.findings.into_iter().map(|x| (f.clone(), x)));
        suppressed.extend(r.suppressed.into_iter().map(|x| (f.clone(), x)));
    }

    if cli.json {
        let row = |(f, x): &(PathBuf, Finding)| {
            serde_json::json!({
                "file": f, "line": x.line, "rule_id": x.rule_id, "severity": x.severity,
                "description": x.description, "snippet": x.snippet,
            })
        };
        let upgrades: Vec<_> = deps::recommendations(dep_findings)
            .into_iter()
            .map(|(e, p, v)| serde_json::json!({"ecosystem": e, "package": p, "version": v}))
            .collect();
        let report = serde_json::json!({
            "code_findings": code_findings.iter().map(row).collect::<Vec<_>>(),
            "suppressed": suppressed.iter().map(row).collect::<Vec<_>>(),
            "dependency_findings": dep_findings,
            "upgrades": upgrades,
        });
        println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
    } else {
        for (f, x) in &code_findings {
            println!("{}:{} [{}] {} — {}", f.display(), x.line, x.severity, x.rule_id, x.description);
        }
        for (f, x) in &suppressed {
            print_suppressed(f, std::slice::from_ref(x));
        }
        print_deps(dep_findings);
        println!(
            "\nToplam {} kod bulgusu, {} bağımlılık açığı, {} bastırılmış bulgu ({} kaynak dosya tarandı).",
            code_findings.len(),
            dep_findings.len(),
            suppressed.len(),
            targets.sources.len()
        );
    }
    let failing = !code_findings.is_empty() || !dep_findings.is_empty();
    Ok(if failing { ExitCode::from(1) } else { ExitCode::SUCCESS })
}

/// --provider verilmediyse hangi anahtar tanımlıysa onu seç.
fn detect_provider() -> Result<Provider> {
    let has = |k: &str| std::env::var(k).map(|v| !v.trim().is_empty()).unwrap_or(false);
    if has("GEMINI_API_KEY") {
        Ok(Provider::Gemini)
    } else if has("ANTHROPIC_API_KEY") {
        Ok(Provider::Anthropic)
    } else {
        Err(Error::Config(
            "API anahtarı bulunamadı: GEMINI_API_KEY veya ANTHROPIC_API_KEY tanımlayın".into(),
        ))
    }
}

async fn drive<P: PatchProvider>(provider: P, cli: &Cli, files: &[(PathBuf, Lang)]) -> Result<u8> {
    let orch = Orchestrator::new(
        Scanner::new()?,
        provider,
        Patcher::new(cli.validate.clone(), cli.validate_dir.clone()),
        Config {
            max_iterations: cli.max_iter,
            max_file_bytes: 512 * 1024,
            max_consecutive_failures: 2,
            dry_run: cli.dry_run,
        },
    );

    let mut code = 0u8;
    for (f, _) in files {
        match orch.remediate(f).await {
            Ok(Outcome::Clean { iterations, suppressed }) => {
                println!("✔ {} — Sistemde açık kalmadı ({iterations} yama turu)", f.display());
                print_suppressed(f, &suppressed);
            }
            Ok(Outcome::Exhausted { remaining }) => {
                println!("✘ {} — iterasyon sınırı doldu, {} açık kaldı", f.display(), remaining.len());
                code = code.max(1);
            }
            Ok(Outcome::Stalled { remaining, reason }) => {
                println!("✘ {} — durdu ({reason}), {} açık kaldı", f.display(), remaining.len());
                code = code.max(1);
            }
            Ok(Outcome::DryRun { explanation, findings }) => {
                println!("• {} — {findings} açık için öneri üretildi (dry-run):\n  {explanation}", f.display());
            }
            Err(e) => {
                error!("{}: {e}", f.display());
                code = 2;
            }
        }
    }
    Ok(code)
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).with_target(false).init();
    match run().await {
        Ok(c) => c,
        Err(Error::Config(msg)) => {
            eprintln!("{msg}");
            ExitCode::from(2)
        }
        Err(e) => {
            error!("{e}");
            ExitCode::from(2)
        }
    }
}
