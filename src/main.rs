#![forbid(unsafe_code)] // bu crate'te unsafe yazmak derleme hatasıdır

mod ai;
mod ci;
mod controls;
mod deps;
mod error;
mod gemini;
mod orchestrator;
mod osv;
mod patcher;
mod providers;
mod recon;
mod report;
mod scanner;
mod upgrade;
mod util;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use tracing::{error, info, warn};

use crate::ai::PatchProvider;
use crate::controls::{ControlFinding, Project};
use crate::deps::DepFinding;
use crate::error::{Error, Result};
use crate::orchestrator::{Config, Orchestrator, Outcome};
use crate::patcher::Patcher;
use crate::recon::SiteReport;
use crate::report::{part_of, Part, Report};
use crate::scanner::{Finding, Lang, Scanner};
use crate::util::SKIP_DIRS;

const USAGE: &str = "\
Kullanım: autoremediate [dosya|dizin] [--site <adres>] [seçenekler]

Siteyi bir bina gibi düşünün; hırsız zayıf noktayı görürse oradan girer. Araç altı şeye bakar:
  1) Hırsızın gözü     --site ile yayındaki siteye DIŞARIDAN bakar (açık pencere, unutulmuş anahtar)
  2) Kırık duvarlar    koddaki açıklar → LLM ile yamalanır, yeniden taranarak doğrulanır
  3) Eksik kameralar   kurulmamış savunmalar (helmet, rate limit, CSRF, güvenli çerez...) → takılır
  4) Kilitsiz kapılar  kimlik doğrulaması olmayan /admin, API ve Server Action'lar → kilitlenir
  5) Çürük temel       nginx / Apache / php.ini / Dockerfile ayarları, desteği bitmiş PHP/Node/Python
  6) Çürük malzeme     savunmasız bağımlılıklar (React2Shell vb.) → --fix-deps ile değiştirilir

Kaynak kod:  Rust, PHP, JavaScript/TypeScript, Python, Go
Bağımlılık:  package-lock.json, yarn.lock, pnpm-lock.yaml, package.json, composer.lock, Cargo.lock,
             requirements.txt, poetry.lock, Pipfile.lock, go.mod

  --scan-only            Sadece tara ve raporla, hiçbir dosyayı değiştirme (API anahtarı gerekmez)
  --site <adres>         Yayındaki siteye dışarıdan bak (YALNIZCA sahibi olduğunuz / izinli siteler)
  --dry-run              Yamaları, kurulacak savunmaları ve yükseltmeleri göster, dosyaya yazma
  --no-harden            Eksik savunmaları (kameraları / kilitleri) kurma, sadece duvarları yamala
  --fix-deps             Savunmasız bağımlılıkları paket yöneticisiyle yükselt; açık kapanmazsa
                         ya da --validate başarısızsa geri al
  --provider <ad>        LLM sağlayıcısı: anthropic, openai, gemini, openrouter, deepseek, mistral, xai,
                         groq, together, fireworks, cerebras, cohere, qwen, kimi, glm, huggingface,
                         github, nvidia, azure, custom, ollama, lmstudio
                         (verilmezse anahtarı tanımlı olan ilk sağlayıcı seçilir)
  --model <ad>           Sağlayıcının modelini değiştir (ör. gpt-5-mini, deepseek-reasoner)
  --providers            Tüm sağlayıcıları, anahtar değişkenlerini ve hazır olanları listele
  --max-iter <N>         En fazla döngü sayısı (varsayılan 5, üst sınır 20)
  --validate \"<komut>\"   Her değişiklikten sonra çalışacak doğrulama (örn. \"npm test\", \"cargo check -q\")
  --validate-dir <dizin> Doğrulama komutunun çalışma dizini
  --osv                  Bağımlılıkları canlı OSV veritabanında da sorgula
                         (osv.dev'e yalnızca paket adı + sürüm gönderilir)
  --no-deps              Bağımlılık denetimini atla
  --json                 --scan-only çıktısını JSON olarak ver (CI için)
  --sarif <dosya>        Bulguları SARIF olarak yaz (GitHub Security sekmesi)
  --html <dosya>         Tek dosyalık HTML rapor yaz (güvenlik puanı + tüm bölümler)
  --init-ci              Projeye bekçi ekle: her push/PR/hafta tarayan GitHub Actions iş akışı

Ortam: sağlayıcının API anahtarı (ör. OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY,
OPENROUTER_API_KEY, DEEPSEEK_API_KEY, GROQ_API_KEY...; tam liste: --providers). --scan-only için gerekmez";

/// Bundan büyük kaynak dosyaları (genelde paketlenmiş çıktı) atlanır
const MAX_SOURCE_BYTES: u64 = 2 * 1024 * 1024;

struct Cli {
    target: Option<PathBuf>,
    site: Option<String>,
    provider: Option<String>,
    model: Option<String>,
    dry_run: bool,
    scan_only: bool,
    harden: bool,
    fix_deps: bool,
    max_iter: u32,
    validate: Option<Vec<String>>,
    validate_dir: Option<PathBuf>,
    osv: bool,
    deps: bool,
    json: bool,
    sarif: Option<PathBuf>,
    html: Option<PathBuf>,
    init_ci: bool,
}

fn parse_args() -> Result<Cli> {
    let mut args = std::env::args().skip(1);
    let mut cli = Cli {
        target: None,
        site: None,
        provider: None,
        model: None,
        dry_run: false,
        scan_only: false,
        harden: true,
        fix_deps: false,
        max_iter: 5,
        validate: None,
        validate_dir: None,
        osv: false,
        deps: true,
        json: false,
        sarif: None,
        html: None,
        init_ci: false,
    };
    let need = |name: &str| Error::Config(format!("{name} bir değer bekliyor"));

    while let Some(a) = args.next() {
        match a.as_str() {
            "--dry-run" => cli.dry_run = true,
            "--scan-only" => cli.scan_only = true,
            "--no-harden" => cli.harden = false,
            "--fix-deps" => cli.fix_deps = true,
            "--osv" => cli.osv = true,
            "--no-deps" => cli.deps = false,
            "--json" => cli.json = true,
            "--init-ci" => cli.init_ci = true,
            "--site" => cli.site = Some(args.next().ok_or_else(|| need("--site"))?),
            "--sarif" => cli.sarif = Some(PathBuf::from(args.next().ok_or_else(|| need("--sarif"))?)),
            "--html" => cli.html = Some(PathBuf::from(args.next().ok_or_else(|| need("--html"))?)),
            "--provider" => {
                let v = args.next().ok_or_else(|| need("--provider"))?.to_ascii_lowercase();
                if !providers::ids().contains(&v.as_str()) && !matches!(v.as_str(), "claude" | "google") {
                    return Err(Error::Config(format!("bilinmeyen sağlayıcı: {v}. Seçenekler: {}", providers::ids().join(", "))));
                }
                cli.provider = Some(v);
            }
            "--model" => cli.model = Some(args.next().ok_or_else(|| need("--model"))?),
            "--providers" => return Err(Error::Config(providers_table())),
            "--max-iter" => {
                let v = args.next().ok_or_else(|| need("--max-iter"))?;
                cli.max_iter = v
                    .parse::<u32>()
                    .map_err(|_| Error::Config(format!("geçersiz --max-iter: {v}")))?
                    .clamp(1, 20);
            }
            "--validate" => {
                let v = args.next().ok_or_else(|| need("--validate"))?;
                cli.validate = Some(v.split_whitespace().map(String::from).collect());
            }
            "--validate-dir" => {
                cli.validate_dir = Some(PathBuf::from(args.next().ok_or_else(|| need("--validate-dir"))?));
            }
            "-V" | "--version" => return Err(Error::Config(format!("autoremediate {}", env!("CARGO_PKG_VERSION")))),
            "-h" | "--help" => return Err(Error::Config(USAGE.into())),
            o if o.starts_with("--") => return Err(Error::Config(format!("bilinmeyen seçenek: {o}\n\n{USAGE}"))),
            o => {
                if cli.target.replace(PathBuf::from(o)).is_some() {
                    return Err(Error::Config("yalnızca tek hedef verilebilir".into()));
                }
            }
        }
    }
    if cli.target.is_none() && cli.site.is_none() {
        return Err(Error::Config(USAGE.into()));
    }
    if cli.json && !cli.scan_only {
        return Err(Error::Config("--json yalnızca --scan-only ile kullanılabilir".into()));
    }
    if cli.fix_deps && cli.scan_only {
        return Err(Error::Config("--fix-deps dosya değiştirir; --scan-only ile birlikte kullanılamaz".into()));
    }
    if cli.init_ci && cli.target.as_ref().is_none_or(|t| !t.is_dir()) {
        return Err(Error::Config("--init-ci için hedef bir proje dizini olmalı".into()));
    }
    Ok(cli)
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

type Located = Vec<(PathBuf, Finding)>;

/// Tüm kaynakları tarar: (bulgular, bastırılmış bulgular)
fn scan_walls(sources: &[(PathBuf, Lang)]) -> Result<(Located, Located)> {
    let scanner = Scanner::new()?;
    let (mut walls, mut suppressed) = (Vec::new(), Vec::new());
    for (f, lang) in sources {
        let src = match std::fs::read_to_string(f) {
            Ok(s) => s,
            Err(e) => {
                warn!("{} okunamadı: {e}", f.display());
                continue;
            }
        };
        let r = scanner.scan_full(&src, *lang);
        walls.extend(r.findings.into_iter().map(|x| (f.clone(), x)));
        suppressed.extend(r.suppressed.into_iter().map(|x| (f.clone(), x)));
    }
    Ok((walls, suppressed))
}

// ---- Rapor ---------------------------------------------------------------

fn section(title: &str) {
    println!("\n══════ {title} ══════");
}

fn print_site(site: &SiteReport) {
    section(&format!("1) Hırsızın gözü — {}", site.url));
    if !site.tech.is_empty() {
        println!("  Dışarıdan görünen teknoloji: {}", site.tech.join(", "));
        if site.tech.contains(&"Next.js") {
            println!("  ↳ Next.js görünüyor: React2Shell vb. için bağımlılıkları --osv ile mutlaka kontrol edin.");
        }
    }
    if site.findings.is_empty() {
        println!("  ✔ Dışarıdan açık pencere ya da unutulmuş anahtar görünmüyor.");
    }
    for f in &site.findings {
        println!("  [{}] {} {} — {}", f.severity, f.id, f.title, f.detail);
        println!("        Çözüm: {}", f.remedy);
    }
}

fn print_walls(findings: &[(PathBuf, Finding)], suppressed: &[(PathBuf, Finding)]) {
    section("2) Kırık duvarlar — koddaki açıklar");
    if findings.is_empty() {
        println!("  ✔ Kırık duvar bulunmadı.");
    }
    for (f, x) in findings {
        println!("  {}:{} [{}] {} — {}", f.display(), x.line, x.severity, x.rule_id, x.description);
    }
    for (f, x) in suppressed {
        print_suppressed(f, std::slice::from_ref(x));
    }
}

const PARTS: [(Part, &str, &str); 3] = [
    (Part::Cameras, "3) Eksik kameralar — kurulmamış savunmalar", "Bilinen temel savunmalar yerinde."),
    (Part::Locks, "4) Kilitsiz kapılar — kimlik doğrulaması olmayan hassas kapılar", "Kilitsiz hassas kapı bulunmadı."),
    (Part::Infra, "5) Çürük temel — sunucu ve çalışma ortamı", "Sunucu yapılandırmasında bilinen sorun bulunmadı."),
];

fn print_cameras(list: &[ControlFinding]) {
    for (part, title, ok) in PARTS {
        section(title);
        let items: Vec<&ControlFinding> = list.iter().filter(|c| part_of(c) == part).collect();
        if items.is_empty() {
            println!("  ✔ {ok}");
        }
        for c in items {
            println!("  [{}] {} {} — {}", c.severity, c.id, c.title, c.location.display());
            if !c.detail.is_empty() {
                println!("        {}", c.detail);
            }
            println!("        Neden önemli: {}", c.why);
            println!("        Kurulum: {}", c.how_to_fix);
        }
    }
}

fn print_deps(findings: &[DepFinding]) {
    section("6) Çürük malzeme — savunmasız bağımlılıklar");
    if findings.is_empty() {
        println!("  ✔ Bilinen savunmasız bağımlılık bulunmadı.");
        return;
    }
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
        println!("\n  Önerilen yükseltmeler (ya da --fix-deps ile otomatik):");
        for (eco, pkg, ver) in rec {
            println!("    {}", eco.upgrade_hint(&pkg, &ver));
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

fn print_score(r: &Report) {
    let (score, grade) = r.score();
    println!("  Güvenlik puanı: {score}/100 (not: {grade})");
}

/// İstenen dosya raporlarını (SARIF / HTML) yazar.
fn write_reports(cli: &Cli, r: &Report) -> Result<()> {
    if let Some(p) = &cli.sarif {
        let text = serde_json::to_string_pretty(&r.to_sarif()).map_err(|e| Error::Config(e.to_string()))?;
        std::fs::write(p, text).map_err(|e| Error::io(p, e))?;
        info!("SARIF raporu yazıldı: {}", p.display());
    }
    if let Some(p) = &cli.html {
        std::fs::write(p, r.to_html()).map_err(|e| Error::io(p, e))?;
        info!("HTML raporu yazıldı: {}", p.display());
    }
    Ok(())
}

/// Yeni savunmaların gerektirdiği paketler: ekosisteme göre kurulum komutu
fn print_package_hint(packages: &[&str]) {
    let (pip, npm): (Vec<&str>, Vec<&str>) = packages.iter().partition(|p| p.starts_with("pip:"));
    if !npm.is_empty() {
        println!("    npm install {}", npm.join(" "));
    }
    if !pip.is_empty() {
        let names: Vec<&str> = pip.iter().map(|p| p.trim_start_matches("pip:")).collect();
        println!("    pip install {}  (requirements dosyasına da ekleyin)", names.join(" "));
    }
}

// ---- Çalıştırma ----------------------------------------------------------

async fn run() -> Result<ExitCode> {
    let cli = parse_args()?;

    // Bekçi kurulumu
    if cli.init_ci {
        if let Some(t) = &cli.target {
            match ci::init(t) {
                Ok(p) => println!("✔ Bekçi eklendi: {} (commit edip push'layın; ayrıntılar dosyanın başında)", p.display()),
                Err(e) => println!("• {e}"),
            }
        }
    }

    // 1) Hırsızın gözü
    let site = match &cli.site {
        Some(u) => {
            println!("Not: --site yalnızca sahibi olduğunuz veya test izniniz olan siteler için kullanılmalıdır.");
            Some(recon::inspect(u).await?)
        }
        None => None,
    };
    let site_bad = site.as_ref().is_some_and(|s| !s.findings.is_empty());

    let Some(target) = cli.target.clone() else {
        // Sadece dış bakış
        let r = Report { root: Path::new("."), site: site.as_ref(), walls: &[], suppressed: &[], cameras: &[], deps: &[] };
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&r.to_json()).unwrap_or_default());
        } else if let Some(s) = &site {
            print_site(s);
            print_score(&r);
        }
        write_reports(&cli, &r)?;
        return Ok(if site_bad { ExitCode::from(1) } else { ExitCode::SUCCESS });
    };

    let targets = collect_files(&target)?;
    let root = if target.is_dir() { target.clone() } else { target.parent().map(Path::to_path_buf).unwrap_or_default() };
    let project = Project { root: &root, sources: &targets.sources, manifests: &targets.manifests };
    let dep_findings = if cli.deps { audit_deps(&targets.manifests, cli.osv).await } else { Vec::new() };

    if cli.scan_only {
        let (walls, suppressed) = scan_walls(&targets.sources)?;
        let cameras = controls::audit(&project);
        let r = Report { root: &root, site: site.as_ref(), walls: &walls, suppressed: &suppressed, cameras: &cameras, deps: &dep_findings };
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&r.to_json()).unwrap_or_default());
        } else {
            if let Some(s) = &site {
                print_site(s);
            }
            print_walls(&walls, &suppressed);
            print_cameras(&cameras);
            print_deps(&dep_findings);
            section("Özet");
            let n = |p: Part| cameras.iter().filter(|c| part_of(c) == p).count();
            println!(
                "  {} açık pencere, {} kırık duvar, {} eksik kamera, {} kilitsiz kapı, {} çürük temel, {} çürük malzeme, {} bastırılmış bulgu ({} kaynak dosya).",
                site.as_ref().map_or(0, |s| s.findings.len()),
                walls.len(),
                n(Part::Cameras),
                n(Part::Locks),
                n(Part::Infra),
                dep_findings.len(),
                suppressed.len(),
                targets.sources.len()
            );
            print_score(&r);
        }
        write_reports(&cli, &r)?;
        return Ok(if r.has_findings() { ExitCode::from(1) } else { ExitCode::SUCCESS });
    }

    if let Some(s) = &site {
        print_site(s);
    }
    let mut code = u8::from(site_bad);
    let needs_llm = !targets.sources.is_empty() || (cli.harden && !controls::audit(&project).is_empty());
    if needs_llm {
        let c = match providers::select(cli.provider.as_deref(), cli.model.as_deref()) {
            Ok((provider, label)) => {
                info!("Sağlayıcı: {label}");
                drive(provider, &cli, &targets.sources, &project).await?
            }
            // Yalnızca bağımlılık yükseltmesi istendiyse ve sağlayıcı seçilmediyse LLM adımları atlanabilir
            Err(e) if cli.fix_deps && cli.provider.is_none() => {
                warn!("{e} — duvar/kamera adımları atlandı, yalnızca bağımlılıklar yükseltilecek");
                0
            }
            Err(e) => return Err(e),
        };
        code = code.max(c);
    }

    // 6) Çürük malzeme
    if !dep_findings.is_empty() {
        if cli.fix_deps {
            section("6) Çürük malzeme — değiştiriliyor");
            let rep = upgrade::apply(&dep_findings, cli.validate.as_deref(), cli.dry_run).await;
            for (d, step) in &rep.planned {
                println!("  • {} (dry-run): {step}", d.display());
            }
            for (d, pkg) in &rep.upgraded {
                println!("  ✔ {pkg} — {}", d.display());
            }
            for (d, why) in &rep.failed {
                println!("  ✘ {} — {why}", d.display());
                code = code.max(1);
            }
            if !rep.upgraded.is_empty() {
                println!("  Not: kilit dosyaları güncellendi; değişiklikleri inceleyip commit edin.");
            }
        } else {
            print_deps(&dep_findings);
            println!("  Not: otomatik yükseltme için --fix-deps kullanın.");
            code = code.max(1);
        }
    }

    // Son durum: değişikliklerden sonra bina yeniden kontrol edilir
    if !cli.dry_run {
        let targets = collect_files(&target)?;
        let project = Project { root: &root, sources: &targets.sources, manifests: &targets.manifests };
        let (walls, suppressed) = scan_walls(&targets.sources)?;
        let cameras = controls::audit(&project);
        let deps_after = if cli.deps { audit_deps(&targets.manifests, cli.osv).await } else { Vec::new() };
        let r = Report { root: &root, site: site.as_ref(), walls: &walls, suppressed: &suppressed, cameras: &cameras, deps: &deps_after };
        section("Son durum");
        let n = |p: Part| cameras.iter().filter(|c| part_of(c) == p).count();
        println!(
            "  {} kırık duvar, {} eksik kamera, {} kilitsiz kapı, {} çürük temel, {} çürük malzeme kaldı.",
            walls.len(),
            n(Part::Cameras),
            n(Part::Locks),
            n(Part::Infra),
            deps_after.len()
        );
        print_score(&r);
        write_reports(&cli, &r)?;
        if r.has_findings() {
            code = code.max(1);
        }
    }
    Ok(ExitCode::from(code))
}

/// `--providers` çıktısı
fn providers_table() -> String {
    let mut s = String::from("LLM sağlayıcıları (✔ = ortamda hazır; --provider verilmezse ilk hazır olan seçilir)\n\n");
    s.push_str(&format!("  {:<12} {:<40} {:<55} {}\n", "--provider", "Servis", "Ortam değişkeni", "Varsayılan model"));
    for (id, name, key, model, ready) in providers::catalog() {
        let mark = if ready { "✔" } else { " " };
        s.push_str(&format!("{mark} {id:<12} {name:<40} {key:<55} {model}\n"));
    }
    s.push_str("\nModeli değiştirmek için --model <ad> ya da sağlayıcının *_MODEL değişkeni (ör. OPENAI_MODEL).");
    s
}

/// Önce duvarlar (kod açıkları) yamalanır, sonra kameralar ve kilitler takılır.
async fn drive<P: PatchProvider>(
    provider: P,
    cli: &Cli,
    files: &[(PathBuf, Lang)],
    project: &Project<'_>,
) -> Result<u8> {
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
    section("2) Kırık duvarlar — yamalanıyor");
    for (f, _) in files {
        match orch.remediate(f).await {
            Ok(Outcome::Clean { iterations: 0, suppressed }) => {
                print_suppressed(f, &suppressed);
            }
            Ok(Outcome::Clean { iterations, suppressed }) => {
                println!("  ✔ {} — duvar yamalandı, açık kalmadı ({iterations} tur)", f.display());
                print_suppressed(f, &suppressed);
            }
            Ok(Outcome::Exhausted { remaining }) => {
                println!("  ✘ {} — iterasyon sınırı doldu, {} açık kaldı", f.display(), remaining.len());
                code = code.max(1);
            }
            Ok(Outcome::Stalled { remaining, reason }) => {
                println!("  ✘ {} — durdu ({reason}), {} açık kaldı", f.display(), remaining.len());
                code = code.max(1);
            }
            Ok(Outcome::DryRun { explanation, findings }) => {
                println!("  • {} — {findings} açık için öneri (dry-run):\n    {explanation}", f.display());
            }
            Err(e) => {
                error!("{}: {e}", f.display());
                code = 2;
            }
        }
    }

    if !cli.harden {
        let left = controls::audit(project);
        if !left.is_empty() {
            print_cameras(&left);
            code = code.max(1);
        }
        return Ok(code);
    }

    section("3–5) Eksik kameralar, kilitsiz kapılar ve çürük temel — takılıyor");
    let report = controls::install(project, orch.provider(), orch.scanner(), orch.patcher(), cli.dry_run).await?;
    for (p, id) in &report.installed {
        println!("  ✔ {id} takıldı — {}", p.display());
    }
    for (p, note) in &report.dry_run_notes {
        println!("  • {} (dry-run): {note}", p.display());
    }
    for (p, id, why) in &report.failed {
        println!("  ✘ {id} takılamadı — {} ({why})", p.display());
        code = code.max(1);
    }
    for c in &report.manual {
        println!("  ✋ [{}] {} {} — {}", c.severity, c.id, c.title, c.how_to_fix);
        if !c.detail.is_empty() {
            println!("        {}", c.detail);
        }
        code = code.max(1);
    }
    if !report.packages.is_empty() {
        println!("\n  Yeni savunmalar şu paketleri kullanıyor; kurun ve testleri çalıştırın:");
        print_package_hint(&report.packages);
    }
    if report.installed.is_empty() && report.failed.is_empty() && report.manual.is_empty() && report.dry_run_notes.is_empty() {
        println!("  ✔ Bilinen temel savunmalar zaten yerinde.");
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
