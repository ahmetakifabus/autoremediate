//! 5) Eksik savunmalar ("kameralar")
//!
//! Kod taraması kırık duvarları (açıkları) bulur. Bu modül ise hiç
//! KURULMAMIŞ savunmaları bulur: güvenlik başlıkları, giriş denemesi sınırı,
//! CSRF koruması, güvenli oturum çerezi, yükleme klasöründe betik çalıştırma
//! yasağı, doğrulanmayan Server Action'lar, kayıt (log) eksikliği...
//!
//! Her bulgu bir kurulum yöntemiyle gelir:
//!   * `CreateFile` / `AppendLine`: deterministik, LLM gerekmez
//!   * `Llm`: ilgili dosyaya savunmayı ekleyen hedefli talimat
//!   * `Manual`: insanın yapması gereken adım (ör. dosyayı web kökünden taşımak)
//!
//! Kurulumdan sonra denetim YENİDEN çalıştırılır; savunma görünmüyorsa ya da
//! kod taraması yeni bir açık bulursa değişiklik geri alınır.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use tracing::{info, warn};

use crate::ai::{PatchProvider, PatchRequest};
use crate::error::{Error, Result};
use crate::patcher::Patcher;
use crate::scanner::{Finding, Lang, Scanner, Severity};
use crate::util::SKIP_DIRS;

#[derive(Debug, Clone)]
pub enum Fix {
    /// LLM, `location` dosyasına bu savunmayı ekler
    Llm { instruction: &'static str, packages: &'static [&'static str] },
    /// Yoksa yeni dosya oluştur
    CreateFile { path: PathBuf, content: &'static str },
    /// Dosyanın sonuna satır ekle (yoksa oluştur)
    AppendLine { path: PathBuf, line: &'static str },
    /// İnsan yapmalı
    Manual(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct ControlFinding {
    pub id: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    /// Hırsız bu eksikliği nasıl kullanır?
    pub why: &'static str,
    pub location: PathBuf,
    pub how_to_fix: String,
    #[serde(skip)]
    pub fix: Fix,
}

pub struct Project<'a> {
    pub root: &'a Path,
    pub sources: &'a [(PathBuf, Lang)],
    pub manifests: &'a [PathBuf],
}

struct Src {
    path: PathBuf,
    lang: Lang,
    text: String,
}

fn re(p: &str) -> Regex {
    // Desenler sabit ve testlerle doğrulanıyor.
    Regex::new(p).unwrap_or_else(|e| panic!("geçersiz desen {p:?}: {e}"))
}

// ---- Kurulum talimatları ve şablonlar --------------------------------------

const I_HELMET: &str = "EKSİK SAVUNMA: Express uygulamasında güvenlik başlıkları yok. Modül stiline uygun şekilde \
`helmet` paketini içe aktar (require/import) ve uygulama oluşturulduktan hemen sonra `app.use(helmet())` ekle. \
Başka hiçbir şeyi değiştirme.";
const I_RATELIMIT: &str = "EKSİK SAVUNMA: Express uygulamasında istek/giriş denemesi sınırı yok. Modül stiline uygun \
şekilde `express-rate-limit` paketini içe aktar; tüm uygulama için makul bir genel sınır \
(ör. 15 dakikada IP başına 300 istek, standardHeaders: true, legacyHeaders: false) ekle; dosyada \
login/signin/auth/password/reset/token yolları varsa onlara daha sıkı ayrı bir sınır (ör. 15 dakikada 10 deneme) uygula.";
const I_SESSION_COOKIE: &str = "EKSİK SAVUNMA: Oturum çerezi korumasız. Mevcut session/cookieSession yapılandırmasının \
cookie ayarlarına httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax' ekle \
(mevcut değerleri koru, sadece eksikleri ekle).";
const I_LOGGING: &str = "EKSİK SAVUNMA: İstek kaydı (log) yok; saldırı olduğunda iz kalmaz. Modül stiline uygun şekilde \
`morgan` paketini içe aktar ve uygulama oluşturulduktan sonra `app.use(morgan('combined'))` ekle.";
const I_NEXT_HEADERS: &str = "EKSİK SAVUNMA: Next.js yapılandırmasında güvenlik başlıkları yok. nextConfig nesnesine \
`poweredByHeader: false` ve tüm yollar için (source: '/:path*') şu başlıkları döndüren bir `async headers()` ekle \
(mevcut headers() varsa listeye ekle): X-Frame-Options: DENY; X-Content-Type-Options: nosniff; \
Referrer-Policy: strict-origin-when-cross-origin; Permissions-Policy: camera=(), microphone=(), geolocation=(); \
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload; \
Content-Security-Policy: frame-ancestors 'none'; base-uri 'self'; object-src 'none'. Diğer ayarları koru.";
const I_NEXT_POWERED: &str = "EKSİK SAVUNMA: Next.js `X-Powered-By` başlığıyla teknolojisini ilan ediyor. \
nextConfig nesnesine `poweredByHeader: false` ekle, diğer ayarları koru.";
const I_SERVER_ACTION: &str = "EKSİK SAVUNMA: Bu dosyadaki Server Action'lar herkese açık HTTP uç noktalarıdır ve \
girdileri doğrulanmıyor. Her dışa aktarılan Server Action'ın başında argümanları/FormData'yı bir `zod` şemasıyla \
`safeParse` ile doğrula; geçersizse işlemi yapmadan hata döndür. Mevcut yetki kontrollerini ve dönüş tiplerini koru.";
const I_PHP_SESSION: &str = "EKSİK SAVUNMA: PHP oturum çerezi korumasız. Bu dosyadaki ilk session_start() çağrısından \
hemen önce, oturum zaten başlamamışsa session_set_cookie_params(['lifetime' => 0, 'path' => '/', \
'secure' => true, 'httponly' => true, 'samesite' => 'Lax']) çağır. Başka bir şeyi değiştirme.";
const I_PHP_ERRORS: &str = "EKSİK SAVUNMA: Hata ayrıntıları ziyaretçiye gösteriliyor (display_errors açık) ve saldırgana \
dosya yollarını/sorguları sızdırıyor. display_errors değerini '0' yap ve hataların dosyaya yazılması için \
ini_set('log_errors', '1') ekle.";
const I_PHP_CSRF: &str = "EKSİK SAVUNMA: Bu dosyadaki POST formlarında CSRF koruması yok. Oturumda yoksa \
bin2hex(random_bytes(32)) ile csrf_token üret; her POST formuna gizli csrf_token alanı ekle; POST isteği işlenmeden \
önce hash_equals ile doğrula, uymazsa 403 dönüp dur. Oturum başlatılmamışsa session_start() ekle.";
const I_PHP_BRUTE: &str = "EKSİK SAVUNMA: Giriş denemesi sınırı yok; parola tahmin saldırısına (brute force) açık. \
password_verify kontrolünün etrafına, kullanıcı adı + IP ($_SERVER['REMOTE_ADDR']) anahtarıyla başarısız \
denemeleri sayan (mevcut veritabanı bağlantısı varsa onu, yoksa sys_get_temp_dir() altında bir dosyayı kullanan) \
ve 15 dakikada 5 başarısız denemeden sonra girişi geçici olarak engelleyen bir kontrol ekle; başarılı girişte \
sayacı sıfırla ve session_regenerate_id(true) çağır.";

const NEXT_CONFIG_TEMPLATE: &str = r#"// autoremediate: güvenlik başlıkları ("kameralar")
const securityHeaders = [
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
  { key: 'Content-Security-Policy', value: "frame-ancestors 'none'; base-uri 'self'; object-src 'none'" },
];

/** @type {import('next').NextConfig} */
const nextConfig = {
  poweredByHeader: false,
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }];
  },
};

export default nextConfig;
"#;

const UPLOAD_HTACCESS: &str = r#"# autoremediate: bu yükleme klasöründe betik çalıştırmak yasak.
# Saldırgan "resim" diye PHP yüklese bile çalıştıramaz.
<FilesMatch "\.(php\d?|phtml|phar|pht|phps|cgi|pl|py|sh|asp|aspx|jsp)$">
    Require all denied
</FilesMatch>
<IfModule mod_php.c>
    php_flag engine off
</IfModule>
<IfModule mod_php7.c>
    php_flag engine off
</IfModule>
"#;

const NGINX_UPLOAD_HINT: &str = "Nginx kullanıyorsanız sunucu yapılandırmasına da ekleyin: \
location ~* ^/uploads/.*\\.(php|phtml|phar)$ { deny all; }";

// ---- Denetim ---------------------------------------------------------------

fn read_sources(p: &Project) -> Vec<Src> {
    p.sources
        .iter()
        .filter_map(|(path, lang)| {
            std::fs::read_to_string(path).ok().map(|text| Src { path: path.clone(), lang: *lang, text })
        })
        .collect()
}

fn npm_deps(manifests: &[PathBuf]) -> HashSet<String> {
    let mut out = HashSet::new();
    for m in manifests.iter().filter(|m| m.file_name().is_some_and(|n| n == "package.json")) {
        let Ok(text) = std::fs::read_to_string(m) else { continue };
        let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
        for section in ["dependencies", "devDependencies"] {
            if let Some(map) = v.get(section).and_then(Value::as_object) {
                out.extend(map.keys().cloned());
            }
        }
    }
    out
}

fn file_name(p: &Path) -> &str {
    p.file_name().and_then(|n| n.to_str()).unwrap_or("")
}

/// Proje kökünden itibaren (atlanan dizinler hariç) adı verilen kümede olan dizinler.
fn find_dirs(root: &Path, names: &[&str], max_depth: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            if !ft.is_dir() || ft.is_symlink() {
                continue;
            }
            let name = e.file_name().to_string_lossy().to_ascii_lowercase();
            if SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }
            if names.contains(&name.as_str()) {
                out.push(e.path());
            }
            if depth < max_depth {
                stack.push((e.path(), depth + 1));
            }
        }
    }
    out.sort();
    out
}

fn llm(instruction: &'static str, packages: &'static [&'static str]) -> Fix {
    Fix::Llm { instruction, packages }
}

fn how_to(fix: &Fix) -> String {
    match fix {
        Fix::Llm { packages, .. } if packages.is_empty() => "Otomatik eklenebilir (LLM, yerinde)".into(),
        Fix::Llm { packages, .. } => format!("Otomatik eklenebilir (LLM) + paket: {}", packages.join(" ")),
        Fix::CreateFile { path, .. } => format!("Otomatik: {} oluşturulur", path.display()),
        Fix::AppendLine { path, line } => format!("Otomatik: {} dosyasına `{line}` eklenir", path.display()),
        Fix::Manual(s) => format!("Elle: {s}"),
    }
}

#[allow(clippy::too_many_arguments)]
fn push(
    out: &mut Vec<ControlFinding>,
    id: &'static str,
    severity: Severity,
    title: &'static str,
    why: &'static str,
    location: &Path,
    fix: Fix,
) {
    out.push(ControlFinding { id, severity, title, why, location: location.to_path_buf(), how_to_fix: how_to(&fix), fix });
}

/// Projede kurulmamış savunmaları bulur. Dosyaları her çağrıda diskten okur
/// (kurulumdan sonra yeniden denetim için).
pub fn audit(p: &Project) -> Vec<ControlFinding> {
    let srcs = read_sources(p);
    let deps = npm_deps(p.manifests);
    let mut out = Vec::new();
    let js: Vec<&Src> = srcs.iter().filter(|s| s.lang == Lang::Js).collect();
    let php: Vec<&Src> = srcs.iter().filter(|s| s.lang == Lang::Php).collect();
    let any = |files: &[&Src], r: &Regex| files.iter().any(|s| r.is_match(&s.text));

    // ----- Express -----
    let app_file = js.iter().find(|s| re(r"\bexpress\s*\(\s*\)").is_match(&s.text));
    if let Some(app) = app_file {
        if !any(&js, &re(r"\bhelmet\b")) {
            push(&mut out, "CAM101", Severity::High, "Güvenlik başlıkları yok (helmet)",
                "Tarayıcıya 'bu siteyi çerçeveye koyma, içerik türünü tahmin etme, sadece HTTPS kullan' diyen başlıklar yok; clickjacking ve XSS'in etkisi büyür.",
                &app.path, llm(I_HELMET, &["helmet"]));
        }
        if !any(&js, &re(r"express-rate-limit|rate-limiter-flexible|express-slow-down|express-brute|@upstash/ratelimit|\brateLimit\s*\(")) {
            let login = any(&js, &re(r#"['"`]/(api/)?(auth/)?(login|signin|sign-in|token|password|reset)"#));
            push(&mut out, "CAM102", if login { Severity::High } else { Severity::Medium },
                "İstek / giriş denemesi sınırı yok (rate limit)",
                "Hırsız aynı kapıya saniyede binlerce anahtar dener: parola tahmini, kayıt spam'i, API'yi tüketme.",
                &app.path, llm(I_RATELIMIT, &["express-rate-limit"]));
        }
        if !any(&js, &re(r"\b(morgan|pino|winston|bunyan|log4js|pino-http)\b")) {
            push(&mut out, "CAM105", Severity::Low, "İstek kaydı (log) yok",
                "Güvenlik kamerası kaydı yok: saldırı olduğunda ne olduğunu, nereden geldiğini göremezsiniz.",
                &app.path, llm(I_LOGGING, &["morgan"]));
        }
    }
    let session_re = re(r"\b(session|cookieSession)\s*\(\s*\{");
    for s in js.iter().filter(|s| session_re.is_match(&s.text)) {
        let secure = re(r"\bsecure\s*:").is_match(&s.text);
        let samesite = re(r"(?i)\bsameSite\s*:").is_match(&s.text);
        if !secure || !samesite {
            push(&mut out, "CAM103", Severity::Medium, "Oturum çerezi korumasız (secure / sameSite yok)",
                "Çerez şifresiz bağlantıda çalınabilir ya da başka siteden gelen sahte isteklere (CSRF) eklenir.",
                &s.path, llm(I_SESSION_COOKIE, &[]));
        }
    }

    // ----- Next.js -----
    if deps.contains("next") {
        let configs: Vec<&&Src> = js.iter().filter(|s| file_name(&s.path).starts_with("next.config.")).collect();
        let header_files: String = js
            .iter()
            .filter(|s| {
                let n = file_name(&s.path);
                n.starts_with("next.config.") || n.starts_with("middleware.") || n.starts_with("proxy.")
            })
            .map(|s| s.text.as_str())
            .chain(std::fs::read_to_string(p.root.join("vercel.json")).ok().as_deref())
            .collect::<Vec<_>>()
            .join("\n");
        let has_headers = re(r"X-Frame-Options|frame-ancestors").is_match(&header_files)
            && header_files.contains("Strict-Transport-Security")
            && header_files.contains("X-Content-Type-Options");
        match configs.first() {
            None => {
                let base = p
                    .manifests
                    .iter()
                    .find(|m| file_name(m) == "package.json")
                    .and_then(|m| m.parent())
                    .unwrap_or(p.root);
                if !has_headers {
                    let path = base.join("next.config.mjs");
                    push(&mut out, "CAM201", Severity::High, "Next.js güvenlik başlıkları yok",
                        "Clickjacking, MIME karıştırma ve HTTPS düşürme saldırılarına karşı tarayıcı korumaları kapalı.",
                        &path, Fix::CreateFile { path: path.clone(), content: NEXT_CONFIG_TEMPLATE });
                }
            }
            Some(cfg) => {
                if !has_headers {
                    push(&mut out, "CAM201", Severity::High, "Next.js güvenlik başlıkları yok",
                        "Clickjacking, MIME karıştırma ve HTTPS düşürme saldırılarına karşı tarayıcı korumaları kapalı.",
                        &cfg.path, llm(I_NEXT_HEADERS, &[]));
                } else if !re(r"poweredByHeader\s*:\s*false").is_match(&cfg.text) {
                    push(&mut out, "CAM202", Severity::Low, "Next.js kendini ilan ediyor (X-Powered-By)",
                        "Binanın kapısında 'Next.js' tabelası: hırsız hangi bilinen açığı (ör. React2Shell) deneyeceğini hemen bilir.",
                        &cfg.path, llm(I_NEXT_POWERED, &[]));
                }
            }
        }
        let use_server = re(r#"(?m)^\s*['"]use server['"]"#);
        let exported = re(r"export\s+(default\s+)?(async\s+)?function|export\s+const\s+\w+\s*=\s*async");
        let validated = re(r"\.(parse|safeParse|parseAsync|safeParseAsync)\s*\(|\bvalidate\w*\s*\(");
        for s in js.iter().filter(|s| use_server.is_match(&s.text) && exported.is_match(&s.text)) {
            if !validated.is_match(&s.text) {
                push(&mut out, "CAM203", Severity::High, "Server Action girdisi doğrulanmıyor",
                    "Server Action'lar herkesin doğrudan çağırabildiği HTTP uç noktalarıdır; formdaki kısıtlar sunucuyu korumaz.",
                    &s.path, llm(I_SERVER_ACTION, &["zod"]));
            }
        }
    }

    // ----- PHP -----
    if !php.is_empty() {
        let ini_text: String = [".htaccess", ".user.ini", "php.ini", "public/.htaccess", "public_html/.htaccess"]
            .iter()
            .filter_map(|f| std::fs::read_to_string(p.root.join(f)).ok())
            .collect::<Vec<_>>()
            .join("\n");
        let cookie_conf = re(r"session_set_cookie_params|cookie_httponly|cookie_secure");
        if let Some(s) = php.iter().find(|s| re(r"\bsession_start\s*\(").is_match(&s.text)) {
            if !any(&php, &cookie_conf) && !cookie_conf.is_match(&ini_text) {
                push(&mut out, "CAM301", Severity::Medium, "PHP oturum çerezi korumasız",
                    "Oturum çerezi JavaScript ile okunabilir (XSS ile hesap çalma) ve şifresiz bağlantıda gönderilir.",
                    &s.path, llm(I_PHP_SESSION, &[]));
            }
        }
        let disp = re(r#"(?i)ini_set\s*\(\s*['"]display_errors['"]\s*,\s*['"]?(1|on|true|stdout)"#);
        for s in php.iter().filter(|s| disp.is_match(&s.text)) {
            push(&mut out, "CAM302", Severity::Medium, "Hata ayrıntıları ziyaretçiye gösteriliyor",
                "Hata mesajları hırsıza binanın planını verir: dosya yolları, SQL sorguları, sürümler.",
                &s.path, llm(I_PHP_ERRORS, &[]));
        }
        // Yükleme klasörü: betik çalıştırma yasağı
        let upload_re = re(r"\bmove_uploaded_file\s*\(");
        if any(&php, &upload_re) {
            let lit = re(r#"['"](?:\./)?([\w-]+)/"#);
            let mut dirs: Vec<PathBuf> = find_dirs(p.root, &["upload", "uploads", "user_uploads", "user-uploads", "files", "media"], 6);
            for s in php.iter().filter(|s| upload_re.is_match(&s.text)) {
                for line in s.text.lines().filter(|l| upload_re.is_match(l)) {
                    for c in lit.captures_iter(line) {
                        if let Some(d) = s.path.parent().map(|p| p.join(&c[1])) {
                            if d.is_dir() && !dirs.contains(&d) {
                                dirs.push(d);
                            }
                        }
                    }
                }
            }
            if dirs.is_empty() {
                let s = php.iter().find(|s| upload_re.is_match(&s.text)).map(|s| s.path.clone()).unwrap_or_default();
                push(&mut out, "CAM303", Severity::High, "Yükleme klasöründe betik çalıştırma kapatılmamış",
                    "Hırsız 'resim' diye PHP dosyası yükler, sonra adresini açıp çalıştırır (web shell).",
                    &s, Fix::Manual(format!("Yüklenen dosyaları web kökü dışında saklayın ya da yükleme klasörüne PHP çalıştırmayı kapatan .htaccess koyun. {NGINX_UPLOAD_HINT}")));
            }
            for d in dirs {
                let ht = d.join(".htaccess");
                match std::fs::read_to_string(&ht) {
                    Err(_) => push(&mut out, "CAM303", Severity::High, "Yükleme klasöründe betik çalıştırma kapatılmamış",
                        "Hırsız 'resim' diye PHP dosyası yükler, sonra adresini açıp çalıştırır (web shell).",
                        &d, Fix::CreateFile { path: ht, content: UPLOAD_HTACCESS }),
                    Ok(t) if !re(r"(?i)engine\s+off|Require\s+all\s+denied|Deny\s+from\s+all").is_match(&t) => {
                        push(&mut out, "CAM303", Severity::High, "Yükleme klasöründe betik çalıştırma kapatılmamış",
                            "Hırsız 'resim' diye PHP dosyası yükler, sonra adresini açıp çalıştırır (web shell).",
                            &d, Fix::Manual(format!("{} mevcut; içine PHP çalıştırmayı kapatan kuralları ekleyin (php_flag engine off / Require all denied).", ht.display())))
                    }
                    Ok(_) => {}
                }
            }
        }
        let post_form = re(r#"(?i)<form[^>]*method\s*=\s*["']?post"#);
        let csrf = re(r"(?i)csrf");
        for s in php.iter().filter(|s| post_form.is_match(&s.text) && !csrf.is_match(&s.text)) {
            push(&mut out, "CAM304", Severity::Medium, "POST formlarında CSRF koruması yok",
                "Başka bir site, oturumu açık kullanıcının tarayıcısından bu forma sahte istek gönderebilir.",
                &s.path, llm(I_PHP_CSRF, &[]));
        }
        let brute_guard = re(r"(?i)attempt|throttle|rate.?limit|lockout|too many");
        for s in php.iter().filter(|s| re(r"\bpassword_verify\s*\(").is_match(&s.text) && !brute_guard.is_match(&s.text)) {
            push(&mut out, "CAM305", Severity::Medium, "Giriş denemesi sınırı yok (brute force)",
                "Hırsız aynı hesaba sınırsız parola dener; zayıf parolalar dakikalar içinde düşer.",
                &s.path, llm(I_PHP_BRUTE, &[]));
        }
    }

    // ----- Genel -----
    let env = p.root.join(".env");
    if env.is_file() {
        let gi = std::fs::read_to_string(p.root.join(".gitignore")).unwrap_or_default();
        let ignored = gi.lines().map(str::trim).any(|l| matches!(l, ".env" | "/.env" | ".env*" | "*.env" | ".env.*" | "/.env*"));
        if !ignored {
            push(&mut out, "CAM401", Severity::High, ".env dosyası git'e karşı korunmuyor",
                "Parolalar/anahtarlar bir 'git add -A' ile depoya, oradan da herkesin eline geçebilir.",
                &env, Fix::AppendLine { path: p.root.join(".gitignore"), line: ".env" });
        }
    }
    for d in ["public", "public_html", "www", "htdocs", "web", "static"] {
        let pub_dir = p.root.join(d);
        for (name, title) in [(".env", "Gizli anahtar dosyası (.env) herkese açık klasörde"), (".git", "Git deposu (.git) herkese açık klasörde")] {
            let target = pub_dir.join(name);
            if target.exists() {
                push(&mut out, if name == ".env" { "CAM402" } else { "CAM403" }, Severity::Critical, title,
                    "Kapı açık bırakılmış kasa: tarayıcıdan doğrudan indirilebilir (parolalar / tüm kaynak kod).",
                    &target, Fix::Manual(format!("{} dosyasını web kökü dışına taşıyın ve içindeki tüm anahtarları yenileyin.", target.display())));
            }
        }
    }
    let lock_names = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json", "bun.lockb", "bun.lock"];
    for m in p.manifests.iter().filter(|m| file_name(m) == "package.json") {
        let dir = m.parent().unwrap_or(p.root);
        if !lock_names.iter().any(|l| dir.join(l).exists()) {
            push(&mut out, "CAM404", Severity::Low, "Bağımlılık sürümleri kilitlenmemiş (lockfile yok)",
                "Her kurulumda farklı (ele geçirilmiş olabilecek) sürüm gelebilir; hangi sürümü kullandığınızı denetleyemezsiniz.",
                m, Fix::Manual(format!("{} içinde `npm install` çalıştırıp oluşan package-lock.json dosyasını commit edin.", dir.display())));
        }
    }

    out.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.location.cmp(&b.location)).then_with(|| a.id.cmp(b.id)));
    out
}

// ---- Kurulum ("kamera takma") ----------------------------------------------

#[derive(Debug, Serialize)]
pub struct InstallReport {
    pub installed: Vec<(PathBuf, &'static str)>,
    pub failed: Vec<(PathBuf, &'static str, String)>,
    pub manual: Vec<ControlFinding>,
    pub packages: Vec<&'static str>,
    pub dry_run_notes: Vec<(PathBuf, String)>,
}

pub async fn install<P: PatchProvider>(
    project: &Project<'_>,
    provider: &P,
    scanner: &Scanner,
    patcher: &Patcher,
    dry_run: bool,
) -> Result<InstallReport> {
    let findings = audit(project);
    let mut report = InstallReport { installed: vec![], failed: vec![], manual: vec![], packages: vec![], dry_run_notes: vec![] };
    let mut llm_groups: BTreeMap<PathBuf, Vec<ControlFinding>> = BTreeMap::new();

    for f in findings {
        match &f.fix {
            Fix::Manual(_) => report.manual.push(f),
            Fix::CreateFile { path, content } => {
                if dry_run {
                    report.dry_run_notes.push((path.clone(), format!("{} oluşturulacak", path.display())));
                } else if path.exists() {
                    report.failed.push((path.clone(), f.id, "dosya zaten var, üzerine yazılmadı".into()));
                } else {
                    tokio::fs::write(path, content).await.map_err(|e| Error::io(path, e))?;
                    info!("Kamera takıldı: {} → {}", f.id, path.display());
                    report.installed.push((path.clone(), f.id));
                }
            }
            Fix::AppendLine { path, line } => {
                if dry_run {
                    report.dry_run_notes.push((path.clone(), format!("{} dosyasına `{line}` eklenecek", path.display())));
                } else {
                    let mut text = tokio::fs::read_to_string(path).await.unwrap_or_default();
                    if !text.is_empty() && !text.ends_with('\n') {
                        text.push('\n');
                    }
                    text.push_str(line);
                    text.push('\n');
                    tokio::fs::write(path, text).await.map_err(|e| Error::io(path, e))?;
                    report.installed.push((path.clone(), f.id));
                }
            }
            Fix::Llm { .. } => llm_groups.entry(f.location.clone()).or_default().push(f),
        }
    }

    for (path, group) in llm_groups {
        let Some(lang) = Lang::from_path(&path) else { continue };
        let source = match tokio::fs::read_to_string(&path).await {
            Ok(s) => s,
            Err(e) => {
                warn!("{} okunamadı: {e}", path.display());
                continue;
            }
        };
        let fake: Vec<Finding> = group
            .iter()
            .map(|f| Finding {
                rule_id: f.id,
                severity: f.severity,
                line: 1,
                snippet: String::new(),
                description: match f.fix {
                    Fix::Llm { instruction, .. } => instruction,
                    _ => f.title,
                },
            })
            .collect();
        let file_name = file_name(&path).to_string();
        let req = PatchRequest { file_name: &file_name, language: lang.name(), source: &source, findings: &fake };
        let before = scanner.scan(&source, lang).len();
        let wanted: HashSet<&str> = group.iter().map(|f| f.id).collect();

        let mut done = false;
        let mut last_err = String::from("bilinmeyen");
        for attempt in 1..=2 {
            let proposal = match provider.propose_patch(&req).await {
                Ok(p) => p,
                Err(e) => {
                    last_err = e.to_string();
                    continue;
                }
            };
            if dry_run {
                report.dry_run_notes.push((path.clone(), proposal.explanation));
                done = true;
                break;
            }
            if let Err(e) = patcher.apply(&path, &source, &proposal.fixed_code).await {
                last_err = e.to_string();
                continue;
            }
            // Doğrulama 1: kamera takarken yeni duvar kırılmadı mı?
            let after = scanner.scan(&proposal.fixed_code, lang).len();
            if after > before {
                patcher.rollback(&path, &source).await?;
                last_err = format!("yeni açık oluştu ({before} → {after}), geri alındı");
                continue;
            }
            // Doğrulama 2: kamera gerçekten takıldı mı?
            let still: HashSet<&str> = audit(project)
                .into_iter()
                .filter(|f| f.location == path && wanted.contains(f.id))
                .map(|f| f.id)
                .collect();
            if still.len() == wanted.len() {
                patcher.rollback(&path, &source).await?;
                last_err = format!("savunma eklenmedi (deneme {attempt}), geri alındı");
                continue;
            }
            for f in &group {
                if still.contains(f.id) {
                    report.failed.push((path.clone(), f.id, "kısmen kuruldu; bu savunma eklenemedi".into()));
                } else {
                    report.installed.push((path.clone(), f.id));
                    if let Fix::Llm { packages, .. } = f.fix {
                        report.packages.extend(packages.iter().copied());
                    }
                }
            }
            done = true;
            break;
        }
        if !done {
            for f in &group {
                report.failed.push((path.clone(), f.id, last_err.clone()));
            }
        }
    }
    report.packages.sort();
    report.packages.dedup();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempProject {
        root: PathBuf,
    }
    impl TempProject {
        fn new(tag: &str) -> Self {
            let root = std::env::temp_dir().join(format!("autofix_ctl_{}_{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            Self { root }
        }
        fn write(&self, rel: &str, text: &str) -> PathBuf {
            let p = self.root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, text).unwrap();
            p
        }
        fn audit(&self, sources: &[&str], manifests: &[&str]) -> Vec<&'static str> {
            let s: Vec<(PathBuf, Lang)> =
                sources.iter().map(|r| { let p = self.root.join(r); let l = Lang::from_path(&p).unwrap(); (p, l) }).collect();
            let m: Vec<PathBuf> = manifests.iter().map(|r| self.root.join(r)).collect();
            let mut ids: Vec<_> = audit(&Project { root: &self.root, sources: &s, manifests: &m }).iter().map(|f| f.id).collect();
            ids.sort();
            ids
        }
    }
    impl Drop for TempProject {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn bare_express_app_lacks_cameras() {
        let t = TempProject::new("express");
        t.write("app.js", "const express = require('express');\nconst session = require('express-session');\nconst app = express();\napp.use(session({ secret: process.env.S }));\napp.post('/login', h);\n");
        t.write("package.json", r#"{"dependencies":{"express":"^4"}}"#);
        assert_eq!(t.audit(&["app.js"], &["package.json"]), vec!["CAM101", "CAM102", "CAM103", "CAM105", "CAM404"]);
    }

    #[test]
    fn hardened_express_app_is_quiet() {
        let t = TempProject::new("express_ok");
        t.write("app.js", "import helmet from 'helmet';\nimport rateLimit from 'express-rate-limit';\nimport morgan from 'morgan';\nconst app = express();\napp.use(helmet());\napp.use(morgan('combined'));\napp.use(session({ cookie: { secure: true, sameSite: 'lax' } }));\n");
        t.write("package.json", r#"{"dependencies":{"express":"^4"}}"#);
        t.write("package-lock.json", "{}");
        assert!(t.audit(&["app.js"], &["package.json"]).is_empty());
    }

    #[test]
    fn next_without_config_gets_template_and_actions_are_checked() {
        let t = TempProject::new("next");
        t.write("package.json", r#"{"dependencies":{"next":"15.5.9"}}"#);
        t.write("package-lock.json", "{}");
        t.write("app/actions.ts", "'use server'\nexport async function save(formData: FormData) { await db.insert(formData.get('x')) }\n");
        let ids = t.audit(&["app/actions.ts"], &["package.json"]);
        assert_eq!(ids, vec!["CAM201", "CAM203"]);
        // Şablon kendi denetimimizden geçmeli
        t.write("next.config.mjs", NEXT_CONFIG_TEMPLATE);
        let ids = t.audit(&["app/actions.ts", "next.config.mjs"], &["package.json"]);
        assert_eq!(ids, vec!["CAM203"]);
    }

    #[test]
    fn php_upload_dir_gets_htaccess() {
        let t = TempProject::new("php");
        t.write("upload.php", "<?php\nsession_start();\nmove_uploaded_file($tmp, 'uploads/' . $name);\n?>\n<form method=\"post\"></form>\n");
        std::fs::create_dir_all(t.root.join("uploads")).unwrap();
        let ids = t.audit(&["upload.php"], &[]);
        assert_eq!(ids, vec!["CAM301", "CAM303", "CAM304"]);
        t.write("uploads/.htaccess", UPLOAD_HTACCESS);
        assert_eq!(t.audit(&["upload.php"], &[]), vec!["CAM301", "CAM304"]);
    }

    use crate::ai::PatchProposal;

    /// helmet ekleyen sahte LLM
    struct AddHelmet;
    impl PatchProvider for AddHelmet {
        async fn propose_patch(&self, req: &PatchRequest<'_>) -> Result<PatchProposal> {
            Ok(PatchProposal {
                explanation: "helmet eklendi".into(),
                fixed_code: format!("{}const helmet = require('helmet');\napp.use(helmet());\n", req.source),
            })
        }
    }

    /// "Taktım" deyip hiçbir şey takmayan sahte LLM
    struct Liar;
    impl PatchProvider for Liar {
        async fn propose_patch(&self, req: &PatchRequest<'_>) -> Result<PatchProposal> {
            Ok(PatchProposal { explanation: "tamam".into(), fixed_code: format!("{}// güvenli\n", req.source) })
        }
    }

    const BARE_APP: &str = "const express = require('express');\nconst rateLimit = require('express-rate-limit');\nconst morgan = require('morgan');\nconst app = express();\n";

    async fn run_install<P: PatchProvider>(t: &TempProject, p: &P) -> InstallReport {
        let sources = vec![(t.root.join("app.js"), Lang::Js)];
        let project = Project { root: &t.root, sources: &sources, manifests: &[] };
        install(&project, p, &Scanner::new().unwrap(), &Patcher::new(None, None), false).await.unwrap()
    }

    #[tokio::test]
    async fn cameras_are_installed_and_verified() {
        let t = TempProject::new("install_ok");
        t.write("app.js", BARE_APP);
        t.write(".env", "DB_PASS=x\n");
        let r = run_install(&t, &AddHelmet).await;
        let mut ids: Vec<_> = r.installed.iter().map(|(_, id)| *id).collect();
        ids.sort();
        assert_eq!(ids, vec!["CAM101", "CAM401"], "{r:?}");
        assert_eq!(r.packages, vec!["helmet"]);
        assert!(r.failed.is_empty());
        assert!(std::fs::read_to_string(t.root.join(".gitignore")).unwrap().contains(".env"));
        assert!(t.audit(&["app.js"], &[]).is_empty());
    }

    #[tokio::test]
    async fn fake_installs_are_rolled_back() {
        let t = TempProject::new("install_liar");
        t.write("app.js", BARE_APP);
        let r = run_install(&t, &Liar).await;
        assert!(r.installed.is_empty());
        assert_eq!(r.failed.len(), 1);
        assert_eq!(std::fs::read_to_string(t.root.join("app.js")).unwrap(), BARE_APP, "dosya orijinaline dönmeli");
    }

    #[test]
    fn env_and_public_secrets() {
        let t = TempProject::new("env");
        t.write(".env", "DB_PASS=x\n");
        t.write("public/.git/HEAD", "ref: refs/heads/master\n");
        assert_eq!(t.audit(&[], &[]), vec!["CAM401", "CAM403"]);
        t.write(".gitignore", "node_modules\n.env\n");
        assert_eq!(t.audit(&[], &[]), vec!["CAM403"]);
    }
}
