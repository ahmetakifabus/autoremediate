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
    /// INI dosyasında `anahtar = değer` (varsa değiştir, yoksa ekle)
    IniSet { path: PathBuf, key: &'static str, value: &'static str },
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
    /// Ayrıntı (ör. korumasız yolların listesi); boş olabilir
    #[serde(skip_serializing_if = "String::is_empty")]
    pub detail: String,
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

const I_EXPRESS_AUTH: &str = "EKSİK KİLİT: Bu dosyadaki yönetim / hassas yollar kimlik doğrulaması olmadan herkese açık. \
Projede zaten bir kimlik doğrulama ara katmanı (ör. requireAuth, isAuthenticated, passport.authenticate, verifyToken) \
varsa onu bu yollara ekle; yoksa dosyada `req.session?.user` (ya da `req.user`) yoksa 401, yönetim yollarında \
kullanıcının rolü 'admin' değilse 403 döndüren küçük bir `requireAuth` ara katmanı tanımla ve hassas yolların \
handler'ından önce kullan. Diğer yolları ve davranışı değiştirme.";
const I_NEXT_AUTH: &str = "EKSİK KİLİT: Bu Next.js sayfası / route handler'ı kimlik doğrulaması yapmıyor. Projede \
kullanılan kimlik doğrulama yöntemini (ör. auth() / getServerSession / currentUser / cookies() ile oturum) \
kullanarak işlemin başında oturumu kontrol et; oturum yoksa route handler'da 401 döndür, sayfada redirect('/login') \
yap; yönetim sayfalarında rol 'admin' değilse 403 / notFound(). Başka bir şeyi değiştirme.";
const I_ACTION_AUTH: &str = "EKSİK KİLİT: Bu dosyadaki Server Action'lar veriyi değiştiriyor ama çağıranın kim olduğunu \
kontrol etmiyor; Server Action'lar herkesin doğrudan çağırabildiği uç noktalardır. Her veri değiştiren action'ın \
başında projedeki kimlik doğrulama yöntemiyle oturumu al, yoksa hata fırlat/döndür; kaydı değiştirmeden önce \
kaydın o kullanıcıya ait olduğunu (ya da kullanıcının yetkili olduğunu) kontrol et.";
const I_PHP_AUTH: &str = "EKSİK KİLİT: Bu PHP sayfası yönetim işlemi / veri silme-güncelleme yapıyor ama giriş kontrolü \
yok. Dosyanın en başında (çıktıdan önce) oturumu başlat (session_status() !== PHP_SESSION_ACTIVE ise session_start()) \
ve $_SESSION içinde oturum açmış kullanıcı yoksa http_response_code(401) (ya da login sayfasına yönlendirme) ile \
dur; yönetim sayfalarında kullanıcının rolü admin değilse 403 ile dur. Projede zaten bir auth/check dosyası varsa \
onu require_once ile kullan.";
const I_FLASK_AUTH: &str = "EKSİK KİLİT: Bu Flask/Django dosyasındaki yönetim yolları giriş kontrolü olmadan açık. \
Flask'ta flask_login'in @login_required dekoratörünü (ve admin rol kontrolünü), Django'da @login_required / \
@staff_member_required dekoratörünü bu görünümlere ekle. Başka bir şeyi değiştirme.";
const I_FLASK_HEADERS: &str = "EKSİK SAVUNMA: Flask uygulamasında güvenlik başlıkları yok. `flask_talisman` paketinden \
Talisman'ı içe aktar ve uygulama oluşturulduktan hemen sonra `Talisman(app, content_security_policy=None)` ekle \
(HTTPS yönlendirmesi ve HSTS, X-Frame-Options, X-Content-Type-Options gelir). Başka bir şeyi değiştirme.";
const I_FLASK_LIMIT: &str = "EKSİK SAVUNMA: Flask uygulamasında giriş denemesi sınırı yok. `flask_limiter` paketinden \
Limiter ve get_remote_address'i içe aktar, `limiter = Limiter(get_remote_address, app=app, default_limits=[\"300 per 15 minutes\"])` \
ekle ve login/şifre sıfırlama yollarına `@limiter.limit(\"10 per 15 minutes\")` uygula.";
const I_DJANGO_SECURE: &str = "EKSİK SAVUNMA: Django ayarlarında üretim güvenlik ayarları eksik. Dosyanın sonuna, mevcut \
değerleri ezmeden eksik olanları ekle: SESSION_COOKIE_SECURE = True, CSRF_COOKIE_SECURE = True, \
SESSION_COOKIE_HTTPONLY = True, SECURE_CONTENT_TYPE_NOSNIFF = True, X_FRAME_OPTIONS = 'DENY', \
SECURE_HSTS_SECONDS = 31536000, SECURE_HSTS_INCLUDE_SUBDOMAINS = True, SECURE_SSL_REDIRECT = not DEBUG.";
const I_DJANGO_CSRF: &str = "EKSİK SAVUNMA: Django MIDDLEWARE listesinde CsrfViewMiddleware yok; tüm formlar CSRF'ye açık. \
'django.middleware.csrf.CsrfViewMiddleware' girdisini MIDDLEWARE listesine, SessionMiddleware'den sonra ve \
CommonMiddleware'in hemen ardından ekle.";
const I_GO_HEADERS: &str = "EKSİK SAVUNMA: Go HTTP sunucusu güvenlik başlıkları göndermiyor ve zaman aşımı yok. \
Her yanıta X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Referrer-Policy: strict-origin-when-cross-origin, \
Strict-Transport-Security: max-age=63072000; includeSubDomains başlıklarını ekleyen küçük bir ara katman \
(func securityHeaders(next http.Handler) http.Handler) yaz ve sunucu handler'ını onunla sar. http.ListenAndServe \
kullanılıyorsa ReadHeaderTimeout: 10*time.Second, ReadTimeout, WriteTimeout ve IdleTimeout ayarlı bir http.Server \
kullan. Mevcut yönlendirmeleri değiştirme.";

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
        Fix::IniSet { path, key, value } => format!("Otomatik: {} içinde `{key} = {value}`", path.display()),
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
    push_d(out, id, severity, title, why, location, String::new(), fix);
}

#[allow(clippy::too_many_arguments)]
fn push_d(
    out: &mut Vec<ControlFinding>,
    id: &'static str,
    severity: Severity,
    title: &'static str,
    why: &'static str,
    location: &Path,
    detail: String,
    fix: Fix,
) {
    out.push(ControlFinding { id, severity, title, why, location: location.to_path_buf(), detail, how_to_fix: how_to(&fix), fix });
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

    // ----- Python (Flask / Django) -----
    let py: Vec<&Src> = srcs.iter().filter(|s| s.lang == Lang::Python).collect();
    if let Some(app) = py.iter().find(|s| re(r"\bFlask\s*\(\s*__name__").is_match(&s.text)) {
        if !any(&py, &re(r"(?i)talisman|X-Frame-Options|secure\.Secure")) {
            push(&mut out, "CAM110", Severity::High, "Flask güvenlik başlıkları yok",
                "Tarayıcı korumaları (çerçeveleme yasağı, HTTPS zorlaması, içerik türü kilidi) kapalı.",
                &app.path, llm(I_FLASK_HEADERS, &["pip:flask-talisman"]));
        }
        let login = any(&py, &re(r#"(?i)route\s*\(\s*['"]/(api/)?(auth/)?(login|signin|token|password|reset)"#));
        if login && !any(&py, &re(r"(?i)\blimiter\b|ratelimit|rate_limit")) {
            push(&mut out, "CAM111", Severity::High, "Giriş denemesi sınırı yok (rate limit)",
                "Hırsız aynı kapıya saniyede binlerce anahtar dener: parola tahmini, kayıt spam'i.",
                &app.path, llm(I_FLASK_LIMIT, &["pip:Flask-Limiter"]));
        }
    }
    for s in py.iter().filter(|s| file_name(&s.path) == "settings.py" && s.text.contains("INSTALLED_APPS")) {
        let has = |k: &str| re(&format!(r"(?m)^\s*{k}\s*=")).is_match(&s.text);
        if !(has("SESSION_COOKIE_SECURE") && has("CSRF_COOKIE_SECURE") && has("SECURE_HSTS_SECONDS")) {
            push(&mut out, "CAM112", Severity::Medium, "Django üretim güvenlik ayarları eksik",
                "Çerezler şifresiz bağlantıda gider, HTTPS zorlanmaz; oturum çalınabilir.",
                &s.path, llm(I_DJANGO_SECURE, &[]));
        }
        if s.text.contains("MIDDLEWARE") && !s.text.contains("CsrfViewMiddleware") {
            push(&mut out, "CAM113", Severity::High, "Django CSRF koruması kapalı",
                "Başka bir site, oturumu açık kullanıcının tarayıcısından sahte form gönderebilir.",
                &s.path, llm(I_DJANGO_CSRF, &[]));
        }
    }

    // ----- Go -----
    let go: Vec<&Src> = srcs.iter().filter(|s| s.lang == Lang::Go).collect();
    let go_server = re(r"\bhttp\.(ListenAndServe|HandleFunc|Handle)\s*\(|\bgin\.(Default|New)\s*\(|\bchi\.NewRouter\s*\(|\bmux\.NewRouter\s*\(|\bfiber\.New\s*\(|\becho\.New\s*\(");
    if let Some(srv) = go.iter().find(|s| go_server.is_match(&s.text)) {
        if !any(&go, &re(r"X-Frame-Options|unrolled/secure|helmet|Content-Security-Policy")) {
            push(&mut out, "CAM120", Severity::Medium, "Go sunucusu güvenlik başlıkları göndermiyor",
                "Tarayıcı korumaları kapalı; zaman aşımı yoksa yavaş bağlantılarla sunucu kilitlenebilir.",
                &srv.path, llm(I_GO_HEADERS, &[]));
        }
    }

    // ----- Kapı kilitleri: kimlik doğrulaması olmayan hassas kapılar -----
    locks(&mut out, p.root, &js, &php, &py, &deps);

    // ----- Binanın altyapısı: sunucu / çalışma ortamı ayarları -----
    server_audit(&mut out, p);

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

// ---- Kapı kilitleri -----------------------------------------------------------

/// Kimlik doğrulama / yetki kontrolüne işaret eden kalıplar
const AUTH_MARK: &str = r"(?i)auth|login|protect|guard|verify|jwt|passport|session|isadmin|requirerole|ensure\w*|permission|\bacl\b|\bcan\(|currentuser|getuser|clerk|getserversession|gettoken|staff_member|is_staff|is_superuser";
const SENSITIVE_PATH: &str = r"(?i)/(api/)?(admin|dashboard|manage|management|panel|yonetim|internal|debug|config|settings|backup|export|import|users?/:\w+)\b";

fn locks(out: &mut Vec<ControlFinding>, root: &Path, js: &[&Src], php: &[&Src], py: &[&Src], deps: &HashSet<String>) {
    let auth = re(AUTH_MARK);
    // Proje köküne göreli, "/" ayraçlı yol (kökün kendi adı eşleşmeye karışmasın)
    let rel = |p: &Path| format!("/{}", p.strip_prefix(root).unwrap_or(p).to_string_lossy().replace('\\', "/"));

    // Express / Koa tarzı yönlendiriciler
    let route = re(r#"\b(app|router|r|api|admin)\.(get|post|put|patch|delete|all|use)\s*\(\s*['"`](/[^'"`]*)['"`]\s*,(.*)$"#);
    let sensitive = re(SENSITIVE_PATH);
    let global_auth = re(r"(?i)\b(app|router)\.use\s*\(\s*(['`\x22][^'`\x22]*['`\x22]\s*,\s*)?[\w.]*(auth|passport|jwt|protect|guard|session|ensure)");
    for s in js {
        if global_auth.is_match(&s.text) {
            continue;
        }
        let open: Vec<String> = s
            .text
            .lines()
            .filter_map(|l| route.captures(l))
            .filter(|c| sensitive.is_match(&c[3]) && !auth.is_match(&c[4]))
            .map(|c| format!("{} {}", c[2].to_ascii_uppercase(), &c[3]))
            .collect();
        if !open.is_empty() {
            push_d(out, "CAM501", Severity::High, "Yönetim / hassas yollar kilitsiz (kimlik doğrulaması yok)",
                "Hırsız kapıyı denemez bile, açık: /admin gibi yollara giriş yapmadan erişir, veri siler / indirir.",
                &s.path, format!("Kilitsiz: {}", open.join(", ")), llm(I_EXPRESS_AUTH, &[]));
        }
    }

    // Next.js App Router: route handler'lar ve yönetim sayfaları
    if deps.contains("next") {
        let mw_protects_admin = js.iter().any(|s| {
            let n = file_name(&s.path);
            (n.starts_with("middleware.") || n.starts_with("proxy.")) && s.text.contains("admin") && auth.is_match(&s.text)
        });
        let mutating = re(r"export\s+(async\s+)?(function\s+(POST|PUT|PATCH|DELETE)\b|const\s+(POST|PUT|PATCH|DELETE)\b)");
        for s in js {
            let path = rel(&s.path);
            let n = file_name(&s.path);
            let in_app = path.contains("/app/");
            let admin = re(r"(?i)/(admin|dashboard|panel|yonetim)/").is_match(&path);
            let is_route = n.starts_with("route.");
            let is_page = n.starts_with("page.") || n.starts_with("layout.");
            if !in_app || auth.is_match(&s.text) {
                continue;
            }
            if admin && (is_route || is_page) && !mw_protects_admin {
                push(out, "CAM502", Severity::High, "Next.js yönetim sayfası / API'si kilitsiz",
                    "Yönetim paneli adresini bilen herkes içeri girer; Next.js 'gizli link' koruma değildir.",
                    &s.path, llm(I_NEXT_AUTH, &[]));
            } else if is_route && mutating.is_match(&s.text) {
                push(out, "CAM502", Severity::Medium, "Veri değiştiren API ucu kimlik doğrulamasız",
                    "POST/PUT/DELETE uçlarını herkes doğrudan çağırabilir; veri ekleyebilir, silebilir.",
                    &s.path, llm(I_NEXT_AUTH, &[]));
            }
        }
        let use_server = re(r#"(?m)^\s*['"]use server['"]"#);
        let writes = re(r"\b(prisma|db|sql|supabase|drizzle|knex|mongoose|\w+Model|\w+Repo\w*)\b[^;\n]*\.(create|createMany|update|updateMany|upsert|delete|deleteMany|insert|destroy|remove|from)\s*\(");
        for s in js.iter().filter(|s| use_server.is_match(&s.text) && writes.is_match(&s.text) && !auth.is_match(&s.text)) {
            push(out, "CAM503", Severity::High, "Server Action veriyi kimlik kontrolü olmadan değiştiriyor",
                "Server Action'lar herkese açık HTTP uçlarıdır: hırsız başkasının kaydını güncelleyebilir / silebilir (IDOR).",
                &s.path, llm(I_ACTION_AUTH, &[]));
        }
    }

    // PHP: yönetim sayfaları ve veri silen/güncelleyen betikler
    let php_guard = re(r"(?i)\$_SESSION|auth|login|check_?user|is_?logged|require_?login|current_?user");
    let destructive = re(r"(?i)\bDELETE\s+FROM\b|\bUPDATE\s+\w+\s+SET\b|\bunlink\s*\(|\bDROP\s+TABLE\b");
    let input = re(r"\$_(GET|POST|REQUEST)\b");
    for s in php {
        if php_guard.is_match(&s.text) {
            continue;
        }
        let path = rel(&s.path).to_ascii_lowercase();
        let admin = re(r"/(admin|panel|yonetim|manage|dashboard)[^/]*(/|\.php)").is_match(&path);
        if admin {
            push(out, "CAM504", Severity::High, "PHP yönetim sayfası kilitsiz (giriş kontrolü yok)",
                "Adresi tahmin eden herkes yönetim paneline girer; /admin ilk denenen kapıdır.",
                &s.path, llm(I_PHP_AUTH, &[]));
        } else if destructive.is_match(&s.text) && input.is_match(&s.text) {
            push(out, "CAM505", Severity::High, "Veri silen / güncelleyen PHP betiği kimlik kontrolü yapmıyor",
                "Hırsız istek parametresini değiştirerek başkasının kaydını siler / değiştirir.",
                &s.path, llm(I_PHP_AUTH, &[]));
        }
    }

    // Flask / Django görünümleri
    let py_admin = re(r#"(?i)(route|path|re_path|get|post)\s*\(\s*r?['"]\^?/?(admin|dashboard|panel|manage|internal)"#);
    let py_guard = re(r"(?i)login_required|staff_member_required|permission_required|current_user|jwt_required|auth_required|is_authenticated|Depends\(\s*\w*(auth|user)");
    for s in py {
        // Django'nun kendi admin sitesi (admin.site.urls) kendi kimlik doğrulamasıyla gelir
        if py_admin.is_match(&s.text) && !py_guard.is_match(&s.text) && !s.text.contains("admin.site.urls") {
            push(out, "CAM506", Severity::High, "Python yönetim görünümleri kilitsiz",
                "Yönetim adresini bilen herkes giriş yapmadan erişir.",
                &s.path, llm(I_FLASK_AUTH, &[]));
        }
    }
}

// ---- Binanın altyapısı: sunucu ve çalışma ortamı -----------------------------

/// Kökten itibaren (atlanan dizinler hariç) adı `pred` ile eşleşen dosyalar
fn find_files(root: &Path, max_depth: usize, pred: &dyn Fn(&str, &Path) -> bool) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            let name = e.file_name().to_string_lossy().to_string();
            if ft.is_dir() {
                if depth < max_depth && !SKIP_DIRS.contains(&name.as_str()) {
                    stack.push((e.path(), depth + 1));
                }
            } else if ft.is_file() && pred(&name, &e.path()) {
                out.push(e.path());
            }
        }
    }
    out.sort();
    out
}

/// İlk "ana.alt" sürüm numarası
fn major_minor(text: &str) -> Option<(u32, u32)> {
    let c = re(r"(\d+)(?:\.(\d+))?").captures(text)?;
    Some((c[1].parse().ok()?, c.get(2).and_then(|m| m.as_str().parse().ok()).unwrap_or(0)))
}

const WHY_EOL: &str = "Desteği bitmiş çalışma ortamı artık güvenlik yaması almıyor: yeni bulunan her açık sonsuza dek açık kalır.";

fn server_audit(out: &mut Vec<ControlFinding>, p: &Project) {
    let root = p.root;
    let read = |f: &Path| std::fs::read_to_string(f).unwrap_or_default();

    // --- nginx ---
    let nginx_files = find_files(root, 5, &|n, path| {
        let in_nginx_dir = path.components().any(|c| {
            let c = c.as_os_str().to_string_lossy();
            c == "nginx" || c == "conf.d" || c.starts_with("sites-")
        });
        n == "nginx.conf" || (n.ends_with(".conf") && in_nginx_dir)
    });
    for f in &nginx_files {
        let t = read(f);
        if !t.contains("server") && !t.contains("http") {
            continue;
        }
        if !re(r"(?m)^\s*server_tokens\s+off\s*;").is_match(&t) && (t.contains("http {") || t.contains("server {")) {
            push(out, "CAM601", Severity::Low, "nginx sürümünü ilan ediyor (server_tokens)",
                "Kapıdaki tabela: hırsız sunucu sürümüne uygun bilinen açığı seçer.",
                f, Fix::Manual("http { } (ya da server { }) bloğuna `server_tokens off;` ekleyin.".into()));
        }
        if re(r"(?m)^\s*autoindex\s+on\s*;").is_match(&t) {
            push(out, "CAM602", Severity::Medium, "nginx dizin listeleme açık (autoindex on)",
                "Hırsız klasörün içini vitrin gibi görür: yedekler, yüklemeler, unutulmuş dosyalar.",
                f, Fix::Manual("`autoindex on;` satırını `autoindex off;` yapın.".into()));
        }
        if re(r"(?m)^\s*ssl_protocols\b[^;]*\bTLSv1(\.1)?(\s|;)").is_match(&t) {
            push(out, "CAM603", Severity::High, "nginx eski TLS sürümlerine izin veriyor (TLS 1.0/1.1)",
                "Kırılmış eski şifreleme: trafik araya girilerek çözülebilir.",
                f, Fix::Manual("`ssl_protocols TLSv1.2 TLSv1.3;` kullanın.".into()));
        }
        if t.contains("server {") && !re(r"add_header\s+(X-Frame-Options|Strict-Transport-Security|Content-Security-Policy)").is_match(&t) {
            push(out, "CAM604", Severity::Medium, "nginx güvenlik başlıkları göndermiyor",
                "Uygulama başlık eklemese bile sunucu ekleyebilir; şu an hiçbir katman eklemiyor.",
                f, Fix::Manual("server { } bloğuna ekleyin: add_header X-Frame-Options DENY always; add_header X-Content-Type-Options nosniff always; add_header Referrer-Policy strict-origin-when-cross-origin always; add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains\" always;".into()));
        }
        if re(r"(?m)^\s*listen\s+(\[::\]:)?80\b").is_match(&t) && !re(r"return\s+30[18]\s+https").is_match(&t) {
            push(out, "CAM605", Severity::Medium, "HTTP (80) trafiği HTTPS'e yönlendirilmiyor",
                "Ziyaretçi şifresiz bağlantıda kalır; parolalar ve çerezler yolda okunabilir.",
                f, Fix::Manual("80 portundaki server bloğunda `return 301 https://$host$request_uri;` kullanın.".into()));
        }
    }

    // --- Apache ---
    let apache_files = find_files(root, 5, &|n, _| {
        matches!(n, ".htaccess" | "httpd.conf" | "apache2.conf" | "ssl.conf") || (n.ends_with(".conf") && n.contains("apache"))
    });
    for f in &apache_files {
        let t = read(f);
        if re(r"(?mi)^\s*Options\b[^\n]*(\s|\+)Indexes\b").is_match(&t) {
            push(out, "CAM611", Severity::Medium, "Apache dizin listeleme açık (Options Indexes)",
                "Hırsız klasörün içini vitrin gibi görür: yedekler, yüklemeler, unutulmuş dosyalar.",
                f, Fix::Manual("`Options -Indexes` kullanın.".into()));
        }
        if re(r"(?mi)^\s*ServerSignature\s+On|^\s*ServerTokens\s+(Full|OS|Minor|Major)").is_match(&t) {
            push(out, "CAM612", Severity::Low, "Apache sürümünü ilan ediyor",
                "Kapıdaki tabela: hırsız sunucu sürümüne uygun bilinen açığı seçer.",
                f, Fix::Manual("`ServerTokens Prod` ve `ServerSignature Off` kullanın.".into()));
        }
        let weak_tls = t.lines().any(|l| {
            let l = l.trim();
            l.starts_with("SSLProtocol")
                && (re(r"(^|\s)\+?TLSv1(\.1)?(\s|$)").is_match(l) || (l.contains(" all") && !l.contains("-TLSv1")))
        });
        if weak_tls {
            push(out, "CAM613", Severity::High, "Apache eski TLS sürümlerine izin veriyor (TLS 1.0/1.1)",
                "Kırılmış eski şifreleme: trafik araya girilerek çözülebilir.",
                f, Fix::Manual("`SSLProtocol -all +TLSv1.2 +TLSv1.3` kullanın.".into()));
        }
    }

    // --- php.ini ---
    let ini_files = find_files(root, 4, &|n, _| n == "php.ini" || n == ".user.ini" || (n.starts_with("php") && n.ends_with(".ini")));
    for f in &ini_files {
        let t = read(f);
        let get = |k: &str| {
            re(&format!(r"(?mi)^\s*{}\s*=\s*(.*?)\s*$", regex::escape(k))).captures(&t).map(|c| c[1].trim_matches('"').to_ascii_lowercase())
        };
        let on = |v: &str| matches!(v, "1" | "on" | "true" | "yes" | "stdout");
        if get("allow_url_include").is_some_and(|v| on(&v)) {
            push(out, "CAM623", Severity::Critical, "allow_url_include açık (uzaktan kod dahil etme)",
                "Tek bir include açığı, hırsızın kendi sunucusundaki kodu sizin binanızda çalıştırmasına dönüşür.",
                f, Fix::IniSet { path: f.clone(), key: "allow_url_include", value: "Off" });
        }
        if get("display_errors").is_some_and(|v| on(&v)) {
            push(out, "CAM622", Severity::Medium, "php.ini: hata ayrıntıları ziyaretçiye gösteriliyor",
                "Hata mesajları hırsıza binanın planını verir: dosya yolları, SQL sorguları, sürümler.",
                f, Fix::IniSet { path: f.clone(), key: "display_errors", value: "Off" });
        }
        if get("expose_php").is_some_and(|v| on(&v)) {
            push(out, "CAM621", Severity::Low, "PHP sürümünü ilan ediyor (expose_php)",
                "Kapıdaki tabela: X-Powered-By başlığı hırsıza PHP sürümünü söyler.",
                f, Fix::IniSet { path: f.clone(), key: "expose_php", value: "Off" });
        }
        if get("session.cookie_httponly").is_some_and(|v| !on(&v)) {
            push(out, "CAM624", Severity::Medium, "php.ini: oturum çerezi JavaScript'e açık",
                "XSS ile oturum çerezi okunup hesap ele geçirilir.",
                f, Fix::IniSet { path: f.clone(), key: "session.cookie_httponly", value: "1" });
        }
    }

    // --- Dockerfile ---
    let dockerfiles = find_files(root, 4, &|n, _| n == "Dockerfile" || n.starts_with("Dockerfile.") || n.ends_with(".dockerfile"));
    let from_re = re(r"(?mi)^\s*FROM\s+(?:--\S+\s+)?(\S+)");
    for f in &dockerfiles {
        let t = read(f);
        let images: Vec<String> = from_re.captures_iter(&t).map(|c| c[1].to_ascii_lowercase()).collect();
        if !re(r"(?mi)^\s*USER\s+\S+").is_match(&t) || re(r"(?mi)^\s*USER\s+(root|0)\s*$").is_match(&t) {
            push(out, "CAM631", Severity::Medium, "Konteyner root olarak çalışıyor",
                "İçeri giren hırsız binanın anahtar destesine sahip olur: konteynerden kaçış ve kalıcılık kolaylaşır.",
                f, Fix::Manual("Son aşamaya ayrıcalıksız bir kullanıcı ekleyin, ör. `USER node` / `USER www-data` / `RUN adduser -D app` + `USER app`.".into()));
        }
        if images.iter().any(|i| i != "scratch" && !i.starts_with('$') && (i.ends_with(":latest") || (!i.contains(':') && !i.contains('@')))) {
            push(out, "CAM632", Severity::Low, "Konteyner imajı sabitlenmemiş (:latest)",
                "Her derlemede farklı (ele geçirilmiş olabilecek) imaj gelebilir; neyi çalıştırdığınızı denetleyemezsiniz.",
                f, Fix::Manual("FROM satırlarında belirli bir sürüm (ör. node:22-alpine) ya da @sha256 özeti kullanın.".into()));
        }
        if re(r"(?mi)^\s*(ENV|ARG)\s+\w*(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\w*(\s*=\s*|\s+)[^\s$]").is_match(&t) {
            push(out, "CAM633", Severity::High, "Dockerfile içinde gizli bilgi",
                "İmajı indiren herkes (docker history) parolayı okur.",
                f, Fix::Manual("Sırları ENV/ARG ile imaja gömmeyin; çalışma anında ortam değişkeni ya da Docker/Kubernetes secret ile verin.".into()));
        }
        for img in &images {
            let (name, tag) = img.rsplit_once('/').map(|(_, x)| x).unwrap_or(img).split_once(':').unwrap_or((img, ""));
            let Some((maj, min)) = major_minor(tag) else { continue };
            let eol = match name {
                "php" => (maj, min) < (8, 2),
                "node" => maj < 22,
                "python" => (maj, min) < (3, 11),
                "golang" => (maj, min) < (1, 26),
                _ => false,
            };
            if eol {
                push_d(out, "CAM641", Severity::High, "Desteği bitmiş çalışma ortamı (EOL)", WHY_EOL,
                    f, format!("İmaj: {img}"),
                    Fix::Manual("İmajı desteklenen bir sürüme yükseltin (PHP ≥ 8.2, Node.js ≥ 22, Python ≥ 3.11, Go ≥ 1.26) ve testleri çalıştırın.".into()));
            }
        }
    }

    // --- Proje dosyalarındaki çalışma ortamı sürümü ---
    for m in p.manifests.iter().chain(find_files(root, 3, &|n, _| matches!(n, "composer.json" | ".nvmrc" | ".node-version" | ".python-version")).iter()) {
        let n = file_name(m);
        let t = read(m);
        let found = match n {
            "composer.json" => serde_json::from_str::<Value>(&t).ok()
                .and_then(|v| v.pointer("/require/php").and_then(Value::as_str).map(String::from))
                .and_then(|c| major_minor(&c).map(|v| ("PHP", v, v < (8, 2), c))),
            "package.json" => serde_json::from_str::<Value>(&t).ok()
                .and_then(|v| v.pointer("/engines/node").and_then(Value::as_str).map(String::from))
                .and_then(|c| major_minor(&c).map(|v| ("Node.js", v, v.0 < 22 && !c.contains(">="), c))),
            ".nvmrc" | ".node-version" => major_minor(t.trim()).map(|v| ("Node.js", v, v.0 < 22, t.trim().to_string())),
            ".python-version" => major_minor(t.trim()).map(|v| ("Python", v, v < (3, 11), t.trim().to_string())),
            "go.mod" => re(r"(?m)^go\s+(\d+\.\d+)").captures(&t).and_then(|c| major_minor(&c[1]).map(|v| ("Go", v, v < (1, 26), c[1].to_string()))),
            _ => None,
        };
        if let Some((rt, _, true, spec)) = found {
            push_d(out, "CAM641", Severity::High, "Desteği bitmiş çalışma ortamı (EOL)", WHY_EOL,
                m, format!("{rt} {spec}"),
                Fix::Manual(format!("{rt} sürümünü desteklenen bir sürüme yükseltin (PHP ≥ 8.2, Node.js ≥ 22, Python ≥ 3.11, Go ≥ 1.26) ve testleri çalıştırın.")));
        }
    }
}

/// `anahtar = değer`: varsa (yorumlu da olsa) ilk satırı değiştir, yoksa sona ekle.
fn ini_set(text: &str, key: &str, value: &str) -> String {
    let line_re = re(&format!(r"(?mi)^\s*;?\s*{}\s*=.*$", regex::escape(key)));
    let new_line = format!("{key} = {value}");
    // Önce yorumsuz satırı tercih et
    let active = re(&format!(r"(?mi)^\s*{}\s*=.*$", regex::escape(key)));
    if let Some(m) = active.find(text).or_else(|| line_re.find(text)) {
        return format!("{}{}{}", &text[..m.start()], new_line, &text[m.end()..]);
    }
    let mut t = text.to_string();
    if !t.is_empty() && !t.ends_with('\n') {
        t.push('\n');
    }
    t.push_str(&new_line);
    t.push('\n');
    t
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
            Fix::IniSet { path, key, value } => {
                if dry_run {
                    report.dry_run_notes.push((path.clone(), format!("{} içinde `{key} = {value}` yapılacak", path.display())));
                } else {
                    let text = tokio::fs::read_to_string(path).await.map_err(|e| Error::io(path, e))?;
                    tokio::fs::write(path, ini_set(&text, key, value)).await.map_err(|e| Error::io(path, e))?;
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
        assert_eq!(ids, vec!["CAM201", "CAM203", "CAM503"]);
        // Şablon kendi denetimimizden geçmeli
        t.write("next.config.mjs", NEXT_CONFIG_TEMPLATE);
        let ids = t.audit(&["app/actions.ts", "next.config.mjs"], &["package.json"]);
        assert_eq!(ids, vec!["CAM203", "CAM503"]);
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

    #[test]
    fn unlocked_doors_are_found() {
        let t = TempProject::new("locks");
        t.write("server.js", "const app = express();\napp.get('/admin/users', listUsers);\napp.delete('/api/users/:id', requireAuth, del);\napp.get('/health', ok);\n");
        t.write("admin/delete.php", "<?php\n$db->query('DELETE FROM posts WHERE id=' . intval($_GET['id']));\n");
        t.write("remove.php", "<?php\n$db->query('DELETE FROM posts WHERE id=' . intval($_POST['id']));\n");
        t.write("safe.php", "<?php\nrequire 'auth.php';\n$db->query('DELETE FROM posts WHERE id=' . intval($_POST['id']));\n");
        t.write("views.py", "@app.route('/admin/stats')\ndef stats():\n    return 'x'\n");
        let s: Vec<(PathBuf, Lang)> = ["server.js", "admin/delete.php", "remove.php", "safe.php", "views.py"]
            .iter()
            .map(|r| { let p = t.root.join(r); let l = Lang::from_path(&p).unwrap(); (p, l) })
            .collect();
        let found = audit(&Project { root: &t.root, sources: &s, manifests: &[] });
        let lock = |id: &str| found.iter().filter(|f| f.id == id).collect::<Vec<_>>();
        assert_eq!(lock("CAM501").len(), 1);
        assert_eq!(lock("CAM501")[0].detail, "Kilitsiz: GET /admin/users", "korumalı /api/users/:id listelenmemeli");
        assert_eq!(lock("CAM504").len(), 1);
        assert_eq!(lock("CAM505").len(), 1, "safe.php auth içeriyor, remove.php içermiyor");
        assert_eq!(lock("CAM506").len(), 1);
        // Global kimlik doğrulama varsa kilit tamam
        t.write("server.js", "const app = express();\napp.use(requireAuth);\napp.get('/admin/users', listUsers);\n");
        assert!(audit(&Project { root: &t.root, sources: &s, manifests: &[] }).iter().all(|f| f.id != "CAM501"));
    }

    #[test]
    fn server_configs_are_checked() {
        let t = TempProject::new("srv");
        t.write("deploy/nginx/site.conf", "server {\n  listen 80;\n  autoindex on;\n  ssl_protocols TLSv1 TLSv1.2;\n}\n");
        t.write("php.ini", "[PHP]\nexpose_php = On\ndisplay_errors = On\n;allow_url_include = Off\n");
        t.write("Dockerfile", "FROM node:18\nENV API_KEY=abc123\nCMD node app.js\n");
        t.write(".htaccess", "Options +Indexes\n");
        let ids = t.audit(&[], &[]);
        for want in ["CAM601", "CAM602", "CAM603", "CAM604", "CAM605", "CAM611", "CAM621", "CAM622", "CAM631", "CAM633", "CAM641"] {
            assert!(ids.contains(&want), "{want} yok: {ids:?}");
        }
        assert!(!ids.contains(&"CAM623") && !ids.contains(&"CAM632"), "{ids:?}");
        // Sertleştirilmiş yapılandırma sessiz
        t.write("deploy/nginx/site.conf", "server {\n  listen 443 ssl;\n  server_tokens off;\n  ssl_protocols TLSv1.2 TLSv1.3;\n  add_header X-Frame-Options DENY always;\n}\n");
        t.write("Dockerfile", "FROM node:22-alpine\nUSER node\nCMD node app.js\n");
        t.write(".htaccess", "Options -Indexes\n");
        let ids = t.audit(&[], &[]);
        assert!(ids.iter().all(|i| !i.starts_with("CAM60") && !i.starts_with("CAM61") && !i.starts_with("CAM63") && *i != "CAM641"), "{ids:?}");
    }

    #[test]
    fn ini_values_are_set() {
        assert_eq!(ini_set("[PHP]\nexpose_php = On\n", "expose_php", "Off"), "[PHP]\nexpose_php = Off\n");
        assert_eq!(ini_set(";display_errors = On\n", "display_errors", "Off"), "display_errors = Off\n");
        assert_eq!(ini_set("a = 1", "b", "2"), "a = 1\nb = 2\n");
    }

    #[test]
    fn python_and_go_cameras() {
        let t = TempProject::new("pygo");
        t.write("app.py", "from flask import Flask\napp = Flask(__name__)\n@app.route('/login', methods=['POST'])\ndef login():\n    pass\n");
        t.write("proj/settings.py", "INSTALLED_APPS = []\nMIDDLEWARE = ['django.middleware.common.CommonMiddleware']\n");
        t.write("main.go", "package main\nfunc main() {\n\thttp.HandleFunc(\"/\", h)\n\thttp.ListenAndServe(\":8080\", nil)\n}\n");
        assert_eq!(t.audit(&["app.py", "proj/settings.py", "main.go"], &[]), vec!["CAM110", "CAM111", "CAM112", "CAM113", "CAM120"]);
    }
}
