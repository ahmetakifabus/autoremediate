//! 6) Hırsızın gözü: yayındaki siteye DIŞARIDAN bakış
//!
//! Saldırgan önce binaya dışarıdan bakar: kapı (HTTPS) kilitli mi, pencereler
//! (güvenlik başlıkları) açık mı, kapıda hangi marka kilit olduğu yazıyor mu
//! (sürüm ifşası), arka bahçede unutulmuş anahtar (.env, .git, yedek) var mı?
//!
//! Bu modül yalnızca birkaç sıradan GET isteği gönderir (saldırı yükü yok,
//! form göndermez, giriş denemez), istekler arasında bekler ve yalnızca aynı
//! sunucudaki yönlendirmeleri izler. YALNIZCA sahibi olduğunuz veya test
//! izniniz olan siteler için kullanın.

use std::time::Duration;

use regex::Regex;
use reqwest::header::HeaderMap;
use reqwest::{redirect, Url};
use serde::Serialize;
use tracing::info;

use crate::error::{Error, Result};
use crate::scanner::Severity;
use crate::util::truncate_chars;

#[derive(Debug, Clone, Serialize)]
pub struct SiteFinding {
    pub id: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    pub detail: String,
    /// Kodda hangi "kamera" bunu kapatır?
    pub remedy: &'static str,
}

const MAX_BODY: usize = 256 * 1024;
const PAUSE: Duration = Duration::from_millis(300);

struct Probe {
    path: &'static str,
    id: &'static str,
    severity: Severity,
    title: &'static str,
    /// Gövde bu desene uyarsa gerçekten açıkta demektir (SPA "her yola 200" yanıtlarını eler)
    proof: &'static str,
    remedy: &'static str,
}

const PROBES: &[Probe] = &[
    Probe { path: "/.git/HEAD", id: "WEB201", severity: Severity::Critical,
        title: "Git deposu indirilebilir (/.git)", proof: r"^ref: refs/|^[0-9a-f]{40}\s*$",
        remedy: ".git klasörünü web kökünden çıkarın; sunucuda gizli dosyalara erişimi engelleyin." },
    Probe { path: "/.env", id: "WEB202", severity: Severity::Critical,
        title: "Gizli anahtar dosyası (.env) indirilebilir", proof: r"(?m)^[A-Z][A-Z0-9_]{2,}=",
        remedy: ".env dosyasını web kökünden çıkarın ve içindeki TÜM anahtarları yenileyin." },
    Probe { path: "/.env.local", id: "WEB202", severity: Severity::Critical,
        title: "Gizli anahtar dosyası (.env.local) indirilebilir", proof: r"(?m)^[A-Z][A-Z0-9_]{2,}=",
        remedy: ".env dosyasını web kökünden çıkarın ve içindeki TÜM anahtarları yenileyin." },
    Probe { path: "/.env.production", id: "WEB202", severity: Severity::Critical,
        title: "Gizli anahtar dosyası (.env.production) indirilebilir", proof: r"(?m)^[A-Z][A-Z0-9_]{2,}=",
        remedy: ".env dosyasını web kökünden çıkarın ve içindeki TÜM anahtarları yenileyin." },
    Probe { path: "/.htpasswd", id: "WEB203", severity: Severity::Critical,
        title: "Parola dosyası (.htpasswd) indirilebilir", proof: r"(?m)^[^:\s]+:(\$apr1\$|\$2[aby]\$|\{SHA\})",
        remedy: ".htpasswd dosyasını web kökü dışına taşıyın ve parolaları değiştirin." },
    Probe { path: "/backup.sql", id: "WEB204", severity: Severity::Critical,
        title: "Veritabanı yedeği indirilebilir (backup.sql)", proof: r"(?i)CREATE TABLE|INSERT INTO",
        remedy: "Yedekleri web kökünde tutmayın; bu dosyayı hemen kaldırın." },
    Probe { path: "/database.sql", id: "WEB204", severity: Severity::Critical,
        title: "Veritabanı yedeği indirilebilir (database.sql)", proof: r"(?i)CREATE TABLE|INSERT INTO",
        remedy: "Yedekleri web kökünde tutmayın; bu dosyayı hemen kaldırın." },
    Probe { path: "/phpinfo.php", id: "WEB205", severity: Severity::Medium,
        title: "phpinfo() sayfası açık", proof: r"PHP Version|phpinfo\(\)",
        remedy: "phpinfo dosyasını silin: sunucu yolları, modüller ve sürümleri hırsıza haritalar." },
    Probe { path: "/info.php", id: "WEB205", severity: Severity::Medium,
        title: "phpinfo() sayfası açık (info.php)", proof: r"PHP Version|phpinfo\(\)",
        remedy: "phpinfo dosyasını silin: sunucu yolları, modüller ve sürümleri hırsıza haritalar." },
    Probe { path: "/server-status", id: "WEB206", severity: Severity::Medium,
        title: "Apache server-status açık", proof: r"Apache Server Status",
        remedy: "mod_status'u kapatın ya da yalnızca 127.0.0.1'e açın." },
    Probe { path: "/.DS_Store", id: "WEB207", severity: Severity::Low,
        title: ".DS_Store dosyası açık (klasör içeriğini sızdırır)", proof: r"Bud1",
        remedy: ".DS_Store dosyalarını sunucudan silin ve dağıtıma eklemeyin." },
];

fn re(p: &str) -> Result<Regex> {
    Regex::new(p).map_err(|e| Error::Config(format!("geçersiz desen {p:?}: {e}")))
}

fn header<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

fn client(same_host_only: Option<String>) -> Result<reqwest::Client> {
    let policy = match same_host_only {
        // Sadece aynı sunucu içinde, en fazla 5 yönlendirme izle
        Some(host) => redirect::Policy::custom(move |a| {
            if a.previous().len() >= 5 || a.url().host_str() != Some(host.as_str()) {
                a.stop()
            } else {
                a.follow()
            }
        }),
        None => redirect::Policy::none(),
    };
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(policy)
        .user_agent(concat!("autoremediate/", env!("CARGO_PKG_VERSION"), " (guvenlik denetimi)"))
        .build()?)
}

async fn body_prefix(resp: reqwest::Response) -> String {
    match resp.bytes().await {
        Ok(b) => String::from_utf8_lossy(&b[..b.len().min(MAX_BODY)]).into_owned(),
        Err(_) => String::new(),
    }
}

/// Başlıkları ve çerezleri inceler (ağ erişimi yok; test edilebilir).
pub(crate) fn check_headers(h: &HeaderMap, https: bool, body: &str) -> Vec<SiteFinding> {
    let mut out = Vec::new();
    let mut add = |id, severity, title, detail: String, remedy| out.push(SiteFinding { id, severity, title, detail, remedy });
    let csp = header(h, "content-security-policy").unwrap_or("");

    if https && header(h, "strict-transport-security").is_none() {
        add("WEB101", Severity::Medium, "HSTS yok (Strict-Transport-Security)",
            "Tarayıcıya 'bu siteye hep HTTPS ile gel' denmiyor; ilk bağlantı şifresiz yakalanabilir.".into(),
            "Express: helmet() | Next.js: next.config headers() | PHP: header('Strict-Transport-Security: ...')");
    }
    if csp.is_empty() {
        add("WEB102", Severity::Medium, "İçerik Güvenlik Politikası (CSP) yok",
            "Bir XSS açığı bulunursa saldırganın betiği hiçbir engelle karşılaşmadan çalışır.".into(),
            "Express: helmet() | Next.js: Content-Security-Policy başlığı | PHP: header('Content-Security-Policy: ...')");
    }
    if header(h, "x-frame-options").is_none() && !csp.contains("frame-ancestors") {
        add("WEB103", Severity::Medium, "Clickjacking koruması yok",
            "Site görünmez bir çerçeveye konup kullanıcıya fark ettirmeden tıklatılabilir.".into(),
            "X-Frame-Options: DENY veya CSP frame-ancestors 'none'");
    }
    if !header(h, "x-content-type-options").is_some_and(|v| v.eq_ignore_ascii_case("nosniff")) {
        add("WEB104", Severity::Low, "X-Content-Type-Options: nosniff yok",
            "Tarayıcı yüklenen bir dosyayı betik sanıp çalıştırabilir.".into(), "X-Content-Type-Options: nosniff");
    }
    if header(h, "referrer-policy").is_none() {
        add("WEB105", Severity::Low, "Referrer-Policy yok",
            "Adres çubuğundaki gizli bilgiler (token içeren linkler) başka sitelere sızabilir.".into(),
            "Referrer-Policy: strict-origin-when-cross-origin");
    }
    if let Some(s) = header(h, "server").filter(|s| s.chars().any(|c| c.is_ascii_digit())) {
        add("WEB106", Severity::Low, "Sunucu sürümünü ilan ediyor",
            format!("Server: {s} — hırsız hangi bilinen açığı deneyeceğini bilir."),
            "Apache: ServerTokens Prod | Nginx: server_tokens off");
    }
    if let Some(p) = header(h, "x-powered-by") {
        add("WEB107", Severity::Low, "Teknoloji ifşası (X-Powered-By)",
            format!("X-Powered-By: {p} — kapıda kilit markası yazıyor."),
            "Express: helmet() | Next.js: poweredByHeader: false | PHP: expose_php = Off");
    }
    if header(h, "access-control-allow-origin") == Some("*")
        && header(h, "access-control-allow-credentials").is_some_and(|v| v.eq_ignore_ascii_case("true"))
    {
        add("WEB108", Severity::High, "CORS her siteye kimlik bilgisiyle açık",
            "Access-Control-Allow-Origin: * + Allow-Credentials: true".into(), "İzin verilen kökenleri açıkça listeleyin.");
    }
    for c in h.get_all("set-cookie").iter().filter_map(|v| v.to_str().ok()) {
        let name = c.split('=').next().unwrap_or("?").trim();
        let lower = c.to_ascii_lowercase();
        let mut missing = Vec::new();
        if https && !lower.contains("secure") {
            missing.push("Secure");
        }
        if !lower.contains("httponly") {
            missing.push("HttpOnly");
        }
        if !lower.contains("samesite") {
            missing.push("SameSite");
        }
        if !missing.is_empty() {
            add("WEB109", Severity::Medium, "Çerez koruma bayrakları eksik",
                format!("'{name}' çerezinde eksik: {}", missing.join(", ")),
                "Express: cookie { httpOnly, secure, sameSite } | PHP: session_set_cookie_params([...])");
        }
    }
    if body.contains("<title>Index of /") || body.contains("<h1>Index of /") {
        add("WEB110", Severity::Medium, "Dizin listeleme açık",
            "Sunucu klasör içeriğini listeliyor; unutulmuş yedekler ve dosyalar görünür.".into(),
            "Apache: Options -Indexes | Nginx: autoindex off");
    }
    out
}

/// Kullanılan teknolojiyi tahmin eder (bilgi amaçlı).
pub(crate) fn fingerprint(h: &HeaderMap, body: &str) -> Vec<&'static str> {
    let powered = header(h, "x-powered-by").unwrap_or("").to_ascii_lowercase();
    let mut out = Vec::new();
    if powered.contains("next.js") || body.contains("/_next/static/") {
        out.push("Next.js");
    }
    if powered.contains("php") || h.get_all("set-cookie").iter().any(|c| c.to_str().is_ok_and(|s| s.starts_with("PHPSESSID"))) {
        out.push("PHP");
    }
    if powered.contains("express") {
        out.push("Express");
    }
    out
}

pub struct SiteReport {
    pub url: String,
    pub tech: Vec<&'static str>,
    pub findings: Vec<SiteFinding>,
}

pub async fn inspect(raw_url: &str) -> Result<SiteReport> {
    let url = Url::parse(raw_url).map_err(|e| Error::Config(format!("geçersiz --site adresi {raw_url:?}: {e}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(Error::Config("--site yalnızca http:// veya https:// adresi kabul eder".into()));
    }
    let host = url.host_str().ok_or_else(|| Error::Config("--site adresinde sunucu adı yok".into()))?.to_string();
    let follow = client(Some(host.clone()))?;
    let no_follow = client(None)?;
    let mut findings = Vec::new();

    info!("Hırsızın gözüyle bakılıyor: {url}");
    let resp = match follow.get(url.clone()).send().await {
        Ok(r) => r,
        Err(e) if url.scheme() == "https" && (e.is_connect() || e.is_request()) => {
            findings.push(SiteFinding {
                id: "WEB001", severity: Severity::High, title: "HTTPS bağlantısı kurulamadı / sertifika geçersiz",
                detail: truncate_chars(&e.to_string(), 200),
                remedy: "Geçerli bir TLS sertifikası kurun (ör. Let's Encrypt).",
            });
            return Ok(SiteReport { url: url.to_string(), tech: vec![], findings });
        }
        Err(e) => return Err(Error::Http(e)),
    };
    let final_https = resp.url().scheme() == "https";
    let headers = resp.headers().clone();
    let body = body_prefix(resp).await;

    if !final_https {
        findings.push(SiteFinding {
            id: "WEB002", severity: Severity::High, title: "Site HTTPS kullanmıyor",
            detail: format!("{url} şifresiz HTTP ile sunuluyor; parolalar ve çerezler yolda okunabilir."),
            remedy: "TLS sertifikası kurup tüm HTTP isteklerini HTTPS'e yönlendirin.",
        });
    } else if url.scheme() == "https" {
        // HTTP sürümü HTTPS'e yönlendiriyor mu?
        let mut http_url = url.clone();
        let _ = http_url.set_scheme("http");
        tokio::time::sleep(PAUSE).await;
        if let Ok(r) = no_follow.get(http_url.clone()).send().await {
            let to_https = header(r.headers(), "location").is_some_and(|l| l.starts_with("https://"));
            if r.status().is_success() && !to_https {
                findings.push(SiteFinding {
                    id: "WEB003", severity: Severity::Medium, title: "HTTP sürümü HTTPS'e yönlendirmiyor",
                    detail: format!("{http_url} şifresiz olarak da açılıyor."),
                    remedy: "Tüm HTTP isteklerini 301 ile HTTPS'e yönlendirin ve HSTS ekleyin.",
                });
            }
        }
    }
    findings.extend(check_headers(&headers, final_https, &body));
    let tech = fingerprint(&headers, &body);

    // Arka bahçede unutulmuş anahtarlar
    for probe in PROBES {
        tokio::time::sleep(PAUSE).await;
        let Ok(target) = url.join(probe.path) else { continue };
        let Ok(r) = no_follow.get(target.clone()).send().await else { continue };
        if !r.status().is_success() {
            continue;
        }
        let ctype = header(r.headers(), "content-type").unwrap_or("").to_ascii_lowercase();
        let text = body_prefix(r).await;
        // HTML hata/SPA sayfaları kanıt sayılmaz (phpinfo/server-status hariç: onlar HTML'dir)
        let html_ok = matches!(probe.id, "WEB205" | "WEB206");
        if ctype.contains("text/html") && !html_ok {
            continue;
        }
        if re(probe.proof)?.is_match(&text) {
            findings.push(SiteFinding {
                id: probe.id, severity: probe.severity, title: probe.title,
                detail: format!("{target} herkese açık"), remedy: probe.remedy,
            });
        }
    }
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(b.id)));
    Ok(SiteReport { url: url.to_string(), tech, findings })
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderName, HeaderValue};

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_str(v).unwrap());
        }
        h
    }

    fn ids(f: &[SiteFinding]) -> Vec<&'static str> {
        let mut v: Vec<_> = f.iter().map(|x| x.id).collect();
        v.sort();
        v
    }

    #[test]
    fn bare_site_shows_open_windows() {
        let h = headers(&[("server", "Apache/2.4.41 (Ubuntu)"), ("x-powered-by", "PHP/7.4.3"), ("set-cookie", "PHPSESSID=abc; path=/")]);
        assert_eq!(
            ids(&check_headers(&h, true, "")),
            vec!["WEB101", "WEB102", "WEB103", "WEB104", "WEB105", "WEB106", "WEB107", "WEB109"]
        );
        assert_eq!(fingerprint(&h, ""), vec!["PHP"]);
    }

    #[test]
    fn hardened_site_is_quiet() {
        let h = headers(&[
            ("strict-transport-security", "max-age=63072000"),
            ("content-security-policy", "default-src 'self'; frame-ancestors 'none'"),
            ("x-content-type-options", "nosniff"),
            ("referrer-policy", "strict-origin-when-cross-origin"),
            ("server", "nginx"),
            ("set-cookie", "sid=1; Path=/; Secure; HttpOnly; SameSite=Lax"),
        ]);
        assert!(check_headers(&h, true, "<html></html>").is_empty());
    }

    #[test]
    fn probe_patterns_compile_and_match() {
        let git = PROBES.iter().find(|p| p.path == "/.git/HEAD").unwrap();
        assert!(re(git.proof).unwrap().is_match("ref: refs/heads/master\n"));
        assert!(!re(git.proof).unwrap().is_match("<!doctype html>"));
        let env = PROBES.iter().find(|p| p.path == "/.env").unwrap();
        assert!(re(env.proof).unwrap().is_match("APP_KEY=base64:xyz\n"));
        for p in PROBES {
            re(p.proof).unwrap();
        }
    }
}
