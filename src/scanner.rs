//! 1) Tarama ve Analiz Modülü — çok dilli (Rust / PHP / JavaScript-TypeScript)
//!
//! Kural tabanlı SAST çekirdeği:
//!  * Her kural bir dil kümesine, bir regex desenine ve isteğe bağlı olarak
//!    bir "güvenli kalıp" (`unless`) desenine sahiptir.
//!  * `tainted()` kurallar yalnızca kullanıcı girdisinin ulaştığı satırlarda
//!    tetiklenir. Girdi, dosya içinde basit bir veri akışı (atama zinciri)
//!    analiziyle izlenir: `$c = $_GET['c']; system($c);` yakalanır.
//!  * Aynı `group` içindeki kurallardan satır başına yalnızca İLKİ (en özgül /
//!    en ağır olanı) raporlanır; böylece aynı açık iki kez sayılmaz.
//!  * Her kural, doğru bir düzeltmenin deseni ortadan kaldırabileceği şekilde
//!    yazılmıştır (aksi halde onarım döngüsü hiç yakınsamaz).
//!  * `autoremediate-ignore[KURAL]: gerekçe` yorumu (aynı ya da önceki satırda)
//!    bulguyu bastırır; bastırılan bulgular ayrıca raporlanır.

use std::collections::HashSet;
use std::fmt;
use std::path::Path;

use regex::Regex;
use serde::Serialize;

use crate::error::{Error, Result};
use crate::util::truncate_chars;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        })
    }
}

impl Severity {
    /// OSV / GitHub Advisory önem derecesi metnini çevirir.
    pub fn from_label(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "CRITICAL" => Some(Severity::Critical),
            "HIGH" => Some(Severity::High),
            "MODERATE" | "MEDIUM" => Some(Severity::Medium),
            "LOW" => Some(Severity::Low),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    Rust,
    Php,
    Js,
    Python,
    Go,
}

impl Lang {
    pub fn from_path(path: &Path) -> Option<Self> {
        let name = path.file_name()?.to_str()?.to_ascii_lowercase();
        // Derlenmiş paketler ve tip bildirimleri kaynak kod değildir.
        if name.ends_with(".min.js") || name.ends_with(".d.ts") || name.ends_with(".bundle.js") {
            return None;
        }
        match name.rsplit_once('.')?.1 {
            "rs" => Some(Lang::Rust),
            "php" | "phtml" | "php3" | "php4" | "php5" | "php7" | "phps" => Some(Lang::Php),
            "js" | "mjs" | "cjs" | "jsx" | "ts" | "mts" | "cts" | "tsx" => Some(Lang::Js),
            "py" | "pyw" => Some(Lang::Python),
            "go" => Some(Lang::Go),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Lang::Rust => "Rust",
            Lang::Php => "PHP",
            Lang::Js => "JavaScript/TypeScript",
            Lang::Python => "Python",
            Lang::Go => "Go",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub rule_id: &'static str,
    pub severity: Severity,
    /// 1 tabanlı satır numarası
    pub line: usize,
    /// LLM'e gönderilecek satır özeti (gizli bilgiler maskelenir)
    pub snippet: String,
    pub description: &'static str,
}

#[derive(Debug, Default)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    /// `autoremediate-ignore` yorumu ile bastırılmış bulgular (insan incelemesi gerekir)
    pub suppressed: Vec<Finding>,
}

// ---- Kural tanımları ------------------------------------------------------

struct RuleDef {
    id: &'static str,
    severity: Severity,
    langs: &'static [Lang],
    description: &'static str,
    pattern: &'static str,
    /// Satır bu deseni de içeriyorsa kural tetiklenmez (güvenli kullanım)
    unless: Option<&'static str>,
    /// Yalnızca kullanıcı girdisi taşıyan satırlarda tetiklenir
    needs_taint: bool,
    /// Aynı gruptan satır başına tek bulgu
    group: Option<&'static str>,
    /// true ise eşleşen satır LLM'e/loglara maskeli gider
    redact: bool,
}

const fn rule(
    id: &'static str,
    severity: Severity,
    langs: &'static [Lang],
    description: &'static str,
    pattern: &'static str,
) -> RuleDef {
    RuleDef { id, severity, langs, description, pattern, unless: None, needs_taint: false, group: None, redact: false }
}

impl RuleDef {
    const fn tainted(mut self) -> Self {
        self.needs_taint = true;
        self
    }
    const fn unless(mut self, p: &'static str) -> Self {
        self.unless = Some(p);
        self
    }
    const fn group(mut self, g: &'static str) -> Self {
        self.group = Some(g);
        self
    }
    const fn redacted(mut self) -> Self {
        self.redact = true;
        self
    }
}

use Severity::{Critical, High, Low, Medium};

const RS: &[Lang] = &[Lang::Rust];
const PHP: &[Lang] = &[Lang::Php];
const JS: &[Lang] = &[Lang::Js];
const PY: &[Lang] = &[Lang::Python];
const GO: &[Lang] = &[Lang::Go];
const ALL: &[Lang] = &[Lang::Rust, Lang::Php, Lang::Js, Lang::Python, Lang::Go];

// Node.js child_process çağrıları (`regex.exec(` gibi metotları dışlar)
const JS_EXEC_FN: &str = r"(^|[^\w.$])(exec|execSync|spawn|spawnSync|execFile|execFileSync|execa|execaSync|execaCommand)\s*\(|\b(cp|childProcess|child_process|proc)\.(exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(";
const JS_HTML_SINK: &str = r"dangerouslySetInnerHTML|\.(innerHTML|outerHTML)\s*=[^=]|\bdocument\.write(ln)?\s*\(|\.insertAdjacentHTML\s*\(";
const JS_HTML_SAFE: &str = r"(?i)DOMPurify|sanitize|escapeHtml|\bescape\(";

const RULES: &[RuleDef] = &[
    // ===================== Ortak (tüm diller) ==============================
    rule("SEC009", Critical, ALL,
        "Kaynak kodda bilinen biçimde gizli anahtar (özel anahtar / AWS / GitHub / Stripe / Slack)",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{36}\b|\bsk_live_[0-9A-Za-z]{20,}|\bxox[baprs]-[0-9A-Za-z-]{10,}")
        .group("secret").redacted(),
    rule("SEC001", Critical, ALL,
        "Kaynak kodda sabit gizli bilgi (secret/token/parola)",
        r##"(?i)(api[_-]?key|secret|passw(or)?d|token|auth[_-]?key)\w*["']?\s*(=>|[:=,])\s*["'][^"'\s]{8,}["']"##)
        .group("secret").redacted(),
    rule("SEC008", Low, ALL,
        "Şifresiz HTTP URL'si (https kullanılmalı)",
        r##"["'`]http://[^"'`\s]+"##)
        .unless(r"http://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|www\.w3\.org|schemas\.|ns\.adobe|purl\.org|xmlns)"),

    // ===================== Rust ============================================
    rule("SEC002", High, RS, "Kabuk üzerinden komut çalıştırma (komut enjeksiyonu riski)",
        r##"Command::new\(\s*"(sh|bash|cmd|cmd\.exe|powershell|pwsh)""##),
    rule("SEC003", High, RS, "SQL sorgusu format! ile oluşturuluyor (SQL enjeksiyonu)",
        r##"(?i)format!\(\s*"\s*(select|insert|update|delete)\b"##),
    rule("SEC004", High, RS, "TLS sertifika/hostname doğrulaması kapatılmış",
        r"danger_accept_invalid_(certs|hostnames)\(\s*true\s*\)"),
    rule("SEC005", Medium, RS, "unsafe blok/fonksiyon: bellek güvenliği garantisi devre dışı",
        r"\bunsafe\s*(\{|fn\b|impl\b)"),
    rule("SEC006", Medium, RS, "mem::transmute kullanımı (tip/bellek güvenliği riski)",
        r"\btransmute\s*(::<|\()"),
    rule("SEC007", Medium, RS, "Kriptografik olarak zayıf özet algoritması (MD5/SHA-1)",
        r"(?i)\b(md5|sha1)::"),

    // ===================== PHP =============================================
    // --- Web shell / dinamik çağrı
    rule("PHP001", Critical, PHP,
        "Kullanıcı girdisi fonksiyon adı olarak çağrılıyor (tek satırlık web shell imzası)",
        r"\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[[^\]]*\]\s*\(")
        .group("php-dyncall"),
    rule("PHP002", Critical, PHP,
        "Kullanıcı kontrollü dinamik fonksiyon çağrısı (call_user_func / $f(...)) → RCE",
        r"(^|[^\w>:$])\$\w+\s*\(|\bcall_user_func(_array)?\s*\(|\b(array_map|register_shutdown_function|forward_static_call)\s*\(\s*\$")
        .tainted().group("php-dyncall"),
    // --- Kod çalıştırma
    rule("PHP003", Critical, PHP,
        "eval/assert içinde gizlenmiş yük (base64/gzinflate) — web shell imzası",
        r"\b(eval|assert)\s*\(\s*@?\s*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|convert_uudecode)")
        .group("php-eval"),
    rule("PHP004", Critical, PHP,
        "Kullanıcı girdisi kod olarak çalıştırılıyor (eval/assert/create_function → RCE)",
        r"\b(eval|assert|create_function)\s*\(")
        .tainted().group("php-eval"),
    rule("PHP005", High, PHP, "eval/create_function kullanımı (kod enjeksiyonu riski)",
        r"\b(eval|create_function)\s*\(")
        .group("php-eval"),
    rule("PHP006", Critical, PHP, "preg_replace /e değiştiricisi (değiştirme metni kod olarak çalışır)",
        r##"preg_replace\s*\(\s*['"][#/~!@%|][^'"]*[#/~!@%|][imsxuADSUXJ]*e[imsxuADSUXJ]*['"]"##),
    // --- Komut enjeksiyonu
    rule("PHP010", Critical, PHP,
        "Kullanıcı girdisi işletim sistemi komutuna ulaşıyor (komut enjeksiyonu / RCE)",
        r"(^|[^\w>:$])(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(|`[^`]*\$[^`]*`")
        .tainted().unless(r"escapeshellarg\s*\(").group("php-exec"),
    rule("PHP011", High, PHP, "Değişken içeren kabuk komutu (escapeshellarg yok)",
        r"(^|[^\w>:$])(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\([^)]*\$|`[^`]*\$[^`]*`")
        .unless(r"escapeshellarg\s*\(").group("php-exec"),
    // --- Nesne enjeksiyonu
    rule("PHP020", Critical, PHP,
        "Kullanıcı girdisi unserialize ediliyor (PHP nesne enjeksiyonu / POP zinciri → RCE)",
        r"\bunserialize\s*\(")
        .tainted().unless(r##"allowed_classes['"]?\s*=>\s*false"##).group("php-deser"),
    rule("PHP021", Medium, PHP, "unserialize allowed_classes kısıtı olmadan kullanılıyor",
        r"\bunserialize\s*\(")
        .unless(r##"allowed_classes['"]?\s*=>\s*false"##).group("php-deser"),
    // --- Dosya dahil etme
    rule("PHP030", Critical, PHP,
        "Kullanıcı kontrollü include/require (LFI/RFI → RCE)",
        r"\b(include|require)(_once)?\b\s*\(?\s*[^;]*\$")
        .tainted(),
    rule("PHP031", High, PHP, "allow_url_include açılıyor (uzaktan dosya dahil etme)",
        r##"ini_set\s*\(\s*['"]allow_url_(include|fopen)['"]\s*,\s*['"]?(1|on|true)"##),
    // --- SQL
    rule("PHP040", Critical, PHP,
        "Kullanıcı girdisi SQL sorgusuna doğrudan giriyor (SQL enjeksiyonu)",
        r"\b(mysqli_query|mysql_query|mysqli_multi_query|pg_query|sqlite_query)\s*\(|->\s*(query|exec|multi_query|prepare|real_query)\s*\(")
        .tainted().group("php-sql"),
    rule("PHP041", High, PHP, "SQL sorgusu değişkenle birleştiriliyor (SQL enjeksiyonu)",
        r##"(?i)["']\s*(select\s.+?\sfrom|insert\s+into|update\s+\S+\s+set|delete\s+from|replace\s+into)\b[^;]*(["']\s*\.\s*\$|\{\$|\$\w+)"##)
        .group("php-sql"),
    // --- Dosya yükleme / dosya sistemi / SSRF
    rule("PHP050", High, PHP,
        "Yüklenen dosya istemcinin verdiği adla kaydediliyor (web shell yükleme riski)",
        r##"move_uploaded_file\s*\([^;]*\[\s*['"]name['"]\s*\]"##),
    rule("PHP060", High, PHP,
        "Kullanıcı kontrollü dosya yolu/içeriği (path traversal, web shell bırakma, phar://)",
        r"\b(file_put_contents|fopen|fwrite|copy|rename|unlink|readfile|fpassthru|show_source|highlight_file|file_exists|is_file|getimagesize)\s*\(")
        .tainted().unless(r"\bbasename\s*\(").group("php-file"),
    rule("PHP061", High, PHP,
        "Kullanıcı kontrollü URL/dosya okunuyor (SSRF / LFI)",
        r"\b(file_get_contents|file|curl_init|fsockopen|get_headers|simplexml_load_file)\s*\(|CURLOPT_URL")
        .tainted().unless(r"\bbasename\s*\(").group("php-file"),
    // --- XSS / değişken üzerine yazma / diğer
    rule("PHP070", High, PHP, "İstek parametresi kaçışsız HTML çıktısına yazılıyor (XSS)",
        r"(\b(echo|print)\b|<\?=)[^;]*\$_(GET|POST|REQUEST|COOKIE|SERVER)")
        .unless(r"htmlspecialchars|htmlentities|intval\s*\(|\(int\)|json_encode").group("php-xss"),
    rule("PHP071", Medium, PHP, "Kullanıcı girdisi kaçışsız HTML çıktısına yazılıyor (XSS)",
        r"\b(echo|print|printf)\b|<\?=")
        .tainted().unless(r"htmlspecialchars|htmlentities|intval\s*\(|\(int\)|json_encode").group("php-xss"),
    rule("PHP080", High, PHP, "extract() ile istek parametreleri değişkenlerin üzerine yazılıyor",
        r"\bextract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|FILES)"),
    rule("PHP081", Medium, PHP, "parse_str ikinci argüman olmadan (register_globals etkisi)",
        r"\bparse_str\s*\(\s*[^,()]+\)"),
    rule("PHP082", Medium, PHP, "Kullanıcı girdisi gevşek (==) karşılaştırılıyor (type juggling ile kimlik doğrulama atlatma)",
        r"\$_(GET|POST|REQUEST|COOKIE)\[[^\]]*\]\s*(==|!=)[^=]|[^=!]==\s*\$_(GET|POST|REQUEST|COOKIE)|\bstrcmp\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)"),
    rule("PHP083", Medium, PHP, "Parola MD5/SHA-1 ile özetleniyor (password_hash kullanılmalı)",
        r"(?i)\b(md5|sha1)\s*\(\s*\$\w*pass"),
    rule("PHP084", Low, PHP, "phpinfo() bilgi sızdırır", r"\bphpinfo\s*\("),

    // ===================== JavaScript / TypeScript =========================
    // --- Komut enjeksiyonu
    rule("JS001", Critical, JS,
        "Kullanıcı girdisi işletim sistemi komutuna ulaşıyor (komut enjeksiyonu / RCE)",
        JS_EXEC_FN)
        .tainted().unless(r##"(execFile|spawn)(Sync)?\s*\(\s*['"][^'"]+['"]\s*,\s*\["##).group("js-exec"),
    rule("JS002", High, JS, "Kabuk komutu dize birleştirme / şablon ile kuruluyor",
        r##"(^|[^\w.$])(exec|execSync)\s*\(\s*(`[^`]*\$\{|['"][^'"]*['"]\s*\+|\w+\s*\+)|\b(cp|childProcess|child_process)\.(exec|execSync)\s*\(\s*(`[^`]*\$\{|['"][^'"]*['"]\s*\+|\w+\s*\+)"##)
        .group("js-exec"),
    rule("JS003", High, JS, "spawn/execFile shell:true ile çalıştırılıyor (komut enjeksiyonu riski)",
        r"\bshell\s*:\s*true"),
    // --- Kod çalıştırma
    rule("JS010", Critical, JS,
        "Kullanıcı girdisi kod olarak çalıştırılıyor (eval/Function/vm → RCE)",
        r"(^|[^\w.$])eval\s*\(|\bnew\s+Function\s*\(|(^|[^\w.$])Function\s*\(|\bvm\d*\.(runInNewContext|runInThisContext|runInContext|compileFunction)\s*\(|\bnew\s+vm\.Script\s*\(")
        .tainted().group("js-eval"),
    rule("JS011", High, JS,
        "eval / new Function / node:vm / dize ile setTimeout (node:vm bir güvenlik sınırı değildir)",
        r##"(^|[^\w.$])eval\s*\(|\bnew\s+Function\s*\(|\bvm\d*\.(runInNewContext|runInThisContext|runInContext|compileFunction)\s*\(|\bnew\s+vm\.Script\s*\(|\bset(Timeout|Interval)\s*\(\s*['"`]"##)
        .group("js-eval"),
    rule("JS012", Critical, JS,
        "Kullanıcı kontrollü modül yükleme (dinamik require/import → RCE)",
        r##"\brequire\s*\(\s*[^'"`)\s]|\bimport\s*\(\s*[^'"`)\s]"##)
        .tainted(),
    // --- Serileştirme / prototip kirliliği
    rule("JS020", Critical, JS,
        "Fonksiyon serileştirebilen güvensiz kütüphane (node-serialize vb. → RCE)",
        r##"(require\s*\(|from)\s*['"](node-serialize|funcster|cryo|serialize-to-js)['"]|\bunserialize\s*\("##),
    rule("JS030", High, JS,
        "Kullanıcı girdisi derin birleştirmeye gidiyor (prototype pollution)",
        r"\b(_\.(merge|mergeWith|defaultsDeep|set|setWith|zipObjectDeep)|merge|deepmerge|deepMerge|extend|defaultsDeep|deepExtend|setValue|dset)\s*\(")
        .tainted().unless(r"__proto__|Object\.create\(null\)|structuredClone"),
    rule("JS031", High, JS,
        "Kullanıcı kontrollü anahtarlarla iç içe atama (prototype pollution gadget'ı)",
        r"\[[^\]]+\]\s*\[[^\]]+\]\s*=[^=]")
        .tainted().unless(r"__proto__|hasOwn|Object\.create\(null\)"),
    // --- SQL / NoSQL
    rule("JS040", Critical, JS,
        "Kullanıcı girdisi SQL sorgusuna doğrudan giriyor (SQL enjeksiyonu)",
        r"\.(query|execute|raw|unsafe|\$queryRawUnsafe|\$executeRawUnsafe|whereRaw|orderByRaw|havingRaw|joinRaw)\s*\(")
        .tainted().unless(r##"\.(query|execute)\s*\(\s*['"`][^'"`$]*['"`]\s*,\s*\["##).group("js-sql"),
    rule("JS041", High, JS, "SQL sorgusu dize birleştirme / şablonla kuruluyor (SQL enjeksiyonu)",
        r##"(?i)["'`]\s*(select\s.+?\sfrom|insert\s+into|update\s+\S+\s+set|delete\s+from|replace\s+into)\b[^;]*(\$\{|["']\s*\+\s*\w)|\$(queryRawUnsafe|executeRawUnsafe)\s*\("##)
        .group("js-sql"),
    rule("JS045", High, JS, "İstek verisi doğrudan MongoDB sorgusuna giriyor (NoSQL operatör enjeksiyonu)",
        r"\.(find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|countDocuments|aggregate)\s*\(\s*(req\.(body|query|params)|\{[^}]*:\s*req\.(body|query)\.\w+\s*\})|\$where")
        .unless(r"String\(|sanitize|mongo-sanitize"),
    // --- Dosya sistemi / SSRF
    rule("JS050", High, JS,
        "Kullanıcı kontrollü dosya yolu (path traversal / dosya yazarak web shell)",
        r"\b(fs|fsp|fse|promises)\.(readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|createReadStream|createWriteStream|unlink|unlinkSync|rm|rmSync|readdir|readdirSync|open|openSync|copyFile|rename|renameSync)\s*\(|(^|[^\w.$])(readFile|writeFile|createReadStream|createWriteStream)\s*\(|\bres\.(sendFile|download)\s*\(")
        .tainted().unless(r"\bbasename\s*\("),
    rule("JS060", High, JS,
        "Kullanıcı kontrollü URL'ye sunucu tarafı istek (SSRF)",
        r"(^|[^\w.$])fetch\s*\(|\baxios(\.(get|post|put|patch|delete|request|head))?\s*\(|\b(http|https)\.(get|request)\s*\(|\bgot(\.\w+)?\s*\(|\bundici\.(request|fetch)\s*\(|\bneedle\s*\(")
        .tainted(),
    // --- XSS / yönlendirme
    rule("JS070", High, JS, "Kullanıcı girdisi HTML olarak işleniyor (XSS)",
        JS_HTML_SINK)
        .tainted().unless(JS_HTML_SAFE).group("js-xss"),
    rule("JS071", Medium, JS, "Sanitize edilmeden HTML enjeksiyon noktası (XSS riski)",
        JS_HTML_SINK)
        .unless(JS_HTML_SAFE).group("js-xss"),
    rule("JS072", High, JS, "Kullanıcı girdisi yanıta HTML olarak yansıtılıyor (reflected XSS)",
        r##"\bres\.(send|write|end)\s*\(\s*(`[^`]*\$\{|['"][^'"]*<[^'"]*['"]\s*\+)"##)
        .tainted().unless(JS_HTML_SAFE),
    rule("JS080", Medium, JS, "Kullanıcı kontrollü yönlendirme (open redirect)",
        r"\bres\.redirect\s*\(|(^|[^\w.$])redirect\s*\(|\blocation\.(href|assign|replace)\s*(=[^=]|\()")
        .tainted().unless(r##"startsWith\(\s*['"]/['"]|new URL\("##),
    // --- Yapılandırma / kripto
    rule("JS090", High, JS, "TLS doğrulaması kapatılmış",
        r##"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED['"\]]*\s*=\s*['"]?0|strictSSL\s*:\s*false"##),
    rule("JS091", High, JS, "JWT doğrulaması zayıflatılmış ('none' algoritması / süre yok sayılıyor)",
        r##"algorithms\s*:\s*\[[^\]]*['"]none['"]|ignoreExpiration\s*:\s*true"##),
    rule("JS092", Medium, JS, "Kriptografik olarak zayıf özet algoritması (MD5/SHA-1)",
        r##"createHash\s*\(\s*['"](md5|sha1)['"]"##),
    rule("JS093", Medium, JS, "Güvenlik değeri Math.random ile üretiliyor (tahmin edilebilir)",
        r"(?i)(token|secret|passw|otp|nonce|salt|session|reset)\w*\s*[:=][^;]*Math\.random\s*\("),
    rule("JS094", Medium, JS, "CORS her kökene kimlik bilgisiyle açık",
        r"origin\s*:\s*(true|['\x22]\*['\x22])[^;]*credentials\s*:\s*true"),
    // ===================== Python ==========================================
    rule("PY001", Critical, PY,
        "Kullanıcı girdisi işletim sistemi komutuna ulaşıyor (komut enjeksiyonu / RCE)",
        r"\bos\.(system|popen|exec[lv]p?e?|spawn\w*)\s*\(|\bsubprocess\.(run|call|check_call|check_output|Popen|getoutput|getstatusoutput)\s*\(")
        .tainted().unless(r"shlex\.quote").group("py-exec"),
    rule("PY002", High, PY, "Kabuk üzerinden komut çalıştırma (shell=True / os.system)",
        r"\bshell\s*=\s*True|\bos\.(system|popen)\s*\(")
        .group("py-exec"),
    rule("PY010", Critical, PY,
        "Kullanıcı girdisi kod olarak çalıştırılıyor (eval/exec/__import__ → RCE)",
        r"(^|[^\w.])(eval|exec|compile)\s*\(|\b__import__\s*\(|\bimportlib\.import_module\s*\(")
        .tainted().group("py-eval"),
    rule("PY011", High, PY, "eval/exec kullanımı (kod enjeksiyonu riski)",
        r"(^|[^\w.])(eval|exec)\s*\(")
        .group("py-eval"),
    rule("PY020", Critical, PY,
        "Kullanıcı girdisi pickle/marshal ile çözülüyor (nesne enjeksiyonu → RCE)",
        r"\b(pickle|cPickle|_pickle|dill|marshal|jsonpickle)\.(loads?|decode)\s*\(")
        .tainted().group("py-deser"),
    rule("PY021", Medium, PY, "pickle/marshal ile serileştirme çözme (güvenilmeyen veriyle RCE)",
        r"\b(pickle|cPickle|_pickle|dill|marshal|jsonpickle)\.(loads?|decode)\s*\(")
        .group("py-deser"),
    rule("PY022", High, PY, "yaml.load güvenli yükleyici olmadan (nesne enjeksiyonu → RCE)",
        r"\byaml\.(load|load_all|unsafe_load|full_load)\s*\(")
        .unless(r"SafeLoader|CSafeLoader"),
    rule("PY030", Critical, PY,
        "Kullanıcı girdisi SQL sorgusuna doğrudan giriyor (SQL enjeksiyonu)",
        r"\.(execute|executemany|executescript|raw|extra)\s*\(|(^|[^\w.])text\s*\(")
        .tainted().unless(r##"\.(execute|executemany|raw)\s*\(\s*['"][^'"]*['"]\s*,"##).group("py-sql"),
    rule("PY031", High, PY, "SQL sorgusu f-string / % / + / format ile kuruluyor (SQL enjeksiyonu)",
        r##"(?i)\bf["'][^"']*\b(select\s.+?\sfrom|insert\s+into|update\s+\S+\s+set|delete\s+from)\b[^"']*\{|["']\s*(select\s.+?\sfrom|insert\s+into|update\s+\S+\s+set|delete\s+from)\b[^"']*["']\s*(%\s*[\w(]|\+\s*\w|\.format\s*\()"##)
        .group("py-sql"),
    rule("PY040", High, PY, "Kullanıcı kontrollü dosya yolu (path traversal / dosya yazarak web shell)",
        r"(^|[^\w.])open\s*\(|\bsend_file\s*\(|\bos\.(remove|unlink|rmdir|makedirs)\s*\(|\bshutil\.\w+\s*\(|(^|[^\w.])Path\s*\(|\bFileResponse\s*\(")
        .tainted().unless(r"secure_filename|basename|send_from_directory|safe_join"),
    rule("PY050", High, PY, "Kullanıcı kontrollü URL'ye sunucu tarafı istek (SSRF)",
        r"\b(requests|httpx|session|client)\.(get|post|put|patch|delete|head|request)\s*\(|\burlopen\s*\(|\baiohttp\.request\s*\(")
        .tainted(),
    rule("PY060", Critical, PY, "Kullanıcı girdisi şablon olarak işleniyor (SSTI → RCE)",
        r"\brender_template_string\s*\(|(^|[^\w.])Template\s*\(|\.from_string\s*\(")
        .tainted(),
    rule("PY061", High, PY, "Kullanıcı girdisi kaçışsız HTML'e yazılıyor (XSS)",
        r"\bMarkup\s*\(|\bmark_safe\s*\(|\bHttpResponse\s*\(|\bmake_response\s*\(|\bHTMLResponse\s*\(|\breturn\s+f['\x22]")
        .tainted().unless(r"escape\s*\("),
    rule("PY062", Medium, PY, "Kullanıcı kontrollü yönlendirme (open redirect)",
        r"(^|[^\w.])redirect\s*\(|\bHttpResponseRedirect\s*\(|\bRedirectResponse\s*\(")
        .tainted().unless(r"url_has_allowed_host_and_scheme|is_safe_url|url_for\s*\("),
    rule("PY074", High, PY, "JWT imza / algoritma doğrulaması kapatılmış",
        r##"verify_signature['"]?\s*:\s*False|algorithms\s*=\s*\[[^\]]*['"]none['"]|\bjwt\.decode\s*\([^)]*verify\s*=\s*False"##)
        .group("py-verify"),
    rule("PY070", High, PY, "TLS doğrulaması kapatılmış",
        r"\bverify\s*=\s*False|_create_unverified_context|\bCERT_NONE\b")
        .group("py-verify"),
    rule("PY071", High, PY, "Hata ayıklama modu açık (Werkzeug debugger → RCE / bilgi sızıntısı)",
        r"^\s*DEBUG\s*=\s*True|\.run\s*\([^)]*debug\s*=\s*True"),
    rule("PY072", Medium, PY, "Kriptografik olarak zayıf özet algoritması (MD5/SHA-1)",
        r"\bhashlib\.(md5|sha1)\s*\(|\bhashlib\.new\s*\(\s*['\x22](md5|sha1)"),
    rule("PY073", Medium, PY, "Güvenlik değeri random modülüyle üretiliyor (tahmin edilebilir; secrets kullanın)",
        r"(?i)(token|secret|passw|otp|nonce|salt|session|reset)\w*\s*=[^=][^#]*\brandom\.(random|randint|choice|choices|getrandbits|randrange)\s*\("),
    rule("PY075", Medium, PY, "tempfile.mktemp yarış durumu (mkstemp / NamedTemporaryFile kullanın)",
        r"\btempfile\.mktemp\s*\("),
    rule("PY076", High, PY, "XML dış varlık (XXE) çözümlemesi açık",
        r"resolve_entities\s*=\s*True|no_network\s*=\s*False"),
    rule("PY077", Medium, PY, "CSRF koruması kapatılmış",
        r"@csrf_exempt\b|WTF_CSRF_ENABLED['\x22\]]*\s*=\s*False"),

    // ===================== Go ==============================================
    rule("GO001", Critical, GO,
        "Kullanıcı girdisi işletim sistemi komutuna ulaşıyor (komut enjeksiyonu / RCE)",
        r"\bexec\.Command(Context)?\s*\(")
        .tainted().group("go-exec"),
    rule("GO002", High, GO, "Kabuk üzerinden komut çalıştırma (sh -c / cmd /c)",
        r##"\bexec\.Command(Context)?\s*\([^)]*["`](sh|bash|/bin/sh|/bin/bash|cmd|cmd\.exe|powershell|pwsh)["`]\s*,\s*["`](-c|/c|/C|-Command)["`]"##)
        .group("go-exec"),
    rule("GO010", Critical, GO,
        "Kullanıcı girdisi SQL sorgusuna doğrudan giriyor (SQL enjeksiyonu)",
        r"\.(Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext|Raw)\s*\(")
        .tainted().unless(r##"\.(Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext|Raw)\s*\(\s*(ctx\s*,\s*)?["`][^"`]*["`]\s*,|\b(c|ctx|URL)\.Query\s*\("##).group("go-sql"),
    rule("GO011", High, GO, "SQL sorgusu fmt.Sprintf / + ile kuruluyor (SQL enjeksiyonu)",
        r##"(?i)fmt\.Sprintf\s*\(\s*["`]\s*(select\s.+?\sfrom|insert\s+into|update\s+\S+\s+set|delete\s+from)|["`]\s*(select\s.+?\sfrom|insert\s+into|update\s+\S+\s+set|delete\s+from)\b[^"`]*["`]\s*\+\s*\w"##)
        .group("go-sql"),
    rule("GO020", High, GO, "Kullanıcı kontrollü dosya yolu (path traversal)",
        r"\bos\.(Open|OpenFile|ReadFile|WriteFile|Create|Remove|RemoveAll|ReadDir)\s*\(|\bioutil\.(ReadFile|WriteFile|ReadDir)\s*\(|\bhttp\.ServeFile\s*\(|\bc\.(File|SaveUploadedFile|FileAttachment)\s*\(")
        .tainted().unless(r"filepath\.Base|path\.Base"),
    rule("GO030", High, GO, "Kullanıcı kontrollü URL'ye sunucu tarafı istek (SSRF)",
        r"\bhttp\.(Get|Post|Head|PostForm|NewRequest|NewRequestWithContext)\s*\(|\b\w*[cC]lient\.(Get|Post|Head)\s*\(")
        .tainted(),
    rule("GO040", High, GO, "Kullanıcı girdisi kaçışsız HTML'e yazılıyor (XSS)",
        r"\btemplate\.(HTML|JS|URL|HTMLAttr)\s*\(|\bw\.Write\s*\(|\bfmt\.Fprint(f|ln)?\s*\(\s*w\b|\bio\.WriteString\s*\(\s*w\b|\bc\.(String|Data)\s*\(")
        .tainted().unless(r"html\.EscapeString|HTMLEscapeString").group("go-xss"),
    rule("GO041", Medium, GO, "template.HTML ile otomatik kaçış devre dışı (XSS riski)",
        r##"\btemplate\.(HTML|JS)\s*\(\s*[^"`)\s]"##)
        .group("go-xss"),
    rule("GO042", Medium, GO, "Kullanıcı kontrollü yönlendirme (open redirect)",
        r"\bhttp\.Redirect\s*\(|\bc\.Redirect\s*\(")
        .tainted(),
    rule("GO050", High, GO, "TLS doğrulaması kapatılmış", r"InsecureSkipVerify\s*:\s*true"),
    rule("GO051", Medium, GO, "Kriptografik olarak zayıf özet algoritması (MD5/SHA-1)",
        r"\b(md5|sha1)\.(New|Sum)\w*\s*\("),
    rule("GO052", Medium, GO, "Güvenlik değeri math/rand ile üretiliyor (crypto/rand kullanın)",
        r"(?i)(token|secret|passw|otp|nonce|salt|session)\w*\s*:?=[^=].*\brand\.(Intn|Int31n?|Int63n?|Uint32|Uint64|Float64)\s*\("),
    rule("GO053", Low, GO, "Zaman aşımı olmayan HTTP sunucusu (Slowloris ile hizmet reddi)",
        r"\bhttp\.ListenAndServe(TLS)?\s*\("),
    rule("GO054", Medium, GO, "unsafe.Pointer kullanımı (bellek güvenliği garantisi devre dışı)",
        r"\bunsafe\.Pointer\b"),
    rule("GO055", High, GO, "JWT imzası doğrulanmıyor",
        r"UnsafeAllowNoneSignatureType|SigningMethodNone|\.ParseUnverified\s*\("),
];

// ---- Taint (kullanıcı girdisi) izleme -------------------------------------

struct TaintSpec {
    /// Doğrudan kullanıcı girdisi kaynakları
    source: Regex,
    /// Atamanın sağ tarafı yalnızca bu ise kaynak sayılır (ör. `= req`)
    rhs_source: Option<Regex>,
    /// Sağ taraf bunu içeriyorsa değer temizlenmiş sayılır
    sanitizer: Regex,
    /// `lhs` / `rhs` adlı gruplara sahip atama desenleri
    assigns: Vec<Regex>,
    /// Satırdaki değişken adlarını bulan desen
    ident: Regex,
    php_style: bool,
}

fn re(p: &str) -> Result<Regex> {
    Regex::new(p).map_err(|e| Error::Config(format!("geçersiz desen {p:?}: {e}")))
}

impl TaintSpec {
    fn php() -> Result<Self> {
        Ok(Self {
            source: re(r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b|\$HTTP_RAW_POST_DATA|php://input|\bgetallheaders\s*\(|\bapache_request_headers\s*\(|\$argv\b|\bfilter_input\s*\(\s*INPUT_\w+\s*,[^,)]+\)")?,
            rhs_source: None,
            sanitizer: re(r"\b(intval|floatval|boolval|basename|escapeshellarg|htmlspecialchars|htmlentities|filter_var|ctype_\w+|is_numeric|password_hash|hash|md5|sha1|crc32|count|strlen|json_encode|in_array|array_key_exists|preg_quote|preg_match|urlencode|rawurlencode|isset|empty)\s*\(|\((int|float|bool)\)")?,
            assigns: vec![
                re(r"^\s*(?P<lhs>\$\w+)(\s*\[[^\]]*\])*\s*(\.|\?\?|\+)?=\s*(?P<rhs>[^=>].*)$")?,
                re(r"foreach\s*\((?P<rhs>.+?)\s+as\s+(?P<lhs>\$\w+(\s*=>\s*\$\w+)?)")?,
            ],
            ident: re(r"\$[A-Za-z_]\w*")?,
            php_style: true,
        })
    }

    fn js() -> Result<Self> {
        Ok(Self {
            source: re(r"\breq\.(body|query|params|headers|cookies|files?|originalUrl|url|path)\b|\breq\.(get|param|header)\s*\(|\brequest\.(body|query|params|headers|nextUrl|url)\b|\b(req|request)\.(json|text|formData|arrayBuffer)\s*\(|\bsearchParams\b|\bformData\.get(All)?\s*\(|\bctx\.(query|params|request\.(body|query))\b|\bprocess\.argv\b|\blocation\.(hash|search|href|pathname)\b|\bdocument\.(URL|referrer|cookie|documentURI)\b|\bwindow\.name\b|\bevent\.data\b|\bparams\.\w+")?,
            rhs_source: Some(re(r"^\s*(await\s+)?(req|request|ctx\.request)\s*;?\s*$")?),
            sanitizer: re(r"\b(parseInt|parseFloat|Number|Boolean|encodeURIComponent|encodeURI|escape\w*|sanitize\w*|DOMPurify|validator|basename|isValid\w*|bcrypt|argon2|typeof)\b|\w*[Ss]chema\.(parse|safeParse|validate)\s*\(|\bz\.\w+|\.safeParse\s*\(|\bJoi\.|\.validate(Sync)?\s*\(|\.length\b|\.includes\s*\(|\.test\s*\(")?,
            assigns: vec![
                re(r"^\s*(export\s+)?(const|let|var)\s+(?P<lhs>[A-Za-z_$][\w$]*|\{[^}]*\}|\[[^\]]*\])\s*(:\s*[^=]+)?=\s*(?P<rhs>[^=>].*)$")?,
                re(r"^\s*(?P<lhs>[A-Za-z_$][\w$]*)\s*(\+|\?\?|\|\|)?=\s*(?P<rhs>[^=>].*)$")?,
                re(r"for\s*\(\s*(const|let|var)\s+(?P<lhs>[A-Za-z_$][\w$]*|\{[^}]*\}|\[[^\]]*\])\s+of\s+(?P<rhs>[^)]+)\)")?,
            ],
            ident: re(r"[A-Za-z_$][\w$]*")?,
            php_style: false,
        })
    }

    fn python() -> Result<Self> {
        Ok(Self {
            source: re(r"\brequest\.(args|form|values|json|data|files|cookies|headers|get_json|get_data|GET|POST|FILES|COOKIES|META|body|query_params|path_params|stream)\b|(^|[^\w.])input\s*\(|\bsys\.argv\b")?,
            rhs_source: Some(re(r"^\s*(await\s+)?request\s*$")?),
            sanitizer: re(r"(^|[^\w.])(int|float|bool|len)\s*\(|\b(shlex\.quote|escape|secure_filename|bleach\.clean|uuid\.UUID|basename|safe_join|model_validate|parse_obj|check_password_hash|generate_password_hash)\s*\(|\bhashlib\.\w+\s*\(|\.(isdigit|isalnum|isdecimal|is_valid)\s*\(|\bre\.(fullmatch|match)\s*\(")?,
            assigns: vec![
                re(r"^\s*(?P<lhs>[A-Za-z_]\w*(\s*,\s*[A-Za-z_]\w*)*)\s*(:\s*[^=]+)?(\+|\|)?=\s*(?P<rhs>[^=].*)$")?,
                re(r"^\s*for\s+(?P<lhs>[A-Za-z_]\w*(\s*,\s*[A-Za-z_]\w*)*)\s+in\s+(?P<rhs>.+):")?,
            ],
            ident: re(r"[A-Za-z_]\w*")?,
            php_style: false,
        })
    }

    fn go() -> Result<Self> {
        Ok(Self {
            source: re(r"\br\.(URL\.(Query|Path|RawQuery)|FormValue|PostFormValue|Form|PostForm|Body|Header|Cookie|PathValue|MultipartForm|FormFile)\b|\b(mux\.Vars|chi\.URLParam)\s*\(|\bc\.(Query|Param|Params|PostForm|FormValue|GetHeader|DefaultQuery|FormFile|Cookies|Body|BodyParser|ShouldBind\w*|Bind\w*)\s*\(|\bos\.Args\b")?,
            rhs_source: None,
            sanitizer: re(r"\b(strconv\.(Atoi|Parse\w+)|filepath\.Base|path\.Base|url\.(QueryEscape|PathEscape)|html\.EscapeString|template\.HTMLEscapeString|uuid\.Parse|bcrypt\.\w+|len)\s*\(|\.MatchString\s*\(")?,
            assigns: vec![
                re(r"^\s*(var\s+)?(?P<lhs>[A-Za-z_]\w*(\s*,\s*[A-Za-z_]\w*)*)\s*([\w.\[\]*]+\s*)?(:=|=|\+=)\s*(?P<rhs>[^=].*)$")?,
                re(r"^\s*for\s+(?P<lhs>[A-Za-z_]\w*(\s*,\s*[A-Za-z_]\w*)*)\s*:=\s*range\s+(?P<rhs>.+?)\s*\{")?,
            ],
            ident: re(r"[A-Za-z_]\w*")?,
            php_style: false,
        })
    }

    /// Satırda izlenen bir değişken geçiyor mu? (JS'te `obj.x` gibi özellik erişimlerini saymaz)
    fn mentions(&self, text: &str, vars: &HashSet<String>) -> bool {
        if vars.is_empty() {
            return false;
        }
        let bytes = text.as_bytes();
        self.ident.find_iter(text).any(|m| {
            if !self.php_style && m.start() > 0 && bytes[m.start() - 1] == b'.' {
                return false;
            }
            vars.contains(m.as_str())
        })
    }

    fn lhs_names(&self, lhs: &str) -> Vec<String> {
        let lhs = lhs.trim();
        if self.php_style {
            return self.ident.find_iter(lhs).map(|m| m.as_str().to_string()).collect();
        }
        if !(lhs.starts_with('{') || lhs.starts_with('[')) {
            // `a` ya da `a, err` (Python/Go çoklu atama); hata ve boş değişkenler izlenmez
            return lhs
                .split(',')
                .map(str::trim)
                .filter(|n| !n.is_empty() && !matches!(*n, "_" | "err" | "if" | "for" | "return" | "var"))
                .map(String::from)
                .collect();
        }
        // Yapı bozma: { a, b: c, d = 1, ...rest } / [x, y]
        lhs.trim_matches(|c| matches!(c, '{' | '}' | '[' | ']'))
            .split(',')
            .filter_map(|part| {
                let p = part.rsplit(':').next()?.split('=').next()?.trim().trim_start_matches("...");
                let ok = !p.is_empty() && p.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '$');
                ok.then(|| p.to_string())
            })
            .collect()
    }

    /// Her satır için "kullanıcı girdisi taşıyor mu?" bilgisini hesaplar.
    fn tainted_lines(&self, lines: &[&str], code: &[bool]) -> Vec<bool> {
        let mut vars: HashSet<String> = HashSet::new();
        // Atama zincirleri için sabit noktaya kadar (en fazla 6 tur) yay.
        for _ in 0..6 {
            let before = vars.len();
            for (line, _) in lines.iter().zip(code).filter(|(_, c)| **c) {
                for a in &self.assigns {
                    let Some(caps) = a.captures(line) else { continue };
                    let (Some(lhs), Some(rhs)) = (caps.name("lhs"), caps.name("rhs")) else { continue };
                    let rhs = rhs.as_str();
                    if self.sanitizer.is_match(rhs) {
                        continue;
                    }
                    let from_source = self.source.is_match(rhs)
                        || self.rhs_source.as_ref().is_some_and(|r| r.is_match(rhs))
                        || self.mentions(rhs, &vars);
                    if from_source {
                        vars.extend(self.lhs_names(lhs.as_str()));
                    }
                }
            }
            if vars.len() == before {
                break;
            }
        }
        lines
            .iter()
            .zip(code)
            .map(|(l, c)| *c && (self.source.is_match(l) || self.mentions(l, &vars)))
            .collect()
    }
}

// ---- Tarayıcı -------------------------------------------------------------

struct CompiledRule {
    def: &'static RuleDef,
    re: Regex,
    unless: Option<Regex>,
}

pub struct Scanner {
    rules: Vec<CompiledRule>,
    php_taint: TaintSpec,
    js_taint: TaintSpec,
    py_taint: TaintSpec,
    go_taint: TaintSpec,
    suppress: Regex,
}

/// Birden fazla satıra yayılmış tek ifade (ör. `exec(\n  cmd,\n  opts)`).
/// Kurallar birleştirilmiş metne uygulanır; bulgu ilk satıra yazılır.
struct Stmt {
    start: usize,
    end: usize,
    text: String,
}

/// Bir ifadeyi en fazla bu kadar satıra kadar birleştir
const MAX_STMT_LINES: usize = 12;

/// Satırdaki net parantez derinliği (dize içleri sayılmaz).
fn paren_delta(line: &str) -> i32 {
    let (mut depth, mut quote, mut escaped) = (0i32, None::<char>, false);
    for c in line.chars() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' | '`' => quote = Some(c),
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
    }
    depth
}

fn statements(lines: &[&str], code: &[bool], lang: Lang) -> Vec<Stmt> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if !code[i] {
            i += 1;
            continue;
        }
        let start = i;
        let mut text = lines[i].to_string();
        let mut depth = paren_delta(lines[i]);
        // Rust'ta yaşam süreleri ('a) tırnak sanılır; orada birleştirme yapılmaz.
        // Satır `{` ile bitiyorsa bir blok açılıyordur (fonksiyon gövdesi), ifade değil.
        let joinable = lang != Lang::Rust && !lines[i].trim_end().ends_with('{');
        while joinable && depth > 0 && i + 1 < lines.len() && i + 1 - start < MAX_STMT_LINES {
            i += 1;
            if !code[i] {
                continue;
            }
            text.push(' ');
            text.push_str(lines[i].trim());
            depth += paren_delta(lines[i]);
            let t = lines[i].trim_end();
            if t.ends_with('{') && (t.contains("=>") || t.contains("function") || t.contains("func")) {
                break; // geri çağırma gövdesi başlıyor
            }
        }
        out.push(Stmt { start, end: i, text });
        i += 1;
    }
    out
}

impl Scanner {
    pub fn new() -> Result<Self> {
        let rules = RULES
            .iter()
            .map(|def| {
                let compile = |p: &str| {
                    Regex::new(p).map_err(|e| Error::Config(format!("{} kuralı geçersiz: {e}", def.id)))
                };
                Ok(CompiledRule {
                    def,
                    re: compile(def.pattern)?,
                    unless: def.unless.map(compile).transpose()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            rules,
            php_taint: TaintSpec::php()?,
            js_taint: TaintSpec::js()?,
            py_taint: TaintSpec::python()?,
            go_taint: TaintSpec::go()?,
            suppress: re(r"autoremediate-ignore\[([A-Za-z0-9_, ]+)\]\s*:\s*\S")?,
        })
    }

    #[cfg(test)]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Bastırılmamış bulgular (onarım döngüsü bunları sıfırlamaya çalışır).
    pub fn scan(&self, source: &str, lang: Lang) -> Vec<Finding> {
        self.scan_full(source, lang).findings
    }

    /// Kaynağı tarar; bulguları önem derecesine (azalan), sonra satıra göre sıralar.
    pub fn scan_full(&self, source: &str, lang: Lang) -> ScanResult {
        let lines: Vec<&str> = source.lines().collect();
        let code = code_mask(&lines, lang);
        let stmts = statements(&lines, &code, lang);
        let texts: Vec<&str> = stmts.iter().map(|s| s.text.as_str()).collect();
        let all_code = vec![true; texts.len()];
        let taint = match lang {
            Lang::Php => self.php_taint.tainted_lines(&texts, &all_code),
            Lang::Js => self.js_taint.tainted_lines(&texts, &all_code),
            Lang::Python => self.py_taint.tainted_lines(&texts, &all_code),
            Lang::Go => self.go_taint.tainted_lines(&texts, &all_code),
            Lang::Rust => vec![false; texts.len()],
        };
        let suppressed_ids: Vec<Vec<String>> = lines
            .iter()
            .map(|l| {
                self.suppress
                    .captures(l)
                    .map(|c| c[1].split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_default()
            })
            .collect();

        let mut out = ScanResult::default();
        for (si, stmt) in stmts.iter().enumerate() {
            let line = stmt.text.as_str();
            let mut groups: HashSet<&str> = HashSet::new();
            for rule in self.rules.iter().filter(|r| r.def.langs.contains(&lang)) {
                if let Some(g) = rule.def.group {
                    if groups.contains(g) {
                        continue;
                    }
                }
                if rule.def.needs_taint && !taint[si] {
                    continue;
                }
                if !rule.re.is_match(line) || rule.unless.as_ref().is_some_and(|u| u.is_match(line)) {
                    continue;
                }
                if let Some(g) = rule.def.group {
                    groups.insert(g);
                }
                let finding = Finding {
                    rule_id: rule.def.id,
                    severity: rule.def.severity,
                    line: stmt.start + 1,
                    snippet: if rule.def.redact {
                        "[MASKELENDİ]".to_string()
                    } else {
                        truncate_chars(line.trim(), 200)
                    },
                    description: rule.def.description,
                };
                let first = stmt.start.saturating_sub(1);
                let is_suppressed = (first..=stmt.end).any(|i| suppressed_ids[i].iter().any(|id| id == rule.def.id));
                if is_suppressed {
                    out.suppressed.push(finding);
                } else {
                    out.findings.push(finding);
                }
            }
        }
        let order = |a: &Finding, b: &Finding| b.severity.cmp(&a.severity).then(a.line.cmp(&b.line));
        out.findings.sort_by(order);
        out.suppressed.sort_by(order);
        out
    }
}

/// Yorum olmayan (kod) satırları işaretler: `//`, `/* ... */`, PHP/Python'da `#`,
/// Python'da üç tırnaklı belge dizeleri.
fn code_mask(lines: &[&str], lang: Lang) -> Vec<bool> {
    let mut in_block = false;
    let mut in_doc: Option<&str> = None;
    lines
        .iter()
        .map(|line| {
            let t = line.trim_start();
            if lang == Lang::Python {
                if let Some(q) = in_doc {
                    if t.contains(q) {
                        in_doc = None;
                    }
                    return false;
                }
                if t.starts_with('#') {
                    return false;
                }
                for q in ["\"\"\"", "'''"] {
                    // Satır yalnızca belge dizesiyle başlıyorsa (atamanın parçası değilse)
                    let body = t.trim_start_matches(['r', 'b', 'u', 'R', 'B', 'U']);
                    if let Some(rest) = body.strip_prefix(q) {
                        if !rest.contains(q) {
                            in_doc = Some(q);
                        }
                        return false;
                    }
                }
                return true;
            }
            if in_block {
                if t.contains("*/") {
                    in_block = false;
                }
                return false;
            }
            if t.starts_with("/*") {
                in_block = !t.contains("*/");
                return false;
            }
            if t.starts_with("//") || (t.starts_with('*') && !t.starts_with("*=")) {
                return false;
            }
            if lang == Lang::Php && t.starts_with('#') && !t.starts_with("#[") {
                return false;
            }
            true
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Antivirüslerin web shell imzası sanmaması için riskli anahtar kelimeler
    /// kaynakta düz metin olarak geçmez; çalışma anında birleştirilir.
    fn kw(parts: &[&str]) -> String {
        parts.concat()
    }

    fn ids(src: &str, lang: Lang) -> Vec<&'static str> {
        let s = Scanner::new().unwrap();
        let mut v: Vec<_> = s.scan(src, lang).iter().map(|x| x.rule_id).collect();
        v.sort();
        v
    }

    #[test]
    fn all_rules_compile() {
        assert!(Scanner::new().unwrap().rule_count() > 40);
    }

    #[test]
    fn detects_multiple_classes() {
        let s = Scanner::new().unwrap();
        let src = r#"
let api_key = "sk-live-1234567890abcdef";
let out = Command::new("sh").arg("-c").output();
let u = "http://example.com";
// let password = "yorum satırı yok sayılır";
"#;
        let f = s.scan(src, Lang::Rust);
        let ids: Vec<_> = f.iter().map(|x| x.rule_id).collect();
        assert_eq!(ids, vec!["SEC001", "SEC002", "SEC008"]);
        assert_eq!(f[0].snippet, "[MASKELENDİ]");
    }

    #[test]
    fn clean_code_has_no_findings() {
        let s = Scanner::new().unwrap();
        assert!(s.scan("fn main() { println!(\"merhaba\"); }", Lang::Rust).is_empty());
    }

    #[test]
    fn lang_detection() {
        assert_eq!(Lang::from_path(Path::new("a/b.PHP")), Some(Lang::Php));
        assert_eq!(Lang::from_path(Path::new("page.tsx")), Some(Lang::Js));
        assert_eq!(Lang::from_path(Path::new("x.min.js")), None);
        assert_eq!(Lang::from_path(Path::new("README.md")), None);
    }

    #[test]
    fn php_taint_flows_through_variables() {
        let src = "<?php\n$c = $_GET['c'];\n$cmd = 'ls ' . $c;\nsystem($cmd);\n";
        assert_eq!(ids(src, Lang::Php), vec!["PHP010"]);
    }

    #[test]
    fn php_webshell_signatures() {
        let dyncall = format!("<?php {}['f']({}['c']);", kw(&["$_G", "ET"]), kw(&["$_PO", "ST"]));
        assert_eq!(ids(&dyncall, Lang::Php), vec!["PHP001"]);
        let packed = format!("<?php @{}({}($x));", kw(&["ev", "al"]), kw(&["base64", "_decode"]));
        assert_eq!(ids(&packed, Lang::Php), vec!["PHP003"]);
        assert_eq!(ids("<?php echo `cat $f`;", Lang::Php), vec!["PHP011"]);
        assert_eq!(ids("<?php include $_GET['page'] . '.php';", Lang::Php), vec!["PHP030"]);
        assert_eq!(
            ids("<?php move_uploaded_file($_FILES['f']['tmp_name'], 'up/' . $_FILES['f']['name']);", Lang::Php),
            vec!["PHP050"]
        );
    }

    #[test]
    fn php_safe_variants_are_quiet() {
        let src = "<?php\n$d = $_GET['d'];\nsystem('ls ' . escapeshellarg($d));\n$o = unserialize($s, ['allowed_classes' => false]);\n$id = intval($_GET['id']);\n$db->query(\"SELECT 1\");\n$pdo->exec('VACUUM');\n";
        assert!(ids(src, Lang::Php).is_empty(), "{:?}", ids(src, Lang::Php));
    }

    #[test]
    fn php_deser_and_sql() {
        assert_eq!(ids("<?php $o = unserialize($_COOKIE['d']);", Lang::Php), vec!["PHP020"]);
        let src = "<?php\n$id = $_GET['id'];\n$r = mysqli_query($db, \"SELECT * FROM u WHERE id = $id\");\n";
        assert_eq!(ids(src, Lang::Php), vec!["PHP040"]);
    }

    #[test]
    fn js_taint_and_sinks() {
        let src = "const { cmd } = req.query;\nexec(cmd);\n";
        assert_eq!(ids(src, Lang::Js), vec!["JS001"]);
        let run_body = format!("app.post('/x', (req, res) => {}(req.body.code));", kw(&["ev", "al"]));
        assert_eq!(ids(&run_body, Lang::Js), vec!["JS010"]);
        assert_eq!(ids("db.query(`SELECT * FROM u WHERE id=${req.params.id}`);", Lang::Js), vec!["JS040"]);
        assert_eq!(ids("_.merge(config, req.body);", Lang::Js), vec!["JS030"]);
        assert_eq!(ids("const s = require('node-serialize');", Lang::Js), vec!["JS020"]);
        assert_eq!(ids("res.sendFile(req.query.f);", Lang::Js), vec!["JS050"]);
        assert_eq!(ids("exec(`ls ${dir}`);", Lang::Js), vec!["JS002"]);
    }

    #[test]
    fn js_safe_variants_are_quiet() {
        let src = "const dir = req.query.d;\nexecFile('ls', [dir]);\nconst m = /a/.exec(s);\nconst id = parseInt(req.params.id, 10);\ndb.query('SELECT * FROM u WHERE id = $1', [id]);\nel.innerHTML = DOMPurify.sanitize(html);\n";
        assert!(ids(src, Lang::Js).is_empty(), "{:?}", ids(src, Lang::Js));
    }

    #[test]
    fn schema_validation_stops_taint() {
        let src = "const input = BodySchema.parse(req.body);\nconst x = input.cmd;\nexec(x);\n";
        assert!(ids(src, Lang::Js).is_empty());
    }

    #[test]
    fn suppression_comment_is_honored_and_reported() {
        let s = Scanner::new().unwrap();
        let src = "const u = req.query.u;\n// autoremediate-ignore[JS060]: host allowlist bir üst satırda kontrol ediliyor\nawait fetch(u);\n";
        let r = s.scan_full(src, Lang::Js);
        assert!(r.findings.is_empty());
        assert_eq!(r.suppressed.len(), 1);
        // Gerekçesiz yorum geçersizdir
        let r = s.scan_full("const u = req.query.u;\n// autoremediate-ignore[JS060]:\nawait fetch(u);\n", Lang::Js);
        assert_eq!(r.findings.len(), 1);
    }

    #[test]
    fn block_comments_are_skipped() {
        assert!(ids(&format!("/*\n {}(req.body.x)\n*/\n", kw(&["ev", "al"])), Lang::Js).is_empty());
        assert!(ids("<?php\n# system($_GET['c']);\n", Lang::Php).is_empty());
    }

    #[test]
    fn multiline_calls_are_joined() {
        let src = "const c = req.query.c;\nexec(\n  c,\n  { timeout: 5 }\n);\n";
        let s = Scanner::new().unwrap();
        let f = s.scan(src, Lang::Js);
        assert_eq!(f.iter().map(|x| x.rule_id).collect::<Vec<_>>(), vec!["JS001"]);
        assert_eq!(f[0].line, 2, "bulgu ifadenin ilk satırına yazılmalı");
        // Geri çağırma gövdeleri tek ifadeye katılmaz; içteki satır kendi numarasıyla raporlanır
        let src = "app.get('/x', (req, res) => {\n  const f = req.query.f;\n  res.sendFile(f);\n});\n";
        assert_eq!(s.scan(src, Lang::Js)[0].line, 3);
        // Çok satırlı atamalar da taint taşır
        let src = "<?php\n$c = trim(\n  $_GET['c']\n);\nsystem($c);\n";
        assert_eq!(ids(src, Lang::Php), vec!["PHP010"]);
    }

    #[test]
    fn python_rules() {
        let src = "cmd = request.args.get('c')\nos.system('ping ' + cmd)\n";
        assert_eq!(ids(src, Lang::Python), vec!["PY001"]);
        let src = "name = request.form['n']\nreturn render_template_string('Merhaba ' + name)\n";
        assert_eq!(ids(src, Lang::Python), vec!["PY060"]);
        let src = "uid = request.args['id']\ncur.execute(f\"SELECT * FROM u WHERE id={uid}\")\n";
        assert_eq!(ids(src, Lang::Python), vec!["PY030"]);
        let data = format!("obj = {}.loads(request.data)\n", kw(&["pic", "kle"]));
        assert_eq!(ids(&data, Lang::Python), vec!["PY020"]);
        assert_eq!(ids("cfg = yaml.load(f)\n", Lang::Python), vec!["PY022"]);
        assert_eq!(ids("app.run(debug=True)\n", Lang::Python), vec!["PY071"]);
        assert_eq!(ids("r = requests.get(u, verify=False)\n", Lang::Python), vec!["PY070"]);
    }

    #[test]
    fn python_safe_variants_are_quiet() {
        let src = "\"\"\"\nos.system(request.args['x'])\n\"\"\"\n# os.system(x)\nuid = int(request.args['id'])\ncur.execute('SELECT * FROM u WHERE id = %s', (uid,))\ncfg = yaml.load(f, Loader=yaml.SafeLoader)\nsubprocess.run(['ls', '-l'])\nv = ast.literal_eval(s)\n";
        assert!(ids(src, Lang::Python).is_empty(), "{:?}", ids(src, Lang::Python));
    }

    #[test]
    fn go_rules() {
        let src = "host := r.URL.Query().Get(\"h\")\nout, err := exec.Command(\"ping\", host).Output()\n";
        assert_eq!(ids(src, Lang::Go), vec!["GO001"]);
        let src = "id := r.FormValue(\"id\")\nrows, err := db.Query(\"SELECT * FROM u WHERE id = \" + id)\n";
        assert_eq!(ids(src, Lang::Go), vec!["GO010"]);
        assert_eq!(ids("q := fmt.Sprintf(\"SELECT * FROM u WHERE n = '%s'\", n)\n", Lang::Go), vec!["GO011"]);
        assert_eq!(ids("tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}\n", Lang::Go), vec!["GO050"]);
        assert_eq!(ids("cmd := exec.Command(\"sh\", \"-c\", script)\n", Lang::Go), vec!["GO002"]);
    }

    #[test]
    fn go_safe_variants_are_quiet() {
        let src = "id, err := strconv.Atoi(r.FormValue(\"id\"))\nif err != nil {\n    http.Error(w, err.Error(), 400)\n}\nrow := db.QueryRow(\"SELECT * FROM u WHERE id = $1\", id)\nname := filepath.Base(r.URL.Query().Get(\"f\"))\nf, err := os.Open(filepath.Join(dir, name))\n";
        assert!(ids(src, Lang::Go).is_empty(), "{:?}", ids(src, Lang::Go));
    }
}
