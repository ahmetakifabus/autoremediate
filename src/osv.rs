//! OSV (https://osv.dev) ile canlı bağımlılık açığı sorgusu.
//!
//! Yerleşik tablo yalnızca bilinen birkaç kritik açığı kapsar; yeni yayımlanan
//! açıklar (GHSA, CVE, RUSTSEC, PHP güvenlik bültenleri) için OSV kullanılır.
//! Gönderilen veri yalnızca paket adı + sürümdür; kaynak kod gönderilmez.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};
use tokio::task::JoinSet;
use tracing::{info, warn};

use crate::ai::post_json_with_retry;
use crate::deps::{DepFinding, Dependency, Version};
use crate::error::{Error, Result};
use crate::scanner::Severity;
use crate::util::truncate_chars;

const BATCH: usize = 500;
const MAX_DETAILS: usize = 400;
const CONCURRENCY: usize = 8;

#[derive(Deserialize)]
struct BatchResp {
    #[serde(default)]
    results: Vec<BatchResult>,
}

#[derive(Deserialize, Default)]
struct BatchResult {
    #[serde(default)]
    vulns: Vec<VulnRef>,
}

#[derive(Deserialize)]
struct VulnRef {
    id: String,
}

#[derive(Deserialize, Clone)]
pub(crate) struct Vuln {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    affected: Vec<Affected>,
    #[serde(default)]
    database_specific: Option<Value>,
    #[serde(default)]
    withdrawn: Option<String>,
}

#[derive(Deserialize, Clone)]
struct Affected {
    #[serde(default)]
    package: Option<Pkg>,
    #[serde(default)]
    ranges: Vec<RangeDef>,
}

#[derive(Deserialize, Clone)]
struct Pkg {
    name: String,
    ecosystem: String,
}

#[derive(Deserialize, Clone)]
struct RangeDef {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    events: Vec<Value>,
}

fn base_url() -> String {
    std::env::var("OSV_BASE_URL").unwrap_or_else(|_| "https://api.osv.dev".into()).trim_end_matches('/').to_string()
}

pub async fn audit(deps: &[Dependency]) -> Result<Vec<DepFinding>> {
    if deps.is_empty() {
        return Ok(Vec::new());
    }
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("autoremediate/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let base = base_url();

    // Aynı paket/sürüm farklı manifestlerde olabilir: bir kez sor.
    let mut uniq: Vec<(&str, &str, &str)> = Vec::new();
    let mut seen = HashSet::new();
    for d in deps {
        let key = (d.ecosystem.osv_name(), d.name.as_str(), d.version.as_str());
        if seen.insert(key) {
            uniq.push(key);
        }
    }
    info!("OSV: {} paket sürümü sorgulanıyor", uniq.len());

    // 1) Toplu sorgu → hangi paket hangi açık kimliklerine sahip
    let mut hits: HashMap<(&str, &str, &str), Vec<String>> = HashMap::new();
    for chunk in uniq.chunks(BATCH) {
        let queries: Vec<Value> = chunk
            .iter()
            .map(|(eco, name, ver)| json!({"package": {"name": name, "ecosystem": eco}, "version": ver}))
            .collect();
        let raw = post_json_with_retry(&http, &format!("{base}/v1/querybatch"), &[], &json!({ "queries": queries }), 3).await?;
        let resp: BatchResp =
            serde_json::from_str(&raw).map_err(|e| Error::Remote(format!("OSV yanıtı çözümlenemedi: {e}")))?;
        for (key, r) in chunk.iter().zip(resp.results) {
            if !r.vulns.is_empty() {
                hits.insert(*key, r.vulns.into_iter().map(|v| v.id).collect());
            }
        }
    }

    // 2) Açık ayrıntıları (özet, önem, düzeltilmiş sürüm)
    let mut ids: Vec<String> = hits.values().flatten().cloned().collect::<HashSet<_>>().into_iter().collect();
    ids.sort();
    if ids.len() > MAX_DETAILS {
        warn!("OSV: {} açık bulundu, ilk {MAX_DETAILS} tanesinin ayrıntısı alınıyor", ids.len());
        ids.truncate(MAX_DETAILS);
    }
    let mut details: HashMap<String, Vuln> = HashMap::new();
    for chunk in ids.chunks(CONCURRENCY) {
        let mut set = JoinSet::new();
        for id in chunk {
            let (http, base, id) = (http.clone(), base.clone(), id.clone());
            set.spawn(async move { get_vuln(&http, &base, &id).await });
        }
        while let Some(res) = set.join_next().await {
            match res {
                Ok(Ok(v)) => {
                    details.insert(v.id.clone(), v);
                }
                Ok(Err(e)) => warn!("OSV ayrıntısı alınamadı: {e}"),
                Err(e) => warn!("OSV görevi başarısız: {e}"),
            }
        }
    }

    // 3) Bulgular: her manifestteki her bağımlılık için
    let mut out = Vec::new();
    for d in deps {
        let key = (d.ecosystem.osv_name(), d.name.as_str(), d.version.as_str());
        for id in hits.get(&key).into_iter().flatten() {
            match details.get(id) {
                Some(v) if v.withdrawn.is_some() => {}
                Some(v) => out.push(to_finding(d, v)),
                None => out.push(DepFinding {
                    ecosystem: d.ecosystem,
                    package: d.name.clone(),
                    version: d.version.clone(),
                    manifest: d.manifest.clone(),
                    approximate: d.approximate,
                    id: id.clone(),
                    aliases: Vec::new(),
                    severity: Severity::Medium,
                    summary: "(ayrıntı alınamadı)".into(),
                    fixed: None,
                    origin: "osv",
                }),
            }
        }
    }
    Ok(out)
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() < 100 && id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
}

async fn get_vuln(http: &reqwest::Client, base: &str, id: &str) -> Result<Vuln> {
    // Kimlik URL yoluna girer: yol enjeksiyonunu engelle.
    if !valid_id(id) {
        return Err(Error::Remote(format!("geçersiz OSV kimliği: {id:?}")));
    }
    let url = format!("{base}/v1/vulns/{id}");
    let mut delay = Duration::from_millis(500);
    let mut last = Error::Remote("bilinmeyen hata".into());
    for attempt in 1..=3 {
        match http.get(&url).send().await {
            Ok(r) if r.status().is_success() => {
                let text = r.text().await?;
                return serde_json::from_str(&text).map_err(|e| Error::Remote(format!("{id}: {e}")));
            }
            Ok(r) if r.status().as_u16() == 429 || r.status().is_server_error() => {
                last = Error::Remote(format!("{id}: HTTP {}", r.status()));
            }
            Ok(r) => return Err(Error::Remote(format!("{id}: HTTP {}", r.status()))),
            Err(e) if e.is_timeout() || e.is_connect() => last = Error::Http(e),
            Err(e) => return Err(Error::Http(e)),
        }
        if attempt < 3 {
            tokio::time::sleep(delay).await;
            delay *= 2;
        }
    }
    Err(last)
}

pub(crate) fn to_finding(d: &Dependency, v: &Vuln) -> DepFinding {
    let severity = v
        .database_specific
        .as_ref()
        .and_then(|ds| ds.get("severity"))
        .and_then(Value::as_str)
        .and_then(Severity::from_label)
        .unwrap_or(Severity::Medium);
    let summary = v
        .summary
        .clone()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| v.details.as_deref().and_then(|t| t.lines().find(|l| !l.trim().is_empty())).map(str::to_string))
        .map(|s| truncate_chars(s.trim(), 200))
        .unwrap_or_default();
    DepFinding {
        ecosystem: d.ecosystem,
        package: d.name.clone(),
        version: d.version.clone(),
        manifest: d.manifest.clone(),
        approximate: d.approximate,
        id: v.id.clone(),
        aliases: v.aliases.clone(),
        severity,
        summary,
        fixed: fixed_version(v, d),
        origin: "osv",
    }
}

/// Kurulu sürümden büyük en küçük "fixed" olayı.
fn fixed_version(v: &Vuln, d: &Dependency) -> Option<String> {
    let cur = Version::parse(&d.version)?;
    let mut best: Option<(Version, String)> = None;
    for a in &v.affected {
        if let Some(p) = &a.package {
            if !p.name.eq_ignore_ascii_case(&d.name) || p.ecosystem != d.ecosystem.osv_name() {
                continue;
            }
        }
        for r in a.ranges.iter().filter(|r| r.kind != "GIT") {
            for f in r.events.iter().filter_map(|e| e.get("fixed")).filter_map(Value::as_str) {
                if let Some(fv) = Version::parse(f) {
                    if fv > cur && best.as_ref().is_none_or(|(b, _)| fv < *b) {
                        best = Some((fv, f.to_string()));
                    }
                }
            }
        }
    }
    best.map(|(_, s)| s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::Ecosystem;
    use std::path::PathBuf;

    const GHSA: &str = r#"{
      "id": "GHSA-fv66-9v8q-g76r",
      "summary": "React Server Components RCE",
      "aliases": ["CVE-2025-55182"],
      "database_specific": {"severity": "CRITICAL"},
      "affected": [
        {"package": {"name": "react-server-dom-webpack", "ecosystem": "npm"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "19.0.0"}, {"fixed": "19.0.1"}]},
                    {"type": "SEMVER", "events": [{"introduced": "19.1.0"}, {"fixed": "19.1.2"}]}]},
        {"package": {"name": "other", "ecosystem": "npm"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "19.0.0-beta"}]}]}
      ]
    }"#;

    #[test]
    fn maps_osv_record_to_finding() {
        let v: Vuln = serde_json::from_str(GHSA).unwrap();
        let d = Dependency {
            ecosystem: Ecosystem::Npm,
            name: "react-server-dom-webpack".into(),
            version: "19.1.0".into(),
            manifest: PathBuf::from("package-lock.json"),
            approximate: false,
        };
        let f = to_finding(&d, &v);
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.fixed.as_deref(), Some("19.1.2"));
        assert_eq!(f.aliases, vec!["CVE-2025-55182".to_string()]);
    }

    #[test]
    fn rejects_path_like_ids() {
        assert!(valid_id("GHSA-fv66-9v8q-g76r"));
        assert!(valid_id("RUSTSEC-2024-0001"));
        assert!(!valid_id("../admin"));
        assert!(!valid_id("a/b"));
    }
}
