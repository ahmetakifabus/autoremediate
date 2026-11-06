//! 7) Rapor çıktıları: güvenlik puanı, JSON, SARIF (GitHub Security sekmesi) ve
//! tek dosyalık HTML rapor.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::controls::ControlFinding;
use crate::deps::{self, DepFinding};
use crate::recon::SiteReport;
use crate::scanner::{Finding, Severity};

pub struct Report<'a> {
    pub root: &'a Path,
    pub site: Option<&'a SiteReport>,
    pub walls: &'a [(PathBuf, Finding)],
    pub suppressed: &'a [(PathBuf, Finding)],
    pub cameras: &'a [ControlFinding],
    pub deps: &'a [DepFinding],
}

/// Kamera bulgularının hangi bölüme ait olduğu
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Part {
    Cameras,
    Locks,
    Infra,
}

pub fn part_of(c: &ControlFinding) -> Part {
    if c.id.starts_with("CAM5") {
        Part::Locks
    } else if c.id.starts_with("CAM6") {
        Part::Infra
    } else {
        Part::Cameras
    }
}

fn weight(s: Severity) -> u32 {
    match s {
        Severity::Critical => 20,
        Severity::High => 8,
        Severity::Medium => 3,
        Severity::Low => 1,
    }
}

impl Report<'_> {
    fn severities(&self) -> Vec<Severity> {
        let mut v: Vec<Severity> = Vec::new();
        if let Some(s) = self.site {
            v.extend(s.findings.iter().map(|f| f.severity));
        }
        v.extend(self.walls.iter().map(|(_, f)| f.severity));
        v.extend(self.cameras.iter().map(|c| c.severity));
        v.extend(self.deps.iter().map(|d| d.severity));
        v
    }

    /// 0–100 güvenlik puanı ve harf notu. Kritik bir açık varken not en fazla D'dir.
    pub fn score(&self) -> (u32, char) {
        let sev = self.severities();
        let penalty: u32 = sev.iter().map(|s| weight(*s)).sum();
        let mut score = (100.0 / (1.0 + f64::from(penalty) / 25.0)).round() as u32;
        if sev.contains(&Severity::Critical) {
            score = score.min(49);
        }
        let grade = match score {
            90.. => 'A',
            75..=89 => 'B',
            60..=74 => 'C',
            40..=59 => 'D',
            _ => 'F',
        };
        (score, grade)
    }

    pub fn has_findings(&self) -> bool {
        !self.severities().is_empty()
    }

    fn rel(&self, p: &Path) -> String {
        p.strip_prefix(self.root).unwrap_or(p).to_string_lossy().replace('\\', "/")
    }

    pub fn to_json(&self) -> Value {
        let row = |(f, x): &(PathBuf, Finding)| {
            json!({
                "file": f, "line": x.line, "rule_id": x.rule_id, "severity": x.severity,
                "description": x.description, "snippet": x.snippet,
            })
        };
        let upgrades: Vec<_> = deps::recommendations(self.deps)
            .into_iter()
            .map(|(e, p, v)| json!({"ecosystem": e, "package": p, "version": v}))
            .collect();
        let pick = |part: Part| self.cameras.iter().filter(|c| part_of(c) == part).collect::<Vec<_>>();
        let (score, grade) = self.score();
        json!({
            "score": score,
            "grade": grade.to_string(),
            "site": self.site.map(|s| json!({"url": s.url, "technology": s.tech, "findings": s.findings})),
            "code_findings": self.walls.iter().map(row).collect::<Vec<_>>(),
            "suppressed": self.suppressed.iter().map(row).collect::<Vec<_>>(),
            "missing_defenses": pick(Part::Cameras),
            "unlocked_doors": pick(Part::Locks),
            "infrastructure": pick(Part::Infra),
            "dependency_findings": self.deps,
            "upgrades": upgrades,
        })
    }

    /// SARIF 2.1.0 — GitHub Code Scanning (`upload-sarif`) ile Security sekmesinde görünür.
    pub fn to_sarif(&self) -> Value {
        let level = |s: Severity| match s {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low => "note",
        };
        let score = |s: Severity| match s {
            Severity::Critical => "9.5",
            Severity::High => "7.5",
            Severity::Medium => "5.0",
            Severity::Low => "2.0",
        };
        let mut rules: Vec<Value> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut results: Vec<Value> = Vec::new();
        let mut add = |id: &str, sev: Severity, title: &str, msg: String, uri: String, line: usize| {
            if seen.insert(id.to_string()) {
                rules.push(json!({
                    "id": id,
                    "shortDescription": {"text": title},
                    "defaultConfiguration": {"level": level(sev)},
                    "properties": {"security-severity": score(sev), "tags": ["security"]},
                }));
            }
            results.push(json!({
                "ruleId": id,
                "level": level(sev),
                "message": {"text": msg},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line.max(1)},
                }}],
            }));
        };
        for (f, x) in self.walls {
            add(x.rule_id, x.severity, x.description, format!("{} ({})", x.description, x.rule_id), self.rel(f), x.line);
        }
        for c in self.cameras {
            let mut msg = format!("{} — {} Çözüm: {}", c.title, c.why, c.how_to_fix);
            if !c.detail.is_empty() {
                msg = format!("{msg} [{}]", c.detail);
            }
            add(c.id, c.severity, c.title, msg, self.rel(&c.location), 1);
        }
        for d in self.deps {
            let fix = d.fixed.as_deref().map(|v| format!(" Düzeltilmiş sürüm: {v}.")).unwrap_or_default();
            add(&d.id, d.severity, &d.summary, format!("{}@{}: {}{fix}", d.package, d.version, d.summary), self.rel(&d.manifest), 1);
        }
        json!({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "autoremediate",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/ahmetakifabus/autoremediate",
                    "rules": rules,
                }},
                "results": results,
            }],
        })
    }

    pub fn to_html(&self) -> String {
        let (score, grade) = self.score();
        let color = match grade {
            'A' => "#1a7f37",
            'B' => "#4d8f1f",
            'C' => "#b08800",
            'D' => "#d1580f",
            _ => "#cf222e",
        };
        let site_n = self.site.map_or(0, |s| s.findings.len());
        let n = |p: Part| self.cameras.iter().filter(|c| part_of(c) == p).count();
        let cards = [
            ("Hırsızın gözü", "Dışarıdan görünen açıklar", site_n, self.site.is_some()),
            ("Kırık duvarlar", "Koddaki açıklar", self.walls.len(), true),
            ("Eksik kameralar", "Kurulmamış savunmalar", n(Part::Cameras), true),
            ("Kilitsiz kapılar", "Kimlik doğrulamasız hassas kapılar", n(Part::Locks), true),
            ("Çürük temel", "Sunucu ve çalışma ortamı", n(Part::Infra), true),
            ("Çürük malzeme", "Savunmasız bağımlılıklar", self.deps.len(), true),
        ];

        let mut h = String::new();
        let _ = write!(
            h,
            r#"<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>autoremediate raporu — {score}/100</title><style>
:root{{--bg:#fff;--fg:#1f2328;--mut:#59636e;--line:#d1d9e0;--card:#f6f8fa}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0d1117;--fg:#e6edf3;--mut:#9198a1;--line:#3d444d;--card:#151b23}}}}
*{{box-sizing:border-box}}body{{margin:0;font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--fg)}}
main{{max-width:1080px;margin:auto;padding:32px 20px}}h1{{margin:0 0 4px;font-size:26px}}h2{{margin:36px 0 10px;font-size:19px}}
.mut{{color:var(--mut)}}.top{{display:flex;gap:28px;align-items:center;flex-wrap:wrap}}
.ring{{width:132px;height:132px;border-radius:50%;display:grid;place-items:center;background:conic-gradient({color} {score}%,var(--line) 0)}}
.ring div{{width:108px;height:108px;border-radius:50%;background:var(--bg);display:grid;place-items:center;text-align:center}}
.ring b{{font-size:34px;line-height:1}}.grade{{font-size:14px;color:{color};font-weight:700}}
.cards{{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-top:24px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}}.card b{{font-size:28px;display:block}}
.ok b{{color:#1a7f37}}.bad b{{color:#cf222e}}.na b{{color:var(--mut)}}
table{{width:100%;border-collapse:collapse;font-size:14px}}th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--mut);font-weight:600}}code{{font-size:12.5px;word-break:break-all}}
.sev{{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;color:#fff}}
.Critical{{background:#8c1d18}}.High{{background:#cf222e}}.Medium{{background:#bf8700}}.Low{{background:#59636e}}
.empty{{color:#1a7f37}}footer{{margin-top:40px;font-size:13px}}
</style></head><body><main>
<div class="top"><div class="ring"><div><div><b>{score}</b><div class="grade">Not: {grade}</div></div></div></div>
<div><h1>Binanın güvenlik raporu</h1><div class="mut">{root}</div>{site}
<div class="mut">Hırsız binaya dışarıdan bakar; kırık duvar, eksik kamera ya da kilitsiz kapı görürse oradan girer.</div></div></div>
<div class="cards">"#,
            root = esc(&self.root.display().to_string()),
            site = self.site.map(|s| format!(r#"<div class="mut">Site: {}</div>"#, esc(&s.url))).unwrap_or_default(),
        );
        for (title, sub, count, active) in cards {
            let class = if !active { "na" } else if count == 0 { "ok" } else { "bad" };
            let shown = if active { count.to_string() } else { "–".into() };
            let _ = write!(h, r#"<div class="card {class}"><b>{shown}</b>{}<div class="mut">{}</div></div>"#, esc(title), esc(sub));
        }
        h.push_str("</div>");

        let sev = |s: Severity| format!(r#"<span class="sev {s}">{s}</span>"#);
        let empty = |h: &mut String, msg: &str| {
            let _ = write!(h, r#"<p class="empty">✔ {}</p>"#, esc(msg));
        };

        if let Some(s) = self.site {
            h.push_str("<h2>1) Hırsızın gözü — dışarıdan bakış</h2>");
            if s.findings.is_empty() {
                empty(&mut h, "Dışarıdan açık pencere ya da unutulmuş anahtar görünmüyor.");
            } else {
                h.push_str("<table><tr><th>Önem</th><th>Bulgu</th><th>Çözüm</th></tr>");
                for f in &s.findings {
                    let _ = write!(h, "<tr><td>{}</td><td><b>{}</b> {}<br><span class=mut>{}</span></td><td>{}</td></tr>",
                        sev(f.severity), f.id, esc(f.title), esc(&f.detail), esc(f.remedy));
                }
                h.push_str("</table>");
            }
        }

        h.push_str("<h2>2) Kırık duvarlar — koddaki açıklar</h2>");
        if self.walls.is_empty() {
            empty(&mut h, "Kırık duvar bulunmadı.");
        } else {
            h.push_str("<table><tr><th>Önem</th><th>Yer</th><th>Açık</th></tr>");
            for (f, x) in self.walls {
                let _ = write!(h, "<tr><td>{}</td><td><code>{}:{}</code></td><td><b>{}</b> {}<br><code class=mut>{}</code></td></tr>",
                    sev(x.severity), esc(&self.rel(f)), x.line, x.rule_id, esc(x.description), esc(&x.snippet));
            }
            h.push_str("</table>");
        }
        if !self.suppressed.is_empty() {
            let _ = write!(h, "<p class=mut>⚠ {} bulgu <code>autoremediate-ignore</code> ile bastırıldı; elle doğrulayın.</p>", self.suppressed.len());
        }

        for (part, title, ok) in [
            (Part::Cameras, "3) Eksik kameralar — kurulmamış savunmalar", "Bilinen temel savunmalar yerinde."),
            (Part::Locks, "4) Kilitsiz kapılar — kimlik doğrulaması olmayan hassas kapılar", "Kilitsiz hassas kapı bulunmadı."),
            (Part::Infra, "5) Çürük temel — sunucu ve çalışma ortamı", "Sunucu yapılandırmasında bilinen sorun bulunmadı."),
        ] {
            let _ = write!(h, "<h2>{}</h2>", esc(title));
            let list: Vec<&ControlFinding> = self.cameras.iter().filter(|c| part_of(c) == part).collect();
            if list.is_empty() {
                empty(&mut h, ok);
                continue;
            }
            h.push_str("<table><tr><th>Önem</th><th>Eksik</th><th>Neden önemli</th><th>Kurulum</th></tr>");
            for c in list {
                let detail = if c.detail.is_empty() { String::new() } else { format!("<br><span class=mut>{}</span>", esc(&c.detail)) };
                let _ = write!(h, "<tr><td>{}</td><td><b>{}</b> {}<br><code class=mut>{}</code>{detail}</td><td>{}</td><td>{}</td></tr>",
                    sev(c.severity), c.id, esc(c.title), esc(&self.rel(&c.location)), esc(c.why), esc(&c.how_to_fix));
            }
            h.push_str("</table>");
        }

        h.push_str("<h2>6) Çürük malzeme — savunmasız bağımlılıklar</h2>");
        if self.deps.is_empty() {
            empty(&mut h, "Bilinen savunmasız bağımlılık bulunmadı.");
        } else {
            h.push_str("<table><tr><th>Önem</th><th>Paket</th><th>Açık</th><th>Düzeltilmiş</th></tr>");
            for d in self.deps {
                let _ = write!(h, "<tr><td>{}</td><td><code>{}@{}</code><br><span class=mut>{}</span></td><td><b>{}</b> {}</td><td>{}</td></tr>",
                    sev(d.severity), esc(&d.package), esc(&d.version), esc(&self.rel(&d.manifest)), esc(&d.id), esc(&d.summary),
                    esc(d.fixed.as_deref().unwrap_or("–")));
            }
            h.push_str("</table>");
            let rec = deps::recommendations(self.deps);
            if !rec.is_empty() {
                h.push_str("<p><b>Önerilen yükseltmeler</b> (ya da <code>--fix-deps</code>):</p><pre>");
                for (e, p, v) in rec {
                    let _ = writeln!(h, "{}", esc(&e.upgrade_hint(&p, &v)));
                }
                h.push_str("</pre>");
            }
        }
        let _ = write!(
            h,
            r#"<footer class="mut">autoremediate {} · Bu rapor bilinen açık türlerini, eksik savunmaları ve bilinen savunmasız sürümleri kapsar; mantık hatalarını ve tüm yetki sorunlarını bulamaz.</footer></main></body></html>"#,
            env!("CARGO_PKG_VERSION")
        );
        h
    }
}

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            _ => o.push(c),
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(sev: Severity) -> Finding {
        Finding { rule_id: "JS001", severity: sev, line: 3, snippet: "<script>".into(), description: "test" }
    }

    #[test]
    fn score_and_grade() {
        let root = Path::new("/p");
        let empty = Report { root, site: None, walls: &[], suppressed: &[], cameras: &[], deps: &[] };
        assert_eq!(empty.score(), (100, 'A'));
        let walls = vec![(PathBuf::from("/p/a.js"), finding(Severity::Low))];
        let r = Report { root, site: None, walls: &walls, suppressed: &[], cameras: &[], deps: &[] };
        assert_eq!(r.score().1, 'A');
        let walls = vec![(PathBuf::from("/p/a.js"), finding(Severity::Critical))];
        let r = Report { root, site: None, walls: &walls, suppressed: &[], cameras: &[], deps: &[] };
        assert!(r.score().0 <= 49 && r.score().1 != 'A');
    }

    #[test]
    fn html_is_escaped_and_sarif_is_relative() {
        let root = Path::new("/p");
        let walls = vec![(PathBuf::from("/p/src/a.js"), finding(Severity::High))];
        let r = Report { root, site: None, walls: &walls, suppressed: &[], cameras: &[], deps: &[] };
        let html = r.to_html();
        assert!(html.contains("&lt;script&gt;") && !html.contains("<code class=mut><script>"));
        let sarif = r.to_sarif();
        assert_eq!(sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "src/a.js");
        assert_eq!(sarif["runs"][0]["results"][0]["level"], "error");
        assert_eq!(sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"], "7.5");
    }
}
