//! 6) Çürük malzemeyi değiştirme: savunmasız bağımlılıkların otomatik yükseltilmesi
//!
//! Akış (her proje dizini / ekosistem için ayrı):
//!   yedek al (manifest + kilit dosyası) → paket yöneticisiyle yükselt →
//!   kilit dosyasını yeniden oku → açık hâlâ duruyor mu? → (varsa) doğrulama
//!   komutu (testler) → başarısızsa dosyaları geri yükle.
//!
//! Doğrudan bağımlılık değilse (ör. `next` içinden gelen `react-server-dom-webpack`)
//! npm `overrides` / yarn `resolutions` / pnpm `pnpm.overrides` ile sabitlenir.
//! Komutlar kabuk OLMADAN çalıştırılır.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;
use tracing::{info, warn};

use crate::deps::{self, DepFinding, Ecosystem};
use crate::error::{Error, Result};
use crate::util::{command, truncate_chars};

const CMD_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug, Default)]
pub struct UpgradeReport {
    /// (dizin, "paket@sürüm")
    pub upgraded: Vec<(PathBuf, String)>,
    /// (dizin, neden)
    pub failed: Vec<(PathBuf, String)>,
    /// dry-run'da çalıştırılacak adımlar
    pub planned: Vec<(PathBuf, String)>,
}

/// Bir dizindeki yükseltme işi
struct Job {
    dir: PathBuf,
    eco: Ecosystem,
    upgrades: Vec<(String, String)>,
    manifests: Vec<PathBuf>,
}

fn jobs(findings: &[DepFinding]) -> Vec<Job> {
    let mut by_dir: BTreeMap<(PathBuf, Ecosystem), Vec<DepFinding>> = BTreeMap::new();
    for f in findings.iter().filter(|f| f.fixed.is_some()) {
        let dir = f.manifest.parent().map(Path::to_path_buf).unwrap_or_default();
        by_dir.entry((dir, f.ecosystem)).or_default().push(f.clone());
    }
    by_dir
        .into_iter()
        .map(|((dir, eco), list)| {
            let mut manifests: Vec<PathBuf> = list.iter().map(|f| f.manifest.clone()).collect();
            manifests.sort();
            manifests.dedup();
            let upgrades = deps::recommendations(&list).into_iter().map(|(_, p, v)| (p, v)).collect();
            Job { dir, eco, upgrades, manifests }
        })
        .collect()
}

/// Değişebilecek dosyalar (geri yükleme için)
fn touched_files(dir: &Path, eco: Ecosystem) -> Vec<PathBuf> {
    let names: &[&str] = match eco {
        Ecosystem::Npm => &["package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"],
        Ecosystem::Packagist => &["composer.json", "composer.lock"],
        Ecosystem::Crates => &["Cargo.toml", "Cargo.lock"],
        Ecosystem::PyPI => &["requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile", "Pipfile.lock"],
        Ecosystem::Go => &["go.mod", "go.sum"],
    };
    names.iter().map(|n| dir.join(n)).collect()
}

struct Backup(Vec<(PathBuf, Option<Vec<u8>>)>);

impl Backup {
    fn take(files: Vec<PathBuf>) -> Self {
        Backup(files.into_iter().map(|p| { let data = std::fs::read(&p).ok(); (p, data) }).collect())
    }
    fn restore(&self) {
        for (p, data) in &self.0 {
            let r = match data {
                Some(d) => std::fs::write(p, d),
                None => match std::fs::remove_file(p) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    other => other,
                },
            };
            if let Err(e) = r {
                warn!("{} geri yüklenemedi: {e}", p.display());
            }
        }
    }
}

/// Program + argümanlar; kabuk yok, zaman aşımlı.
async fn run(dir: &Path, argv: &[String]) -> Result<()> {
    let (prog, args) = argv.split_first().ok_or_else(|| Error::Config("boş komut".into()))?;
    info!("{} $ {}", dir.display(), argv.join(" "));
    let mut c = command(prog);
    c.args(args).current_dir(dir).kill_on_drop(true);
    let out = tokio::time::timeout(CMD_TIMEOUT, c.output())
        .await
        .map_err(|_| Error::Validation(format!("{prog} zaman aşımına uğradı")))?
        .map_err(|e| Error::io(prog, e))?;
    if out.status.success() {
        Ok(())
    } else {
        let mut msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if msg.is_empty() {
            msg = String::from_utf8_lossy(&out.stdout).trim().to_string();
        }
        Err(Error::Validation(format!("{prog}: {}", truncate_chars(&msg, 400))))
    }
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

/// npm/yarn/pnpm: doğrudan bağımlılıklar `install pkg@ver`, dolaylılar override ile.
fn npm_plan(dir: &Path, upgrades: &[(String, String)]) -> Result<(Vec<Vec<String>>, Option<Value>)> {
    let pj_path = dir.join("package.json");
    let text = std::fs::read_to_string(&pj_path).map_err(|e| Error::io(&pj_path, e))?;
    let mut pj: Value = serde_json::from_str(&text).map_err(|e| Error::Config(format!("{}: {e}", pj_path.display())))?;
    let direct = |name: &str| {
        ["dependencies", "devDependencies", "optionalDependencies"]
            .iter()
            .any(|s| pj.get(s).and_then(|m| m.get(name)).is_some())
    };
    let pm = if dir.join("pnpm-lock.yaml").exists() {
        "pnpm"
    } else if dir.join("yarn.lock").exists() {
        "yarn"
    } else {
        "npm"
    };
    let (direct_ups, indirect): (Vec<_>, Vec<_>) = upgrades.iter().partition(|(p, _)| direct(p));

    let mut cmds = Vec::new();
    let mut new_pj = None;
    if !indirect.is_empty() {
        let obj = pj.as_object_mut().ok_or_else(|| Error::Config("package.json bir nesne değil".into()))?;
        let slot = match pm {
            "yarn" => obj.entry("resolutions").or_insert_with(|| Value::Object(Default::default())),
            "pnpm" => obj
                .entry("pnpm")
                .or_insert_with(|| Value::Object(Default::default()))
                .as_object_mut()
                .ok_or_else(|| Error::Config("package.json 'pnpm' alanı nesne değil".into()))?
                .entry("overrides")
                .or_insert_with(|| Value::Object(Default::default())),
            _ => obj.entry("overrides").or_insert_with(|| Value::Object(Default::default())),
        };
        let map = slot.as_object_mut().ok_or_else(|| Error::Config("override alanı nesne değil".into()))?;
        for (p, v) in &indirect {
            map.insert(p.clone(), Value::String(v.clone()));
        }
        new_pj = Some(pj.clone());
    }
    let specs: Vec<String> = direct_ups.iter().map(|(p, v)| format!("{p}@{v}")).collect();
    match (pm, specs.is_empty()) {
        ("npm", false) => cmds.push([s(&["npm", "install"]), specs].concat()),
        ("yarn", false) => cmds.push([s(&["yarn", "add"]), specs].concat()),
        ("pnpm", false) => cmds.push([s(&["pnpm", "add"]), specs].concat()),
        _ => {}
    }
    // `install pkg@ver` override'ları da uygular; yalnızca override varsa düz install yeterli
    if cmds.is_empty() {
        cmds.push(s(&[pm, "install"]));
    }
    Ok((cmds, new_pj))
}

/// requirements.txt içinde `paket==eski` → `paket==yeni` (deterministik metin düzenleme)
fn bump_requirements(text: &str, upgrades: &[(String, String)]) -> String {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let mut l = line.to_string();
        if let Some((name, _)) = line.split_once("==") {
            let key = name.split('[').next().unwrap_or("").trim().to_ascii_lowercase().replace('_', "-");
            if let Some((_, v)) = upgrades.iter().find(|(p, _)| p.to_ascii_lowercase().replace('_', "-") == key) {
                let comment = line.find(['#', ';']).map(|i| format!(" {}", &line[i..])).unwrap_or_default();
                l = format!("{}=={v}{comment}", name.trim_end());
            }
        }
        out.push(l);
    }
    let mut s = out.join("\n");
    if text.ends_with('\n') {
        s.push('\n');
    }
    s
}

/// Yükseltme adımları; dosya düzenlemeleri `edits` olarak döner.
fn plan(job: &Job) -> Result<(Vec<Vec<String>>, Vec<(PathBuf, String)>)> {
    let ups = &job.upgrades;
    let mut edits = Vec::new();
    let cmds = match job.eco {
        Ecosystem::Npm => {
            let (cmds, pj) = npm_plan(&job.dir, ups)?;
            if let Some(pj) = pj {
                let text = serde_json::to_string_pretty(&pj).map_err(|e| Error::Config(e.to_string()))? + "\n";
                edits.push((job.dir.join("package.json"), text));
            }
            cmds
        }
        Ecosystem::Packagist => {
            let mut c = s(&["composer", "update", "--with-all-dependencies"]);
            c.extend(ups.iter().map(|(p, _)| p.clone()));
            let mut req = s(&["composer", "require", "--update-with-all-dependencies"]);
            req.extend(ups.iter().map(|(p, v)| format!("{p}:^{v}")));
            // Önce doğrudan gereksinim olarak yükseltmeyi dene; dolaylıysa update yeterli olur.
            if job.dir.join("composer.json").is_file() { vec![req] } else { vec![c] }
        }
        Ecosystem::Crates => ups
            .iter()
            .map(|(p, v)| s(&["cargo", "update", "-p", p, "--precise", v]))
            .collect(),
        Ecosystem::Go => {
            let mut c: Vec<Vec<String>> = ups.iter().map(|(p, v)| vec!["go".into(), "get".into(), format!("{p}@v{v}")]).collect();
            c.push(s(&["go", "mod", "tidy"]));
            c
        }
        Ecosystem::PyPI => {
            let req = job.dir.join("requirements.txt");
            if job.manifests.iter().any(|m| m.ends_with("requirements.txt")) {
                let text = std::fs::read_to_string(&req).map_err(|e| Error::io(&req, e))?;
                edits.push((req, bump_requirements(&text, ups)));
                Vec::new()
            } else if job.dir.join("poetry.lock").is_file() {
                let mut c = s(&["poetry", "add"]);
                c.extend(ups.iter().map(|(p, v)| format!("{p}@^{v}")));
                vec![c]
            } else {
                let mut c = s(&["pipenv", "install"]);
                c.extend(ups.iter().map(|(p, v)| format!("{p}=={v}")));
                vec![c]
            }
        }
    };
    Ok((cmds, edits))
}

/// Yükseltmeden sonra açık hâlâ duruyor mu? (yerleşik tablo ile yeniden denetim)
fn still_vulnerable(job: &Job) -> Vec<String> {
    let deps = deps::load(&job.manifests);
    deps::check_builtin(&deps)
        .into_iter()
        .filter(|f| job.upgrades.iter().any(|(p, _)| p == &f.package))
        .map(|f| format!("{}@{} ({})", f.package, f.version, f.id))
        .collect()
}

pub async fn apply(findings: &[DepFinding], validate: Option<&[String]>, dry_run: bool) -> UpgradeReport {
    let mut report = UpgradeReport::default();
    for job in jobs(findings) {
        let (cmds, edits) = match plan(&job) {
            Ok(p) => p,
            Err(e) => {
                report.failed.push((job.dir.clone(), e.to_string()));
                continue;
            }
        };
        if dry_run {
            for (p, _) in &edits {
                report.planned.push((job.dir.clone(), format!("{} güncellenir", p.display())));
            }
            for c in &cmds {
                report.planned.push((job.dir.clone(), c.join(" ")));
            }
            continue;
        }
        let backup = Backup::take(touched_files(&job.dir, job.eco));
        let result: Result<()> = async {
            for (p, text) in &edits {
                std::fs::write(p, text).map_err(|e| Error::io(p, e))?;
            }
            for c in &cmds {
                run(&job.dir, c).await?;
            }
            let left = still_vulnerable(&job);
            if !left.is_empty() {
                return Err(Error::Validation(format!("yükseltmeden sonra hâlâ savunmasız: {}", left.join(", "))));
            }
            if let Some(v) = validate {
                run(&job.dir, v).await?;
            }
            Ok(())
        }
        .await;
        match result {
            Ok(()) => {
                for (p, v) in &job.upgrades {
                    report.upgraded.push((job.dir.clone(), format!("{p}@{v}")));
                }
            }
            Err(e) => {
                backup.restore();
                report.failed.push((job.dir.clone(), format!("{e} — dosyalar geri yüklendi")));
            }
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requirements_are_bumped_in_place() {
        let t = "Flask==2.2.0  # web\nrequests[socks]==2.19.0\nnumpy>=1\n";
        let ups = vec![("flask".to_string(), "2.3.2".to_string()), ("requests".to_string(), "2.32.0".to_string())];
        assert_eq!(bump_requirements(t, &ups), "Flask==2.3.2 #  web\nrequests[socks]==2.32.0\nnumpy>=1\n".replace("#  web", "# web"));
    }

    #[test]
    fn npm_direct_and_transitive_upgrades() {
        let dir = std::env::temp_dir().join(format!("autofix_up_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("package.json"), r#"{"name":"x","dependencies":{"next":"15.1.0"}}"#).unwrap();
        std::fs::write(dir.join("package-lock.json"), "{}").unwrap();
        let ups = vec![("next".to_string(), "15.1.11".to_string()), ("react-server-dom-webpack".to_string(), "19.0.3".to_string())];
        let (cmds, pj) = npm_plan(&dir, &ups).unwrap();
        assert_eq!(cmds[0], s(&["npm", "install", "next@15.1.11"]));
        let pj = pj.unwrap();
        assert_eq!(pj["overrides"]["react-server-dom-webpack"], "19.0.3");
        // Alan sırası korunur (preserve_order)
        assert_eq!(pj.as_object().unwrap().keys().next().unwrap(), "name");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
