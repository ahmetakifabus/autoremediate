//! 3b) Döngü ve Doğrulama Mekanizması
//!
//! Akış:  tara → (bulgu yok?) → LLM'den yama al → uygula → YENİDEN TARA
//!        → gerileme/salınım var mı? → evet: geri al, hata say → devam
//!
//! Sonlanma garantileri (sonsuz döngü yok):
//!  * `max_iterations` üst sınırı
//!  * art arda `max_consecutive_failures` başarısız deneme
//!  * aynı dosya içeriği ikinci kez görülürse (salınım) → Stalled

use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::path::Path;

use tracing::{info, warn};

use crate::ai::{PatchProvider, PatchRequest};
use crate::error::{Error, Result};
use crate::patcher::Patcher;
use crate::scanner::{Finding, Lang, Scanner};

pub struct Config {
    pub max_iterations: u32,
    pub max_file_bytes: u64,
    pub max_consecutive_failures: u32,
    pub dry_run: bool,
}

#[derive(Debug)]
pub enum Outcome {
    /// "Sistemde açık kalmadı". `suppressed`: yorumla bastırılmış bulgular
    /// (LLM'in eklediği bastırmalar dahil) — insan incelemesi gerekir.
    Clean { iterations: u32, suppressed: Vec<Finding> },
    /// İterasyon sınırına ulaşıldı, açıklar sürüyor
    Exhausted { remaining: Vec<Finding> },
    /// İlerleme durdu (art arda hata / salınım)
    Stalled { remaining: Vec<Finding>, reason: String },
    /// Sadece öneri üretildi, dosyaya dokunulmadı
    DryRun { explanation: String, findings: usize },
}

pub struct Orchestrator<P: PatchProvider> {
    scanner: Scanner,
    provider: P,
    patcher: Patcher,
    cfg: Config,
}

fn content_hash(s: &str) -> u64 {
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

impl<P: PatchProvider> Orchestrator<P> {
    pub fn new(scanner: Scanner, provider: P, patcher: Patcher, cfg: Config) -> Self {
        Self { scanner, provider, patcher, cfg }
    }

    pub fn scanner(&self) -> &Scanner {
        &self.scanner
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn patcher(&self) -> &Patcher {
        &self.patcher
    }

    async fn read_source(&self, path: &Path) -> Result<String> {
        let meta = tokio::fs::symlink_metadata(path).await.map_err(|e| Error::io(path, e))?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(Error::Config(format!("{} düzgün bir dosya değil", path.display())));
        }
        if meta.len() > self.cfg.max_file_bytes {
            return Err(Error::Config(format!(
                "{} çok büyük ({} bayt > {})",
                path.display(),
                meta.len(),
                self.cfg.max_file_bytes
            )));
        }
        tokio::fs::read_to_string(path).await.map_err(|e| Error::io(path, e))
    }

    pub async fn remediate(&self, path: &Path) -> Result<Outcome> {
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("bilinmeyen");
        let lang = Lang::from_path(path)
            .ok_or_else(|| Error::Config(format!("{} desteklenmeyen dosya türü", path.display())))?;
        let mut source = self.read_source(path).await?;
        let mut seen: HashSet<u64> = HashSet::from([content_hash(&source)]);
        let mut failures = 0u32;

        for iteration in 1..=self.cfg.max_iterations {
            let findings = self.scanner.scan(&source, lang);
            if findings.is_empty() {
                info!("Sistemde açık kalmadı ({file_name})");
                let suppressed = self.scanner.scan_full(&source, lang).suppressed;
                return Ok(Outcome::Clean { iterations: iteration - 1, suppressed });
            }
            if failures >= self.cfg.max_consecutive_failures {
                return Ok(Outcome::Stalled {
                    remaining: findings,
                    reason: format!("art arda {failures} başarısız deneme"),
                });
            }
            info!("[{file_name}] iterasyon {iteration}: {} açık", findings.len());

            let req = PatchRequest { file_name, language: lang.name(), source: &source, findings: &findings };
            let proposal = match self.provider.propose_patch(&req).await {
                Ok(p) => p,
                Err(e) => {
                    warn!("LLM yanıtı alınamadı: {e}");
                    failures += 1;
                    continue;
                }
            };

            if self.cfg.dry_run {
                return Ok(Outcome::DryRun {
                    explanation: proposal.explanation,
                    findings: findings.len(),
                });
            }

            if let Err(e) = self.patcher.apply(path, &source, &proposal.fixed_code).await {
                warn!("Yama uygulanamadı: {e}");
                failures += 1;
                continue;
            }

            // Doğrulama: yama sonrası YENİDEN tara. LLM'in "düzelttim" demesine güvenme.
            let after = self.scanner.scan(&proposal.fixed_code, lang);
            let hash = content_hash(&proposal.fixed_code);
            let regressed = after.len() > findings.len();
            let oscillating = seen.contains(&hash);

            if regressed || oscillating {
                warn!(
                    "Yama reddedildi ({}): {} → {} açık; geri alınıyor",
                    if regressed { "gerileme" } else { "salınım" },
                    findings.len(),
                    after.len()
                );
                self.patcher.rollback(path, &source).await?;
                failures += 1;
                continue;
            }

            seen.insert(hash);
            source = proposal.fixed_code;
            failures = 0;
            info!("Yama kabul edildi: {} → {} açık", findings.len(), after.len());
        }

        let result = self.scanner.scan_full(&source, lang);
        let remaining = result.findings;
        if remaining.is_empty() {
            info!("Sistemde açık kalmadı ({file_name})");
            Ok(Outcome::Clean { iterations: self.cfg.max_iterations, suppressed: result.suppressed })
        } else {
            Ok(Outcome::Exhausted { remaining })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::PatchProposal;

    /// http:// → https:// yapan sahte "LLM"
    struct Fixer;
    impl PatchProvider for Fixer {
        async fn propose_patch(&self, req: &PatchRequest<'_>) -> Result<PatchProposal> {
            Ok(PatchProposal {
                explanation: "https".into(),
                fixed_code: req.source.replace("http://", "https://"),
            })
        }
    }

    /// Hiçbir şeyi düzeltmeyen sahte LLM
    struct Noop;
    impl PatchProvider for Noop {
        async fn propose_patch(&self, req: &PatchRequest<'_>) -> Result<PatchProposal> {
            Ok(PatchProposal { explanation: String::new(), fixed_code: req.source.to_string() })
        }
    }

    /// Yeni açık ekleyen (gerileme yaratan) sahte LLM
    struct Regress;
    impl PatchProvider for Regress {
        async fn propose_patch(&self, req: &PatchRequest<'_>) -> Result<PatchProposal> {
            Ok(PatchProposal {
                explanation: String::new(),
                fixed_code: format!("{}let v = \"http://kotu.example\";\n", req.source),
            })
        }
    }

    const VULN: &str = "fn main() {\n    let u = \"http://example.com/a\";\n    println!(\"{u}\");\n}\n";

    fn cfg() -> Config {
        Config { max_iterations: 5, max_file_bytes: 1 << 20, max_consecutive_failures: 2, dry_run: false }
    }

    fn temp_file(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("autofix_{}_{tag}.rs", std::process::id()));
        std::fs::write(&p, VULN).unwrap();
        p
    }

    fn cleanup(p: &Path) {
        let _ = std::fs::remove_file(p);
        let mut n = p.file_name().unwrap().to_os_string();
        n.push(".autofix.orig");
        let _ = std::fs::remove_file(p.with_file_name(n));
    }

    #[tokio::test]
    async fn loop_converges_to_clean() {
        let p = temp_file("clean");
        let o = Orchestrator::new(Scanner::new().unwrap(), Fixer, Patcher::new(None, None), cfg());
        let out = o.remediate(&p).await.unwrap();
        assert!(matches!(out, Outcome::Clean { iterations: 1, .. }), "{out:?}");
        assert!(std::fs::read_to_string(&p).unwrap().contains("https://"));
        cleanup(&p);
    }

    #[tokio::test]
    async fn useless_patches_stall() {
        let p = temp_file("noop");
        let o = Orchestrator::new(Scanner::new().unwrap(), Noop, Patcher::new(None, None), cfg());
        let out = o.remediate(&p).await.unwrap();
        assert!(matches!(out, Outcome::Stalled { .. }), "{out:?}");
        cleanup(&p);
    }

    #[tokio::test]
    async fn regression_is_rolled_back() {
        let p = temp_file("regress");
        let o = Orchestrator::new(Scanner::new().unwrap(), Regress, Patcher::new(None, None), cfg());
        let out = o.remediate(&p).await.unwrap();
        assert!(matches!(out, Outcome::Stalled { .. }), "{out:?}");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), VULN, "dosya orijinaline dönmeli");
        cleanup(&p);
    }
}
