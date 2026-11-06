//! 3a) Yama uygulama: sağlık kontrolü → yedek → atomik yazma → (opsiyonel)
//! harici doğrulama → hata halinde geri alma (rollback).

use std::path::{Path, PathBuf};
use std::time::Duration;

use tracing::info;

use crate::error::{Error, Result};
use crate::util::truncate_chars;

pub struct Patcher {
    /// Örn. ["cargo", "check", "--quiet"]. Kabuk KULLANILMAZ; doğrudan exec.
    validate_cmd: Option<Vec<String>>,
    validate_dir: Option<PathBuf>,
}

impl Patcher {
    pub fn new(validate_cmd: Option<Vec<String>>, validate_dir: Option<PathBuf>) -> Self {
        Self { validate_cmd, validate_dir }
    }

    /// LLM çıktısı güvenilmez: açıkça saçma yamaları diske yazmadan eler.
    fn sanity_check(original: &str, proposed: &str) -> Result<()> {
        if proposed.trim().is_empty() {
            return Err(Error::PatchRejected("boş çıktı".into()));
        }
        if proposed == original {
            return Err(Error::PatchRejected("yama hiçbir değişiklik içermiyor".into()));
        }
        if proposed.contains('\0') {
            return Err(Error::PatchRejected("NUL baytı içeriyor".into()));
        }
        let (old, new) = (original.len(), proposed.len());
        if new * 100 < old * 40 {
            return Err(Error::PatchRejected("dosya %60'tan fazla küçüldü (kesik çıktı şüphesi)".into()));
        }
        if new > old * 3 + 4096 {
            return Err(Error::PatchRejected("dosya anormal büyüdü".into()));
        }
        Ok(())
    }

    pub async fn apply(&self, path: &Path, original: &str, proposed: &str) -> Result<()> {
        Self::sanity_check(original, proposed)?;
        self.backup_once(path, original).await?;
        write_atomic(path, proposed).await?;

        if let Err(e) = self.run_validator().await {
            self.rollback(path, original).await?;
            return Err(e);
        }
        info!("Yama uygulandı: {}", path.display());
        Ok(())
    }

    pub async fn rollback(&self, path: &Path, original: &str) -> Result<()> {
        write_atomic(path, original).await?;
        info!("Geri alındı: {}", path.display());
        Ok(())
    }

    /// İlk değişiklikten önce <dosya>.autofix.orig yedeği (çökme durumuna karşı).
    async fn backup_once(&self, path: &Path, original: &str) -> Result<()> {
        let mut name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
        name.push(".autofix.orig");
        let backup = path.with_file_name(name);
        let exists = tokio::fs::try_exists(&backup).await.map_err(|e| Error::io(&backup, e))?;
        if !exists {
            tokio::fs::write(&backup, original).await.map_err(|e| Error::io(&backup, e))?;
        }
        Ok(())
    }

    async fn run_validator(&self) -> Result<()> {
        let Some(cmd) = &self.validate_cmd else { return Ok(()) };
        let (prog, args) = cmd
            .split_first()
            .ok_or_else(|| Error::Config("boş doğrulama komutu".into()))?;
        let mut c = crate::util::command(prog);
        c.args(args).kill_on_drop(true);
        if let Some(dir) = &self.validate_dir {
            c.current_dir(dir);
        }
        let out = tokio::time::timeout(Duration::from_secs(180), c.output())
            .await
            .map_err(|_| Error::Validation("doğrulama komutu zaman aşımına uğradı".into()))?
            .map_err(|e| Error::io(prog, e))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(Error::Validation(truncate_chars(&String::from_utf8_lossy(&out.stderr), 500)))
        }
    }
}

/// Geçici dosyaya yaz + rename: yarım yazılmış dosya asla görünmez.
async fn write_atomic(path: &Path, data: &str) -> Result<()> {
    let mut name = std::ffi::OsString::from(".");
    name.push(path.file_name().unwrap_or_default());
    name.push(".autofix.tmp");
    let tmp = path.with_file_name(name);

    let result = async {
        tokio::fs::write(&tmp, data).await?;
        if let Ok(meta) = tokio::fs::metadata(path).await {
            tokio::fs::set_permissions(&tmp, meta.permissions()).await?;
        }
        tokio::fs::rename(&tmp, path).await
    }
    .await;

    if let Err(e) = result {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(Error::io(path, e));
    }
    Ok(())
}
