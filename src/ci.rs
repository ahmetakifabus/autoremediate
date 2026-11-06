//! 8) Bekçi: her push'ta, her PR'da ve her hafta binayı kendiliğinden kontrol
//! eden GitHub Actions iş akışı (`--init-ci`).

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

pub const WORKFLOW_PATH: &str = ".github/workflows/autoremediate.yml";

pub const WORKFLOW: &str = r#"# autoremediate bekçisi: her push'ta, her PR'da ve her pazartesi binayı kontrol eder.
# Kırık duvar, eksik kamera, kilitsiz kapı ya da çürük malzeme bulunursa iş başarısız olur
# ve bulgular GitHub > Security > Code scanning sekmesinde görünür.
#
# Kurulum (bir kez):
#   1. autoremediate deposu gizliyse, o depoyu okuyabilen bir token oluşturun
#      (GitHub > Settings > Developer settings > Fine-grained token, "Contents: Read-only")
#      ve bu depoya AUTOREMEDIATE_TOKEN adıyla secret olarak ekleyin.
#   2. Gizli depolarda Code scanning için GitHub Advanced Security gerekir; yoksa
#      SARIF yükleme adımı atlanır ama tarama ve HTML rapor yine çalışır.
name: autoremediate bekçi

on:
  push:
  pull_request:
  schedule:
    - cron: "0 6 * * 1" # haftalık: yeni yayımlanan açıklar (React2Shell gibi) için
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  bekci:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: autoremediate'i indir
        env:
          GH_TOKEN: ${{ secrets.AUTOREMEDIATE_TOKEN || github.token }}
        run: |
          gh release download --repo ahmetakifabus/autoremediate \
            --pattern 'autoremediate-linux-x86_64' --output autoremediate --clobber
          chmod +x autoremediate

      - name: Binayı kontrol et
        run: ./autoremediate . --scan-only --osv --sarif autoremediate.sarif --html autoremediate-rapor.html

      - name: Bulguları Security sekmesine yükle
        if: always() && hashFiles('autoremediate.sarif') != ''
        continue-on-error: true
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: autoremediate.sarif
          category: autoremediate

      - name: HTML raporu sakla
        if: always() && hashFiles('autoremediate-rapor.html') != ''
        uses: actions/upload-artifact@v4
        with:
          name: autoremediate-rapor
          path: autoremediate-rapor.html
"#;

/// İş akışını proje köküne yazar; varsa üzerine yazmaz.
pub fn init(root: &Path) -> Result<PathBuf> {
    let path = root.join(WORKFLOW_PATH);
    if path.exists() {
        return Err(Error::Config(format!("{} zaten var; üzerine yazılmadı", path.display())));
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| Error::io(dir, e))?;
    }
    std::fs::write(&path, WORKFLOW).map_err(|e| Error::io(&path, e))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_writes_once() {
        let root = std::env::temp_dir().join(format!("autofix_ci_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let p = init(&root).unwrap();
        assert!(std::fs::read_to_string(&p).unwrap().contains("--sarif autoremediate.sarif"));
        assert!(init(&root).is_err(), "var olan iş akışının üzerine yazılmamalı");
        let _ = std::fs::remove_dir_all(&root);
    }
}
