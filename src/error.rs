use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O hatası ({path}): {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("HTTP hatası: {0}")]
    Http(#[from] reqwest::Error),
    #[error("{0}")]
    Config(String),
    #[error("Uzak servis hatası: {0}")]
    Remote(String),
    #[error("Yama reddedildi: {0}")]
    PatchRejected(String),
    #[error("Doğrulama başarısız: {0}")]
    Validation(String),
}

impl Error {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io { path: path.into(), source }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
