//! Google Gemini sağlayıcısı (generateContent REST API).
//!
//! Anahtar URL'ye DEĞİL `x-goog-api-key` başlığına konur; böylece proxy/log
//! kayıtlarında ve hata mesajlarında sızmaz.

use std::future::Future;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::ai::{
    build_user_prompt, parse_proposal, post_json_with_retry, PatchProposal, PatchProvider,
    PatchRequest, SYSTEM_PROMPT,
};
use crate::error::{Error, Result};

#[derive(Clone)]
pub struct GeminiConfig {
    api_key: String, // Debug türetilmedi: anahtar log'a sızmasın
    model: String,
    base_url: String,
    max_output_tokens: u32,
    timeout: Duration,
    max_retries: u32,
}

impl GeminiConfig {
    pub fn new(api_key: String, model: String, base_url: String) -> Result<Self> {
        if api_key.trim().is_empty() {
            return Err(Error::Config("Gemini API anahtarı boş".into()));
        }
        // Model adı URL yoluna girer: yol enjeksiyonunu engelle.
        let ok = !model.is_empty()
            && model.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
        if !ok {
            return Err(Error::Config(format!("geçersiz Gemini model adı: {model:?}")));
        }
        Ok(Self {
            api_key,
            model,
            base_url,
            max_output_tokens: 32_768,
            timeout: Duration::from_secs(180),
            max_retries: 4,
        })
    }

    /// GEMINI_API_KEY (zorunlu), GEMINI_MODEL (varsayılan gemini-3.8-flash),
    /// GEMINI_BASE_URL (opsiyonel; test/proxy için).
    pub fn from_env_with_model(model: Option<&str>) -> Result<Self> {
        let key = std::env::var("GEMINI_API_KEY")
            .map_err(|_| Error::Config("GEMINI_API_KEY ortam değişkeni tanımlı değil".into()))?;
        Self::new(
            key,
            model
                .map(String::from)
                .or_else(|| std::env::var("GEMINI_MODEL").ok())
                .unwrap_or_else(|| "gemini-3.8-flash".into()),
            std::env::var("GEMINI_BASE_URL")
                .unwrap_or_else(|_| "https://generativelanguage.googleapis.com".into()),
        )
    }

    pub fn model(&self) -> &str {
        &self.model
    }
}

pub struct GeminiClient {
    http: reqwest::Client,
    cfg: GeminiConfig,
}

// ---- İstek gövdesi -------------------------------------------------------

#[derive(Serialize)]
struct TextPart<'a> {
    text: &'a str,
}

#[derive(Serialize)]
struct SystemInstruction<'a> {
    parts: Vec<TextPart<'a>>,
}

#[derive(Serialize)]
struct UserContent<'a> {
    role: &'a str,
    parts: Vec<TextPart<'a>>,
}

#[derive(Serialize)]
struct GenerationConfig {
    #[serde(rename = "maxOutputTokens")]
    max_output_tokens: u32,
    temperature: f32,
}

#[derive(Serialize)]
struct GenerateRequest<'a> {
    #[serde(rename = "systemInstruction")]
    system_instruction: SystemInstruction<'a>,
    contents: Vec<UserContent<'a>>,
    #[serde(rename = "generationConfig")]
    generation_config: GenerationConfig,
}

// ---- Yanıt gövdesi -------------------------------------------------------

#[derive(Deserialize, Default)]
struct Part {
    #[serde(default)]
    text: Option<String>,
    /// Düşünce özeti parçaları kod değildir; atlanır.
    #[serde(default)]
    thought: Option<bool>,
}

#[derive(Deserialize, Default)]
struct Content {
    #[serde(default)]
    parts: Vec<Part>,
}

#[derive(Deserialize)]
struct Candidate {
    #[serde(default)]
    content: Option<Content>,
    #[serde(default, rename = "finishReason")]
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct PromptFeedback {
    #[serde(default, rename = "blockReason")]
    block_reason: Option<String>,
}

#[derive(Deserialize)]
struct GenerateResponse {
    #[serde(default)]
    candidates: Vec<Candidate>,
    #[serde(default, rename = "promptFeedback")]
    prompt_feedback: Option<PromptFeedback>,
}

/// Yanıttan düz metni çıkarır; engellenmiş/kesilmiş yanıtları hata sayar
/// (kesik kod asla yama olarak ilerlemesin).
fn extract_text(raw: &str) -> Result<String> {
    let resp: GenerateResponse = serde_json::from_str(raw)
        .map_err(|e| Error::Remote(format!("Gemini yanıtı çözümlenemedi: {e}")))?;

    let Some(cand) = resp.candidates.into_iter().next() else {
        let why = resp
            .prompt_feedback
            .and_then(|f| f.block_reason)
            .unwrap_or_else(|| "aday yanıt yok".into());
        return Err(Error::Remote(format!("Gemini yanıt üretmedi ({why})")));
    };

    let finish = cand.finish_reason.as_deref().unwrap_or("STOP");
    if finish == "MAX_TOKENS" {
        return Err(Error::Remote("Gemini yanıtı token sınırında kesildi".into()));
    }

    let text: String = cand
        .content
        .unwrap_or_default()
        .parts
        .iter()
        .filter(|p| p.thought != Some(true))
        .filter_map(|p| p.text.as_deref())
        .collect();

    if text.trim().is_empty() {
        return Err(Error::Remote(format!("Gemini boş yanıt döndürdü (finishReason={finish})")));
    }
    Ok(text)
}

impl GeminiClient {
    pub fn new(cfg: GeminiConfig) -> Result<Self> {
        let http = reqwest::Client::builder().timeout(cfg.timeout).build()?;
        Ok(Self { http, cfg })
    }

    async fn call(&self, user_prompt: &str) -> Result<String> {
        let body = GenerateRequest {
            system_instruction: SystemInstruction { parts: vec![TextPart { text: SYSTEM_PROMPT }] },
            contents: vec![UserContent { role: "user", parts: vec![TextPart { text: user_prompt }] }],
            // Düşük sıcaklık: yamalar mümkün olduğunca tekrarlanabilir olsun.
            generation_config: GenerationConfig {
                max_output_tokens: self.cfg.max_output_tokens,
                temperature: 0.2,
            },
        };
        let url = format!(
            "{}/v1beta/models/{}:generateContent",
            self.cfg.base_url.trim_end_matches('/'),
            self.cfg.model
        );
        let raw = post_json_with_retry(
            &self.http,
            &url,
            &[("x-goog-api-key", &self.cfg.api_key)],
            &body,
            self.cfg.max_retries,
        )
        .await?;
        extract_text(&raw)
    }
}

impl PatchProvider for GeminiClient {
    fn propose_patch(
        &self,
        req: &PatchRequest<'_>,
    ) -> impl Future<Output = Result<PatchProposal>> + Send {
        let prompt = build_user_prompt(req);
        async move { parse_proposal(&self.call(&prompt).await?) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const OK_JSON: &str = r#"{"candidates":[{"content":{"parts":[{"text":"hmm","thought":true},{"text":"<explanation>ok</explanation><fixed_code>fn main() {}\n</fixed_code>"}]},"finishReason":"STOP"}]}"#;

    #[test]
    fn skips_thought_parts() {
        let t = extract_text(OK_JSON).unwrap();
        assert!(t.starts_with("<explanation>"));
    }

    #[test]
    fn truncated_and_blocked_are_errors() {
        let cut = r#"{"candidates":[{"content":{"parts":[{"text":"x"}]},"finishReason":"MAX_TOKENS"}]}"#;
        assert!(extract_text(cut).is_err());
        let blocked = r#"{"promptFeedback":{"blockReason":"SAFETY"}}"#;
        assert!(extract_text(blocked).unwrap_err().to_string().contains("SAFETY"));
    }

    #[test]
    fn rejects_bad_model_name() {
        assert!(GeminiConfig::new("k".into(), "../evil?x=1".into(), "http://x".into()).is_err());
        assert!(GeminiConfig::new("".into(), "gemini-3.8-flash".into(), "http://x".into()).is_err());
    }

    /// Yerel sahte sunucu: 1. istek 503, 2. istek 200 → retry + başlık + yol kontrolü.
    async fn fake_server(listener: TcpListener, seen: Arc<Mutex<Vec<String>>>) {
        let mut n = 0;
        while let Ok((mut sock, _)) = listener.accept().await {
            let (mut buf, mut tmp) = (Vec::new(), [0u8; 4096]);
            let (head_end, body_len) = loop {
                let k = sock.read(&mut tmp).await.unwrap();
                if k == 0 {
                    break (buf.len(), 0);
                }
                buf.extend_from_slice(&tmp[..k]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..pos]).to_lowercase();
                    let cl = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    break (pos + 4, cl);
                }
            };
            while buf.len() < head_end + body_len {
                let k = sock.read(&mut tmp).await.unwrap();
                if k == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..k]);
            }
            seen.lock().unwrap().push(String::from_utf8_lossy(&buf[..head_end]).to_string());
            n += 1;
            let (status, body) = if n == 1 { ("503 Service Unavailable", "{}") } else { ("200 OK", OK_JSON) };
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            let _ = sock.shutdown().await;
        }
    }

    #[tokio::test]
    async fn end_to_end_with_retry_against_fake_server() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        tokio::spawn(fake_server(listener, seen.clone()));

        let cfg = GeminiConfig::new(
            "test-key-123".into(),
            "gemini-3.8-flash".into(),
            format!("http://127.0.0.1:{port}"),
        )
        .unwrap();
        let client = GeminiClient::new(cfg).unwrap();
        let req = PatchRequest { file_name: "a.rs", language: "Rust", source: "fn main(){}\n", findings: &[] };

        let p = client.propose_patch(&req).await.unwrap();
        assert_eq!(p.fixed_code, "fn main() {}\n");

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "503 sonrası bir kez yeniden denemeli");
        let head = seen[1].to_lowercase();
        assert!(head.starts_with("post /v1beta/models/gemini-3.8-flash:generatecontent "));
        assert!(head.contains("x-goog-api-key: test-key-123"));
        assert!(!head.lines().next().unwrap().contains("test-key-123"), "anahtar URL'de olmamalı");
    }
}
