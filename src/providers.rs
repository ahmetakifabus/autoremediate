//! LLM sağlayıcıları: Anthropic, Gemini ve OpenAI uyumlu (Chat Completions)
//! API sunan tüm servisler (OpenAI, OpenRouter, Groq, DeepSeek, Mistral, xAI,
//! Together, Fireworks, Cerebras, Cohere, Qwen, Kimi, GLM, Hugging Face,
//! GitHub Models, NVIDIA, Azure OpenAI) ve yerel modeller (Ollama, LM Studio).
//!
//! Anahtar asla URL'ye, log'a ya da hata mesajına yazılmaz; yalnızca istek
//! başlığında gider. Anahtar gerektiren sağlayıcılar yalnızca HTTPS (ya da
//! yerel adres) üzerinden çağrılır.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ai::{
    build_user_prompt, parse_proposal, post_json_with_retry, AnthropicClient, LlmConfig, PatchProposal,
    PatchProvider, PatchRequest, SYSTEM_PROMPT,
};
use crate::error::{Error, Result};
use crate::gemini::{GeminiClient, GeminiConfig};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Auth {
    /// `Authorization: Bearer <anahtar>`
    Bearer,
    /// `api-key: <anahtar>` (Azure)
    ApiKeyHeader,
    /// Anahtar yok (yerel sunucu)
    None,
}

/// OpenAI uyumlu bir servisin tanımı
pub struct Preset {
    pub id: &'static str,
    pub name: &'static str,
    /// Anahtarın okunduğu ortam değişkenleri (ilk dolu olan kullanılır)
    key_envs: &'static [&'static str],
    /// Varsayılan uç nokta (…/v1); `base_env` ile değiştirilebilir
    base_url: &'static str,
    base_env: Option<&'static str>,
    pub default_model: &'static str,
    model_env: &'static str,
    auth: Auth,
    /// Yeni OpenAI modelleri `max_tokens` yerine `max_completion_tokens` ister
    completion_tokens_field: &'static str,
}

const fn preset(
    id: &'static str,
    name: &'static str,
    key_envs: &'static [&'static str],
    base_url: &'static str,
    default_model: &'static str,
    model_env: &'static str,
) -> Preset {
    Preset {
        id,
        name,
        key_envs,
        base_url,
        base_env: None,
        default_model,
        model_env,
        auth: Auth::Bearer,
        completion_tokens_field: "max_tokens",
    }
}

/// Otomatik seçimde bu sırayla denenir (yerel sunucular en sonda, yalnızca model tanımlıysa).
pub const PRESETS: &[Preset] = &[
    Preset {
        base_env: Some("OPENAI_BASE_URL"),
        completion_tokens_field: "max_completion_tokens",
        ..preset("openai", "OpenAI", &["OPENAI_API_KEY"], "https://api.openai.com/v1", "gpt-5", "OPENAI_MODEL")
    },
    preset("openrouter", "OpenRouter (yüzlerce model, tek anahtar)", &["OPENROUTER_API_KEY"],
        "https://openrouter.ai/api/v1", "anthropic/claude-sonnet-4.5", "OPENROUTER_MODEL"),
    preset("deepseek", "DeepSeek", &["DEEPSEEK_API_KEY"], "https://api.deepseek.com/v1", "deepseek-chat", "DEEPSEEK_MODEL"),
    preset("mistral", "Mistral AI", &["MISTRAL_API_KEY"], "https://api.mistral.ai/v1", "mistral-large-latest", "MISTRAL_MODEL"),
    preset("xai", "xAI (Grok)", &["XAI_API_KEY"], "https://api.x.ai/v1", "grok-4", "XAI_MODEL"),
    preset("groq", "Groq", &["GROQ_API_KEY"], "https://api.groq.com/openai/v1", "openai/gpt-oss-120b", "GROQ_MODEL"),
    preset("together", "Together AI", &["TOGETHER_API_KEY"], "https://api.together.xyz/v1",
        "Qwen/Qwen3-Coder-480B-A35B-Instruct-FP8", "TOGETHER_MODEL"),
    preset("fireworks", "Fireworks AI", &["FIREWORKS_API_KEY"], "https://api.fireworks.ai/inference/v1",
        "accounts/fireworks/models/qwen3-coder-480b-a35b-instruct", "FIREWORKS_MODEL"),
    preset("cerebras", "Cerebras", &["CEREBRAS_API_KEY"], "https://api.cerebras.ai/v1", "gpt-oss-120b", "CEREBRAS_MODEL"),
    preset("cohere", "Cohere", &["COHERE_API_KEY", "CO_API_KEY"], "https://api.cohere.ai/compatibility/v1",
        "command-a-03-2025", "COHERE_MODEL"),
    preset("qwen", "Alibaba Qwen (DashScope)", &["DASHSCOPE_API_KEY"],
        "https://dashscope-intl.aliyuncs.com/compatible-mode/v1", "qwen3-coder-plus", "QWEN_MODEL"),
    preset("kimi", "Moonshot Kimi", &["MOONSHOT_API_KEY"], "https://api.moonshot.ai/v1", "kimi-k2-0905-preview", "KIMI_MODEL"),
    preset("glm", "Zhipu GLM (Z.ai)", &["ZAI_API_KEY", "ZHIPUAI_API_KEY"], "https://api.z.ai/api/paas/v4", "glm-4.6", "GLM_MODEL"),
    preset("huggingface", "Hugging Face Inference", &["HF_TOKEN", "HUGGINGFACE_API_KEY"],
        "https://router.huggingface.co/v1", "openai/gpt-oss-120b", "HF_MODEL"),
    preset("github", "GitHub Models", &["GITHUB_MODELS_TOKEN"], "https://models.github.ai/inference",
        "openai/gpt-4.1", "GITHUB_MODELS_MODEL"),
    preset("nvidia", "NVIDIA NIM", &["NVIDIA_API_KEY"], "https://integrate.api.nvidia.com/v1",
        "qwen/qwen3-coder-480b-a35b-instruct", "NVIDIA_MODEL"),
    Preset {
        // Uç nokta zorunlu: https://<kaynak>.openai.azure.com → /openai/v1 eklenir.
        // Model alanı Azure'daki dağıtım (deployment) adıdır.
        base_env: Some("AZURE_OPENAI_ENDPOINT"),
        auth: Auth::ApiKeyHeader,
        completion_tokens_field: "max_completion_tokens",
        ..preset("azure", "Azure OpenAI", &["AZURE_OPENAI_API_KEY"], "", "", "AZURE_OPENAI_DEPLOYMENT")
    },
    Preset {
        base_env: Some("OPENAI_COMPAT_BASE_URL"),
        ..preset("custom", "Herhangi bir OpenAI uyumlu uç nokta", &["OPENAI_COMPAT_API_KEY"], "", "", "OPENAI_COMPAT_MODEL")
    },
    Preset {
        base_env: Some("OLLAMA_BASE_URL"),
        auth: Auth::None,
        ..preset("ollama", "Ollama (yerel, anahtarsız)", &[], "http://127.0.0.1:11434/v1", "qwen2.5-coder:14b", "OLLAMA_MODEL")
    },
    Preset {
        base_env: Some("LMSTUDIO_BASE_URL"),
        auth: Auth::None,
        ..preset("lmstudio", "LM Studio (yerel, anahtarsız)", &[], "http://127.0.0.1:1234/v1", "", "LMSTUDIO_MODEL")
    },
];

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

impl Preset {
    fn key(&self) -> Option<String> {
        self.key_envs.iter().find_map(|k| env(k))
    }

    /// Ortamda bu sağlayıcı için yeterli ayar var mı? (otomatik seçim için)
    fn configured(&self) -> bool {
        match self.auth {
            // Yerel sunucular yalnızca model açıkça seçildiyse otomatik seçilir
            Auth::None => env(self.model_env).is_some(),
            _ => {
                self.key().is_some()
                    && (!self.base_url.is_empty() || self.base_env.is_some_and(|b| env(b).is_some()))
            }
        }
    }

    fn base(&self) -> Result<String> {
        let raw = self.base_env.and_then(env).unwrap_or_else(|| self.base_url.to_string());
        if raw.is_empty() {
            let var = self.base_env.unwrap_or("?");
            return Err(Error::Config(format!("{}: {var} ortam değişkeni tanımlı değil", self.name)));
        }
        let mut base = raw.trim_end_matches('/').to_string();
        if self.id == "azure" && !base.ends_with("/openai/v1") {
            base.push_str("/openai/v1");
        }
        Ok(base)
    }
}

/// Anahtarlı istekler yalnızca HTTPS ya da bu makinedeki sunucuya gider.
fn check_transport(base: &str, has_key: bool) -> Result<()> {
    let url = reqwest::Url::parse(base).map_err(|e| Error::Config(format!("geçersiz uç nokta {base:?}: {e}")))?;
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]" | "::1"));
    match url.scheme() {
        "https" => Ok(()),
        "http" if local || !has_key => Ok(()),
        "http" => Err(Error::Config(format!("{base}: API anahtarı şifresiz HTTP ile gönderilmez; https kullanın"))),
        s => Err(Error::Config(format!("{base}: desteklenmeyen şema {s}"))),
    }
}

// ---- OpenAI uyumlu istemci --------------------------------------------------

pub struct OpenAiCompatClient {
    http: reqwest::Client,
    key: Option<String>, // Debug türetilmedi: anahtar log'a sızmasın
    url: String,
    model: String,
    auth: Auth,
    tokens_field: &'static str,
    max_tokens: u32,
    max_retries: u32,
}

#[derive(Serialize)]
struct Msg<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct ChatResponse {
    #[serde(default)]
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: ChoiceMessage,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct ChoiceMessage {
    #[serde(default)]
    content: Value,
}

impl OpenAiCompatClient {
    fn new(p: &Preset, model_override: Option<&str>) -> Result<Self> {
        let key = p.key();
        if p.auth != Auth::None && key.is_none() {
            return Err(Error::Config(format!("{}: {} ortam değişkeni tanımlı değil", p.name, p.key_envs.join(" / "))));
        }
        let model = model_override
            .map(String::from)
            .or_else(|| env(p.model_env))
            .or_else(|| (!p.default_model.is_empty()).then(|| p.default_model.to_string()))
            .ok_or_else(|| Error::Config(format!("{}: model seçin (--model ya da {})", p.name, p.model_env)))?;
        let base = p.base()?;
        check_transport(&base, key.is_some())?;
        let http = reqwest::Client::builder().timeout(Duration::from_secs(300)).build()?;
        Ok(Self {
            http,
            key,
            url: format!("{base}/chat/completions"),
            model,
            auth: p.auth,
            tokens_field: p.completion_tokens_field,
            max_tokens: 16_000,
            max_retries: 4,
        })
    }

    async fn call(&self, user_prompt: &str) -> Result<String> {
        let mut body = serde_json::json!({
            "model": self.model,
            "messages": [
                Msg { role: "system", content: SYSTEM_PROMPT },
                Msg { role: "user", content: user_prompt },
            ],
        });
        body[self.tokens_field] = Value::from(self.max_tokens);

        let bearer;
        let mut headers: Vec<(&str, &str)> = Vec::new();
        match (self.auth, &self.key) {
            (Auth::Bearer, Some(k)) => {
                bearer = format!("Bearer {k}");
                headers.push(("authorization", &bearer));
            }
            (Auth::ApiKeyHeader, Some(k)) => headers.push(("api-key", k)),
            _ => {}
        }
        let raw = post_json_with_retry(&self.http, &self.url, &headers, &body, self.max_retries).await?;
        extract_text(&raw)
    }
}

/// `choices[0].message.content` (dize ya da parça dizisi) → metin
fn extract_text(raw: &str) -> Result<String> {
    let r: ChatResponse = serde_json::from_str(raw).map_err(|e| Error::Remote(format!("yanıt çözümlenemedi: {e}")))?;
    let c = r.choices.into_iter().next().ok_or_else(|| Error::Remote("yanıtta seçenek (choices) yok".into()))?;
    if c.finish_reason.as_deref() == Some("length") {
        return Err(Error::Remote("yanıt token sınırında kesildi".into()));
    }
    let text = match c.message.content {
        Value::String(s) => s,
        Value::Array(parts) => parts
            .iter()
            .filter(|p| p.get("type").and_then(Value::as_str).is_none_or(|t| t == "text"))
            .filter_map(|p| p.get("text").and_then(Value::as_str))
            .collect(),
        _ => String::new(),
    };
    if text.trim().is_empty() {
        return Err(Error::Remote("boş yanıt".into()));
    }
    Ok(text)
}

impl PatchProvider for OpenAiCompatClient {
    async fn propose_patch(&self, req: &PatchRequest<'_>) -> Result<PatchProposal> {
        let raw = self.call(&build_user_prompt(req)).await?;
        parse_proposal(&raw)
    }
}

// ---- Seçim -----------------------------------------------------------------

/// Seçilen sağlayıcı; tek bir tip olarak onarım döngüsüne verilir.
pub enum AnyProvider {
    Anthropic(AnthropicClient),
    Gemini(GeminiClient),
    Compat(OpenAiCompatClient),
}

impl PatchProvider for AnyProvider {
    async fn propose_patch(&self, req: &PatchRequest<'_>) -> Result<PatchProposal> {
        match self {
            AnyProvider::Anthropic(c) => c.propose_patch(req).await,
            AnyProvider::Gemini(c) => c.propose_patch(req).await,
            AnyProvider::Compat(c) => c.propose_patch(req).await,
        }
    }
}

/// (id, açıklama, anahtar değişkeni, varsayılan model, ortamda hazır mı?)
pub fn catalog() -> Vec<(&'static str, &'static str, String, &'static str, bool)> {
    let mut v = vec![
        ("anthropic", "Anthropic Claude", "ANTHROPIC_API_KEY".to_string(), "claude-sonnet-5-5", env("ANTHROPIC_API_KEY").is_some()),
        ("gemini", "Google Gemini", "GEMINI_API_KEY".to_string(), "gemini-2.5-flash", env("GEMINI_API_KEY").is_some()),
    ];
    for p in PRESETS {
        let key = match (p.auth, p.base_env) {
            (Auth::None, _) => format!("(anahtarsız) {}", p.model_env),
            (_, Some(b)) if p.base_url.is_empty() => format!("{} + {b} + {}", p.key_envs[0], p.model_env),
            _ => p.key_envs[0].to_string(),
        };
        let model = if p.default_model.is_empty() { "(zorunlu)" } else { p.default_model };
        v.push((p.id, p.name, key, model, p.configured()));
    }
    v
}

pub fn ids() -> Vec<&'static str> {
    catalog().into_iter().map(|c| c.0).collect()
}

/// `--provider` verilmediyse ortamda anahtarı olan ilk sağlayıcı seçilir.
pub fn select(id: Option<&str>, model: Option<&str>) -> Result<(AnyProvider, String)> {
    let id = match id {
        Some(i) => i.to_ascii_lowercase(),
        None => catalog()
            .into_iter()
            .find(|c| c.4)
            .map(|c| c.0.to_string())
            .ok_or_else(|| Error::Config(
                "LLM sağlayıcısı bulunamadı: bir API anahtarı tanımlayın (ör. OPENAI_API_KEY, ANTHROPIC_API_KEY, \
                 GEMINI_API_KEY, OPENROUTER_API_KEY, DEEPSEEK_API_KEY, GROQ_API_KEY...). Tüm liste: --providers".into(),
            ))?,
    };
    match id.as_str() {
        "anthropic" | "claude" => {
            let mut cfg = LlmConfig::from_env()?;
            if let Some(m) = model {
                cfg.model = m.to_string();
            }
            let label = format!("Anthropic ({})", cfg.model);
            Ok((AnyProvider::Anthropic(AnthropicClient::new(cfg)?), label))
        }
        "gemini" | "google" => {
            let cfg = GeminiConfig::from_env_with_model(model)?;
            let label = format!("Gemini ({})", cfg.model());
            Ok((AnyProvider::Gemini(GeminiClient::new(cfg)?), label))
        }
        other => {
            let p = PRESETS
                .iter()
                .find(|p| p.id == other)
                .ok_or_else(|| Error::Config(format!("bilinmeyen sağlayıcı: {other}. Seçenekler: {}", ids().join(", "))))?;
            let c = OpenAiCompatClient::new(p, model)?;
            let label = format!("{} ({})", p.name, c.model);
            Ok((AnyProvider::Compat(c), label))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn preset_ids_are_unique_and_valid() {
        let ids = ids();
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "yinelenen sağlayıcı kimliği");
        assert!(ids.len() >= 20);
        for p in PRESETS.iter().filter(|p| !p.base_url.is_empty()) {
            check_transport(p.base_url, p.auth != Auth::None).unwrap();
        }
    }

    #[test]
    fn key_is_never_sent_over_plain_http() {
        assert!(check_transport("http://api.example.com/v1", true).is_err());
        assert!(check_transport("http://127.0.0.1:11434/v1", true).is_ok());
        assert!(check_transport("http://gpu-box:8000/v1", false).is_ok());
        assert!(check_transport("file:///etc/passwd", false).is_err());
    }

    #[test]
    fn parses_string_and_part_contents() {
        let s = r#"{"choices":[{"message":{"content":"<fixed_code>x</fixed_code>"},"finish_reason":"stop"}]}"#;
        assert_eq!(extract_text(s).unwrap(), "<fixed_code>x</fixed_code>");
        let parts = r#"{"choices":[{"message":{"content":[{"type":"text","text":"a"},{"type":"reasoning","text":"gizli"},{"type":"text","text":"b"}]}}]}"#;
        assert_eq!(extract_text(parts).unwrap(), "ab");
        assert!(extract_text(r#"{"choices":[{"message":{"content":"x"},"finish_reason":"length"}]}"#).is_err());
        assert!(extract_text(r#"{"choices":[]}"#).is_err());
    }

    /// Tek istekli sahte OpenAI uyumlu sunucu
    async fn fake(listener: TcpListener, seen: Arc<Mutex<String>>) {
        let (mut sock, _) = listener.accept().await.unwrap();
        let (mut buf, mut tmp) = (Vec::new(), [0u8; 8192]);
        loop {
            let k = sock.read(&mut tmp).await.unwrap();
            buf.extend_from_slice(&tmp[..k]);
            let text = String::from_utf8_lossy(&buf).to_string();
            if let Some(pos) = text.find("\r\n\r\n") {
                let cl = text[..pos]
                    .to_lowercase()
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
                    .unwrap_or(0);
                if buf.len() >= pos + 4 + cl || k == 0 {
                    *seen.lock().unwrap() = text;
                    break;
                }
            }
            if k == 0 {
                break;
            }
        }
        let body = r#"{"choices":[{"message":{"role":"assistant","content":"<explanation>ok</explanation><fixed_code>fn main() {}\n</fixed_code>"},"finish_reason":"stop"}]}"#;
        let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        sock.write_all(resp.as_bytes()).await.unwrap();
        let _ = sock.shutdown().await;
    }

    #[tokio::test]
    async fn end_to_end_against_fake_server() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(String::new()));
        tokio::spawn(fake(listener, seen.clone()));

        let client = OpenAiCompatClient {
            http: reqwest::Client::new(),
            key: Some("sk-test-999".into()),
            url: format!("http://127.0.0.1:{port}/v1/chat/completions"),
            model: "test-model".into(),
            auth: Auth::Bearer,
            tokens_field: "max_completion_tokens",
            max_tokens: 100,
            max_retries: 1,
        };
        let req = PatchRequest { file_name: "a.rs", language: "Rust", source: "fn main(){}\n", findings: &[] };
        let p = client.propose_patch(&req).await.unwrap();
        assert_eq!(p.fixed_code, "fn main() {}\n");

        let seen = seen.lock().unwrap().clone();
        let lower = seen.to_lowercase();
        assert!(lower.starts_with("post /v1/chat/completions "));
        assert!(lower.contains("authorization: bearer sk-test-999"));
        assert!(!seen.lines().next().unwrap().contains("sk-test-999"), "anahtar URL'de olmamalı");
        assert!(seen.contains("\"model\":\"test-model\"") && seen.contains("\"max_completion_tokens\":100"));
        assert!(seen.contains("\"role\":\"system\""));
    }
}
