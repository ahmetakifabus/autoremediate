# autoremediate

Sitenizi bir bina gibi düşünün. Hırsız binaya dışarıdan bakar: duvar kırık mı, kamera var mı,
kapı kilitli mi, pencere açık mı, paspasın altında anahtar unutulmuş mu? Bir zayıflık görürse
oradan girer.

**autoremediate** binaya hırsızın gözüyle bakar; kırık duvarları **yamalar**, eksik kameraları
**takar**, kilitsiz kapıları **kilitler**, çürük malzemeyi **değiştirir**. Her işten sonra binayı
yeniden kontrol eder ve sorunun gerçekten giderildiğini **doğrular**. Doğrulama başarısız olursa
değişikliği geri alır.

| | Ne bakar? | Ne yapar? |
|---|---|---|
| **1) Hırsızın gözü** | Yayındaki siteye dışarıdan bakar: HTTPS, güvenlik başlıkları, çerez bayrakları, sürüm ifşası, dışarıda unutulmuş `.env` / `.git` / yedek dosyaları / `phpinfo`, internete açık phpMyAdmin / Adminer | Raporlar ve hangi değişikliğin sorunu kapatacağını söyler |
| **2) Kırık duvarlar** | Koddaki açıklar (Rust, PHP, JS/TS, **Python**, **Go**): komut enjeksiyonu, RCE, SQL/NoSQL enjeksiyonu, SSTI, güvensiz serileştirme, LFI/RFI, web shell kalıpları, prototype pollution, path traversal, SSRF, XSS, sabit parolalar | LLM ile yamalar, yeniden tarar; açık sayısı artarsa değişikliği geri alır |
| **3) Eksik kameralar** | Hiç kurulmamış savunmalar: helmet / güvenlik başlıkları, rate limit, CSRF, güvenli oturum çerezi, istek kaydı, Next.js başlıkları, Flask Talisman/Limiter, Django güvenlik ayarları, Go sunucu başlıkları, yükleme klasöründe PHP çalıştırma yasağı | Savunmayı takar, sonra gerçekten yerinde olduğunu doğrular |
| **4) Kilitsiz kapılar** | Kimlik doğrulaması olmayan `/admin` ve hassas yollar (Express, Next.js, PHP, Flask/Django), veri değiştiren API uçları ve Server Action'lar | Projedeki kimlik doğrulama yöntemiyle kilitler, sonra doğrular |
| **5) Çürük temel** | nginx / Apache (dizin listeleme, eski TLS, sürüm ifşası, HTTPS yönlendirmesi), `php.ini`, Dockerfile (root kullanıcı, gömülü parolalar, `:latest`), desteği bitmiş PHP / Node.js / Python / Go | `php.ini` ayarlarını kendisi düzeltir; diğerleri için tam olarak ne yazılacağını söyler |
| **6) Çürük malzeme** | Bağımlılıklar: React2Shell (CVE-2025-55182 / CVE-2025-66478), Next.js açıkları; `--osv` ile npm, Packagist, crates.io, PyPI ve Go modüllerindeki tüm güncel açıklar | `--fix-deps` ile paket yöneticisini kullanarak yükseltir; açık kapanmazsa ya da testler kırılırsa geri alır |

Sonuçlar 0–100 arası bir **güvenlik puanı** ve harf notuyla özetlenir. Rapor terminalde, JSON,
**SARIF** (GitHub Security sekmesi) ya da tek dosyalık **HTML** olarak alınabilir.

## Kurulum

[Releases](https://github.com/ahmetakifabus/autoremediate/releases) sayfasından işletim sisteminize uygun
dosyayı indirin. Ya da kaynaktan derleyin:

```bash
cargo build --release
```

## Kullanım

```bash
# Sadece rapor: hiçbir dosya değişmez, API anahtarı gerekmez
autoremediate <proje-dizini> --scan-only

# Rapor + dışarıdan bakış + güncel açık veritabanı + HTML rapor
autoremediate <proje-dizini> --scan-only --site https://siteniz.com --osv --html rapor.html

# Önce ne yapılacağını gör (dosyaya yazmaz)
OPENAI_API_KEY=... autoremediate <proje-dizini> --dry-run --fix-deps

# Hepsi: duvarları yamala, kameraları ve kilitleri tak, malzemeyi değiştir; her adımda testleri çalıştır
ANTHROPIC_API_KEY=... autoremediate <proje-dizini> --fix-deps --validate "npm test"

# Yalnızca savunmasız bağımlılıkları yükselt (API anahtarı gerekmez)
autoremediate <proje-dizini> --fix-deps --no-harden --validate "npm test"

# Projeye bekçi ekle: her push / PR / hafta otomatik kontrol
autoremediate <proje-dizini> --init-ci --scan-only
```

> `--site` yalnızca birkaç sıradan GET isteği gönderir (saldırı yükü yok, giriş denemez),
> ama yine de **yalnızca sahibi olduğunuz veya test izniniz olan siteler** için kullanın.

| Seçenek | Açıklama |
|---|---|
| `--scan-only` | Sadece tara ve raporla |
| `--site <adres>` | Yayındaki siteye dışarıdan bak |
| `--dry-run` | Yamaları, kurulacak savunmaları ve yükseltmeleri göster; dosyaya yazma |
| `--no-harden` | Kameraları ve kilitleri takma, sadece duvarları yamala |
| `--fix-deps` | Savunmasız bağımlılıkları yükselt (npm/yarn/pnpm, composer, cargo, pip/poetry/pipenv, go) |
| `--provider <ad>` | LLM sağlayıcısı (aşağıdaki tablo; verilmezse anahtarı tanımlı ilk sağlayıcı) |
| `--model <ad>` | Sağlayıcının modelini değiştir |
| `--providers` | Sağlayıcıları ve ortamda hazır olanları listele |
| `--max-iter N` | En fazla onarım turu (varsayılan 5, en fazla 20) |
| `--validate "<komut>"` | Her değişiklikten sonra çalışacak doğrulama; başarısızsa değişiklik geri alınır |
| `--validate-dir <dizin>` | Doğrulama komutunun çalışma dizini |
| `--osv` | Bağımlılıkları osv.dev'de sorgula (yalnızca paket adı + sürüm gönderilir) |
| `--no-deps` | Bağımlılık denetimini atla |
| `--json` | `--scan-only` çıktısını JSON ver |
| `--sarif <dosya>` | SARIF 2.1.0 raporu (GitHub Code Scanning) |
| `--html <dosya>` | Tek dosyalık HTML rapor (puan + tüm bölümler) |
| `--init-ci` | `.github/workflows/autoremediate.yml` bekçisini oluştur |

Bulgu varsa çıkış kodu 1, hata durumunda 2'dir; bu sayede CI'da doğrudan kullanılabilir.

## LLM sağlayıcıları

Yamalama ve kamera/kilit takma için bir LLM gerekir. Tarama için (`--scan-only`) gerekmez.
Hangi sağlayıcının anahtarı tanımlıysa o kullanılır. Birden fazla anahtar tanımlıysa tablodaki
sıraya göre ilki seçilir; istediğinizi `--provider` ile seçebilirsiniz.

| `--provider` | Servis | Ortam değişkeni | Varsayılan model |
|---|---|---|---|
| `anthropic` | Anthropic Claude | `ANTHROPIC_API_KEY` | claude-sonnet-5-5 |
| `gemini` | Google Gemini | `GEMINI_API_KEY` | gemini-3.8-flash |
| `openai` | OpenAI | `OPENAI_API_KEY` | gpt-5 |
| `openrouter` | OpenRouter (yüzlerce model, tek anahtar) | `OPENROUTER_API_KEY` | anthropic/claude-sonnet-4.5 |
| `deepseek` | DeepSeek | `DEEPSEEK_API_KEY` | deepseek-chat |
| `mistral` | Mistral AI | `MISTRAL_API_KEY` | mistral-large-latest |
| `xai` | xAI (Grok) | `XAI_API_KEY` | grok-4 |
| `groq` | Groq | `GROQ_API_KEY` | openai/gpt-oss-120b |
| `together` | Together AI | `TOGETHER_API_KEY` | Qwen3-Coder-480B |
| `fireworks` | Fireworks AI | `FIREWORKS_API_KEY` | qwen3-coder-480b |
| `cerebras` | Cerebras | `CEREBRAS_API_KEY` | gpt-oss-120b |
| `cohere` | Cohere | `COHERE_API_KEY` | command-a-03-2025 |
| `qwen` | Alibaba Qwen (DashScope) | `DASHSCOPE_API_KEY` | qwen3-coder-plus |
| `kimi` | Moonshot Kimi | `MOONSHOT_API_KEY` | kimi-k2-0905-preview |
| `glm` | Zhipu GLM (Z.ai) | `ZAI_API_KEY` | glm-4.6 |
| `huggingface` | Hugging Face Inference | `HF_TOKEN` | openai/gpt-oss-120b |
| `github` | GitHub Models | `GITHUB_MODELS_TOKEN` | openai/gpt-4.1 |
| `nvidia` | NVIDIA NIM | `NVIDIA_API_KEY` | qwen3-coder-480b |
| `azure` | Azure OpenAI | `AZURE_OPENAI_API_KEY` + `AZURE_OPENAI_ENDPOINT` + `AZURE_OPENAI_DEPLOYMENT` | (dağıtım adı) |
| `custom` | Herhangi bir OpenAI uyumlu uç nokta (vLLM, LiteLLM...) | `OPENAI_COMPAT_API_KEY` + `OPENAI_COMPAT_BASE_URL` + `OPENAI_COMPAT_MODEL` | (zorunlu) |
| `ollama` | Ollama (yerel, anahtarsız, kod dışarı çıkmaz) | `OLLAMA_MODEL` (+ `OLLAMA_BASE_URL`) | qwen2.5-coder:14b |
| `lmstudio` | LM Studio (yerel, anahtarsız) | `LMSTUDIO_MODEL` (+ `LMSTUDIO_BASE_URL`) | (zorunlu) |

- Model, `--model` ile ya da sağlayıcının `*_MODEL` değişkeniyle değiştirilir (`OPENAI_MODEL`,
  `DEEPSEEK_MODEL`, `GEMINI_MODEL`, Anthropic için `AUTOFIX_MODEL` ...). Varsayılan modeller
  zamanla eskiyebilir; sağlayıcınızın güncel model adını kullanın.
- Anahtar yalnızca istek başlığında gönderilir; URL'ye, log'a ya da hata mesajına yazılmaz.
  Anahtarlı istekler yalnızca HTTPS ya da bu makinedeki bir sunucu üzerinden yapılır.
- Kaynak kodunuzun bilgisayarınızdan çıkmasını istemiyorsanız `ollama` ya da `lmstudio` kullanın.
- `autoremediate --providers` tüm listeyi ve ortamda hazır olanları gösterir.
## Bekçi (GitHub Actions)

`--init-ci` projeye bir iş akışı ekler. Bu iş akışı her push'ta, her PR'da ve her pazartesi
binayı kontrol eder. Pazartesi kontrolü, kodunuz değişmese bile o hafta yeni yayımlanan
açıkları yakalamak içindir. Bulgu varsa iş başarısız olur. Bulgular **Security > Code
scanning** sekmesinde görünür, HTML rapor da iş çıktısı olarak saklanır. Kurulum adımları
oluşturulan dosyanın başında yazılıdır.

## Kameralar ve kilitler nasıl takılır?

- **Dosya ile** (LLM gerekmez):
  - Next.js projesinde `next.config.mjs` yoksa güvenlik başlıklarıyla oluşturulur.
  - PHP yükleme klasörüne betik çalıştırmayı kapatan `.htaccess` konur.
  - `.env` dosyası `.gitignore`'a eklenir.
  - `php.ini` içinde `display_errors`, `expose_php`, `allow_url_include` kapatılır.
  - Var olan bir dosyanın üzerine asla yazılmaz.
- **LLM ile**: savunma ya da kilit, ilgili dosyaya en az değişiklikle eklenir. Ardından iki kontrol
  yapılır: kod taraması yeni bir açık bulmamalı **ve** savunma gerçekten görünmeli. Biri
  tutmazsa değişiklik geri alınır.
- **Elle**: örneğin `.git` ya da `.env` herkese açık klasördeyse, ya da nginx/Dockerfile
  değişikliği gerekiyorsa, yazılacak satır tam olarak verilir.

## Bağımlılıklar nasıl değiştirilir? (`--fix-deps`)

1. Manifest ve kilit dosyalarının yedeği alınır.
2. Güvenli sürüm hesaplanır. Yükseltilen sürüm başka bir açığın aralığına düşüyorsa (ör. Next.js
   15.2.3) ilk güvenli sürüme kadar devam edilir.
3. Doğrudan bağımlılıklar `npm install paket@sürüm` (yarn/pnpm/composer/cargo/go/pip karşılıkları)
   ile yükseltilir. Dolaylı bağımlılıklar (ör. `next` içinden gelen `react-server-dom-webpack`)
   `overrides` / `resolutions` ile sabitlenir.
4. Kilit dosyası yeniden okunur. Açık hâlâ duruyorsa ya da `--validate` başarısız olursa dosyalar
   geri yüklenir.

## Bulgu bastırma

Bir bulgu başka bir satırdaki kontrolle (ör. allowlist) güvenli hale getirildiyse, satırın hemen
üstüne gerekçesiyle bir yorum eklenebilir:

```js
// autoremediate-ignore[JS060]: host bir üst satırda allowlist ile kontrol ediliyor
const r = await fetch(url);
```

Bastırılan tüm bulgular, LLM'in eklediği bastırmalar dahil, raporda ⚠ ile listelenir ve elle
doğrulanmalıdır.

## Güvenlik notları

- LLM çıktısı güvenilmez kabul edilir ve hiçbir zaman çalıştırılmaz. Boş, kesik ya da anormal
  büyüyen yamalar reddedilir.
- İlk değişiklikten önce `<dosya>.autofix.orig` yedeği alınır.
- Doğrulama ve paket yöneticisi komutları kabuk (shell) olmadan çalıştırılır.
- Crate'te `unsafe` kod yasaktır.

## Sınırlar

- Hiçbir araç bir siteyi "kırılamaz" yapamaz. Bu araç bilinen açık türlerini, bilinen eksik
  savunmaları, kilitsiz hassas kapıları ve bilinen savunmasız sürümleri yakalar. İş mantığı
  hatalarını ve her türlü yetki sorununu bulamaz.
- Kurallar ifade bazlıdır: birden fazla satıra yayılan çağrılar birleştirilir, ancak dosyalar
  arası veri akışı izlenmez. Kaçırılan açık da, yanlış alarm da olabilir.
- Kilit tespiti adlandırmaya dayanır (`/admin`, `requireAuth`, `$_SESSION` ...). Farklı adlandırılmış
  korumalar tanınmayabilir; bu durumda bulguyu bastırın.
- Rate limit, güvenlik başlıkları, kilitler ve bağımlılık yükseltmeleri uygulamanın davranışını
  etkileyebilir. Uygulamadan sonra uygulamanızı test edin (`--validate` bunun içindir).

## Örnekler ve antivirüs

`samples/` dizinindeki dosyalar **bilerek açıklı** demo hedefleridir; çalıştırmayın. Antivirüslerin
web shell imzası sanmaması için bilinen web shell kalıpları örneklerde ve testlerde düz metin
olarak bulunmaz.

## Test

```bash
cargo test
```
