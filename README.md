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
GEMINI_API_KEY=... autoremediate <proje-dizini> --dry-run --fix-deps

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
| `--provider gemini\|anthropic` | LLM sağlayıcısı (verilmezse tanımlı anahtara göre seçilir) |
| `--max-iter N` | En fazla onarım turu (varsayılan 5, en fazla 20) |
| `--validate "<komut>"` | Her değişiklikten sonra çalışacak doğrulama; başarısızsa değişiklik geri alınır |
| `--validate-dir <dizin>` | Doğrulama komutunun çalışma dizini |
| `--osv` | Bağımlılıkları osv.dev'de sorgula (yalnızca paket adı + sürüm gönderilir) |
| `--no-deps` | Bağımlılık denetimini atla |
| `--json` | `--scan-only` çıktısını JSON ver |
| `--sarif <dosya>` | SARIF 2.1.0 raporu (GitHub Code Scanning) |
| `--html <dosya>` | Tek dosyalık HTML rapor (puan + tüm bölümler) |
| `--init-ci` | `.github/workflows/autoremediate.yml` bekçisini oluştur |

Ortam değişkenleri: `GEMINI_API_KEY` (+ `GEMINI_MODEL`), `ANTHROPIC_API_KEY` (+ `AUTOFIX_MODEL`).
Bulgu varsa çıkış kodu 1, hata durumunda 2'dir; bu sayede CI'da doğrudan kullanılabilir.

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
