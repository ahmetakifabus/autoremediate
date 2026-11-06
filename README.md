# autoremediate

Sitenizi bir bina gibi düşünün. Hırsız binaya dışarıdan bakar: duvar kırık mı,
kamera var mı, pencere açık mı, paspasın altında anahtar unutulmuş mu? Bir zayıflık
görürse oradan girer.

**autoremediate** binaya hırsızın gözüyle bakar, kırık duvarları **yamalar**, eksik
kameraları **takar** ve her işten sonra yeniden kontrol ederek gerçekten kapandığını
**doğrular**.

| | Ne bakar? | Ne yapar? |
|---|---|---|
| **1) Hırsızın gözü** | Yayındaki siteye dışarıdan: HTTPS, güvenlik başlıkları, çerez bayrakları, sürüm ifşası, dışarıda unutulmuş `.env` / `.git` / yedek / `phpinfo` | Raporlar ve hangi kod değişikliğinin kapatacağını söyler |
| **2) Kırık duvarlar** | Koddaki açıklar (Rust, PHP, JS/TS): komut enjeksiyonu, RCE, SQL/NoSQL enjeksiyonu, güvensiz serileştirme, LFI/RFI, web shell kalıpları, prototype pollution, path traversal, SSRF, XSS, sabit parolalar | LLM ile yamalar, yeniden tarar; açık artarsa geri alır |
| **3) Eksik kameralar** | Hiç kurulmamış savunmalar: helmet / güvenlik başlıkları, rate limit, CSRF, güvenli oturum çerezi, istek kaydı, Next.js başlıkları ve Server Action doğrulaması, yükleme klasöründe PHP çalıştırma yasağı, `.env` koruması | Takar (dosya oluşturur veya LLM ile ekler), sonra savunmanın gerçekten yerinde olduğunu doğrular |
| **4) Çürük malzeme** | Bağımlılıklar: React2Shell (CVE-2025-55182 / CVE-2025-66478), Next.js açıkları; `--osv` ile tüm güncel açıklar | Güvenli sürümü hesaplayıp yükseltme komutunu verir |

## Kurulum

```bash
cargo build --release
```

## Kullanım

```bash
# Sadece rapor: hiçbir dosya değişmez, API anahtarı gerekmez
./target/release/autoremediate <proje-dizini> --scan-only

# Rapor + yayındaki siteye dışarıdan bakış + güncel açık veritabanı
./target/release/autoremediate <proje-dizini> --scan-only --site https://siteniz.com --osv

# Sadece dışarıdan bakış
./target/release/autoremediate --site https://siteniz.com

# Önce ne yapılacağını gör (dosyaya yazmaz)
GEMINI_API_KEY=... ./target/release/autoremediate <proje-dizini> --dry-run

# Duvarları yamala + kameraları tak + her değişiklikten sonra tip kontrolü
ANTHROPIC_API_KEY=... ./target/release/autoremediate <proje-dizini> --validate "npx tsc --noEmit"
```

> `--site` yalnızca birkaç sıradan GET isteği gönderir (saldırı yükü yok, giriş denemez),
> ama yine de **yalnızca sahibi olduğunuz veya test izniniz olan siteler** için kullanın.

| Seçenek | Açıklama |
|---|---|
| `--scan-only` | Sadece tara ve raporla |
| `--site <adres>` | Yayındaki siteye dışarıdan bak |
| `--dry-run` | Yamaları ve kurulacak savunmaları göster, dosyaya yazma |
| `--no-harden` | Kameraları takma, sadece duvarları yamala |
| `--provider gemini\|anthropic` | LLM sağlayıcısı (verilmezse tanımlı anahtara göre seçilir) |
| `--max-iter N` | En fazla onarım turu (varsayılan 5, en fazla 20) |
| `--validate "<komut>"` | Her değişiklikten sonra çalışacak doğrulama; başarısızsa geri alınır |
| `--validate-dir <dizin>` | Doğrulama komutunun çalışma dizini |
| `--osv` | Bağımlılıkları osv.dev'de sorgula (yalnızca paket adı + sürüm gönderilir) |
| `--no-deps` | Bağımlılık denetimini atla |
| `--json` | `--scan-only` çıktısını JSON ver (CI için; bulgu varsa çıkış kodu 1) |

Ortam değişkenleri: `GEMINI_API_KEY` (+ `GEMINI_MODEL`), `ANTHROPIC_API_KEY` (+ `AUTOFIX_MODEL`).

## Kameralar nasıl takılır?

- **Dosya ile** (LLM gerekmez): Next.js projesinde `next.config.mjs` yoksa güvenlik
  başlıklarıyla oluşturulur; PHP yükleme klasörüne betik çalıştırmayı kapatan
  `.htaccess` konur; `.env` dosyası `.gitignore`'a eklenir. Var olan dosyanın üzerine
  asla yazılmaz.
- **LLM ile**: savunma ilgili dosyaya en az değişiklikle eklenir. Ardından iki
  kontrol yapılır: kod taraması yeni bir açık bulmamalı **ve** savunma gerçekten
  görünmeli. Biri tutmazsa değişiklik geri alınır.
- **Elle**: `.git` ya da `.env` dosyasının herkese açık klasörde olması gibi durumlarda
  ne yapılacağı yazılır.
- Yeni savunma bir paket gerektiriyorsa (`helmet`, `express-rate-limit`, `morgan`, `zod`)
  kurulum komutu sonda gösterilir.

## Bulgu bastırma

Bir bulgu başka bir satırdaki kontrolle (ör. allowlist) güvenliyse, satırın hemen
üstüne gerekçesiyle yorum eklenebilir:

```js
// autoremediate-ignore[JS060]: host bir üst satırda allowlist ile kontrol ediliyor
const r = await fetch(url);
```

Bastırılan tüm bulgular (LLM'in eklediği dahil) raporda ⚠ ile listelenir ve elle
doğrulanmalıdır.

## Güvenlik notları

- LLM çıktısı güvenilmez kabul edilir: hiçbir zaman çalıştırılmaz; boş, kesik veya
  anormal büyüyen yamalar reddedilir.
- İlk değişiklikten önce `<dosya>.autofix.orig` yedeği alınır.
- Doğrulama komutu kabuk (shell) olmadan çalıştırılır.
- Crate'te `unsafe` kod yasaktır.

## Sınırlar

- Hiçbir araç bir siteyi "kırılamaz" yapamaz. Bu araç bilinen açık türlerini, bilinen
  eksik savunmaları ve bilinen savunmasız sürümleri yakalar; mantık hatalarını ve
  eksik yetki kontrollerini bulamaz.
- Kurallar satır bazlıdır: birden fazla satıra yayılan çağrıları ve dosyalar arası
  veri akışını kaçırabilir, yanlış alarm verebilir.
- Rate limit ve güvenlik başlıkları uygulamanın davranışını etkileyebilir; kurulumdan
  sonra uygulamanızı test edin.

## Örnekler ve antivirüs

`samples/` dizinindeki dosyalar **bilerek açıklı** demo hedefleridir; çalıştırmayın.
Antivirüslerin web shell imzası sanmaması için bilinen web shell kalıpları örneklerde
ve testlerde düz metin olarak bulunmaz.

## Test

```bash
cargo test
```
