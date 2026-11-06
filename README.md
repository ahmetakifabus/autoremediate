# autoremediate

Kaynak koddaki güvenlik açıklarını bulan, bir yapay zekâ modeline (Gemini veya Claude)
düzelttiren ve düzeltmeyi **yeniden tarayarak doğrulayan** komut satırı aracı. Ayrıca
projenin bağımlılıklarını React2Shell gibi framework açıklarına karşı denetler.

## Ne yapar?

1. **Kod taraması**: Rust, PHP ve JavaScript/TypeScript dosyalarında ~50 kuralla
   komut enjeksiyonu, kod çalıştırma (RCE), SQL/NoSQL enjeksiyonu, güvensiz
   serileştirme, dosya dahil etme (LFI/RFI), web shell kalıpları, prototype pollution,
   path traversal, SSRF, XSS, sabit parolalar ve benzerlerini arar. Kullanıcı girdisi
   değişkenler arasında izlenir (`$c = $_GET['c']; ... system($c)` yakalanır).
2. **Otomatik yama**: Bulguları LLM'e gönderir, gelen yamayı yedek alarak uygular,
   dosyayı yeniden tarar. Açık sayısı artarsa veya döngüye girerse yamayı geri alır.
3. **Bağımlılık denetimi**: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`,
   `composer.lock`, `Cargo.lock` dosyalarındaki sürümleri kontrol eder.
   - İnternetsiz çalışan yerleşik tablo: React2Shell (CVE-2025-55182, CVE-2025-66478),
     ardından gelen RSC açıkları ve Next.js middleware atlatma (CVE-2025-29927).
   - `--osv` ile canlı [OSV](https://osv.dev) veritabanı: yeni yayımlanan tüm açıklar.
   - Paketler otomatik yükseltilmez; çalıştırılacak komut önerilir.

## Kurulum

```bash
cargo build --release
```

## Kullanım

```bash
# Sadece tara (API anahtarı gerekmez)
./target/release/autoremediate <proje-dizini> --scan-only

# Bağımlılıkları canlı OSV veritabanında da sorgula
./target/release/autoremediate <proje-dizini> --scan-only --osv

# CI için JSON çıktı (bulgu varsa çıkış kodu 1)
./target/release/autoremediate <proje-dizini> --scan-only --json

# Yamayı üret ama dosyaya yazma
GEMINI_API_KEY=... ./target/release/autoremediate <dosya-veya-dizin> --dry-run

# Otomatik düzelt + her yamadan sonra derleme/tip kontrolü
ANTHROPIC_API_KEY=... ./target/release/autoremediate src --validate "npx tsc --noEmit"
```

| Seçenek | Açıklama |
|---|---|
| `--scan-only` | Sadece tara ve raporla |
| `--dry-run` | Yamayı göster, dosyaya yazma |
| `--provider gemini\|anthropic` | LLM sağlayıcısı (verilmezse tanımlı anahtara göre seçilir) |
| `--max-iter N` | En fazla onarım turu (varsayılan 5, en fazla 20) |
| `--validate "<komut>"` | Her yamadan sonra çalışacak doğrulama; başarısızsa yama geri alınır |
| `--validate-dir <dizin>` | Doğrulama komutunun çalışma dizini |
| `--osv` | Bağımlılıkları osv.dev'de sorgula (yalnızca paket adı + sürüm gönderilir) |
| `--no-deps` | Bağımlılık denetimini atla |
| `--json` | `--scan-only` çıktısını JSON ver |

Ortam değişkenleri: `GEMINI_API_KEY` (+ `GEMINI_MODEL`), `ANTHROPIC_API_KEY` (+ `AUTOFIX_MODEL`).

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

- LLM çıktısı güvenilmez kabul edilir: hiçbir zaman çalıştırılmaz, sadece dosyaya
  yazılır; boş, kesik veya anormal büyüyen yamalar reddedilir.
- İlk değişiklikten önce `<dosya>.autofix.orig` yedeği alınır.
- Doğrulama komutu kabuk (shell) olmadan çalıştırılır.
- Crate'te `unsafe` kod yasaktır.

## Sınırlar

- Kurallar satır bazlıdır: birden fazla satıra yayılan çağrıları ve dosyalar arası
  veri akışını kaçırabilir, yanlış alarm verebilir.
- Mantık hatalarını ve eksik yetki kontrollerini bulamaz.
- Sunucudaki PHP/Node çalışma ortamı sürümünü denetlemez.

## Örnekler ve antivirüs

`samples/` dizinindeki dosyalar **bilerek açıklı** demo hedefleridir; çalıştırmayın.
Antivirüslerin web shell imzası sanmaması için bilinen web shell kalıpları örneklerde
ve testlerde düz metin olarak bulunmaz.

## Test

```bash
cargo test
```
