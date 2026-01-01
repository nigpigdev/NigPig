# 🥕 Carrot Mode Quickstart

Bu kılavuz, NigPig'in Carrot modunu hızlıca kullanmaya başlamanızı sağlar.

## Carrot Nedir?

Carrot, NigPig'in sürekli otomatik tarama modudur. Bir hedef verilen Carrot:

1. **Baseline taraması** yapar (tam keşif + discovery + kontroller)
2. **Delta döngüleri** çalıştırır (sadece değişen varlıkları tarar)
3. **Bildirimleri** gönderir (verified high/critical anında, diğerleri digest)

## Hızlı Başlangıç

### 1. Sistem Kontrolü

```bash
nigpig doctor
```

Eksik araçlar varsa:
```bash
nigpig doctor --install
```

### 2. Carrot Başlat

En basit kullanım:
```bash
nigpig carrot --domain example.com
```

İnteraktif wizard ile:
```bash
nigpig carrot
```

### 3. Wizard Kullanımı

Wizard'da her soruda `0` girmek = preset varsayılanını kabul etmektir.

```
🥕 CARROT MODU - Sürekli Otomatik Tarama

📋 GEREKLİ ALANLAR
  🎯 Hedef domain/hostname: example.com
  📋 Scope (0=generate): 0
     → example.com + *.example.com otomatik oluşturulacak
  ⚡ Profil (0=balanced): 0
  📁 Program adı (0=example.com): 0
  📬 Bildirim (0=none): 0

📊 OPSİYONEL ALANLAR (0 = preset varsayılanı)
  A) BÜTÇELER
     Max runtime (saat) (0=12): 0
     Max req/saat (0=1000): 0
     Max concurrency (0=10): 0

  B) DÖNGÜ
     Döngü aralığı (dk) (0=60): 0
     Delta-only (e/h) (0=evet): 0
     ...

▶️  Başlatmak için ENTER, iptal için 'q':
```

## Profil Seçimi

| Profil | Kullanım Durumu |
|--------|----------------|
| **stealth** | Düşük iz bırakmak istediğinizde |
| **balanced** | Normal kullanım (varsayılan) |
| **aggressive** | Yetki alanınızda yoğun tarama |

```bash
# Stealth profil
nigpig carrot --domain example.com --profile stealth

# Aggressive profil
nigpig carrot --domain example.com --profile aggressive
```

## Bildirim Ayarlama

### Telegram

1. `nigpig init` ile config oluşturun
2. `~/.nigpig/config.yaml` dosyasını düzenleyin:

```yaml
notifications:
  telegram:
    enabled: true
    bot_token: "YOUR_BOT_TOKEN"
    chat_id: "YOUR_CHAT_ID"
```

3. Carrot başlatırken:
```bash
nigpig carrot --domain example.com --notify telegram
```

### Discord

```yaml
notifications:
  discord:
    enabled: true
    webhook_url: "YOUR_WEBHOOK_URL"
```

## Çıktılar

Carrot bittiğinde:

1. **TXT Rapor**: Current directory'de
   - `NigPig_2026-01-01_18-30-45_example.com_balanced_run-abc123.txt`

2. **Workspace**: `~/.nigpig/workspaces/example.com/`
   - `reports/latest.md`
   - `reports/latest.json`
   - `evidence/<finding_id>/bundle.json`
   - `baseline.json` (delta karşılaştırma için)

## İpuçları

### Durdurmak
`Ctrl+C` ile güvenli durdurma. Rapor yazılır.

### Devam ettirmek
```bash
nigpig resume --run-id abc123
```

### Scope özelleştirmek
```bash
# Önce scope oluştur
nigpig target add --domain example.com --scope ./my-scope.yaml

# Sonra carrot başlat
nigpig carrot --domain example.com --scope ./my-scope.yaml
```

## Sorun Giderme

### "subfinder kurulu değil" uyarısı

```bash
nigpig doctor --install
```

### Rate limit/429 uyarıları

Carrot otomatik yavaşlar. Ek olarak profili `stealth` yapabilirsiniz.

### TXT rapor yazılamadı

Current directory'ye yazma izni kontrol edin. Workspace'e fallback yapılır.

---

**🐷 İyi avlar!**
