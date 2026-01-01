# 🐷 NigPig

> **Production-grade Bug Bounty & Güvenlik Tarama Otomasyonu**

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go)](https://go.dev/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue?style=flat-square)](https://github.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

NigPig, bug bounty avcılığı ve web güvenlik açıkları bulmak için tasarlanmış **cross-platform** CLI otomasyon aracıdır.

```
    ███╗   ██╗██╗ ██████╗ ██████╗ ██╗ ██████╗ 
    ████╗  ██║██║██╔════╝ ██╔══██╗██║██╔════╝ 
    ██╔██╗ ██║██║██║  ███╗██████╔╝██║██║  ███╗
    ██║╚██╗██║██║██║   ██║██╔═══╝ ██║██║   ██║
    ██║ ╚████║██║╚██████╔╝██║     ██║╚██████╔╝
    ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝     ╚═╝ ╚═════╝ 
```

## ⚠️ Yasal Uyarı

**Bu araç YALNIZCA yasal ve yetkilendirilmiş hedeflerde kullanılmalıdır!**

NigPig, yalnızca kullanıcının yetkili olduğu hedeflerde kullanılmak üzere tasarlanmıştır. 
Varsayılan olarak yıkıcı testler, brute-force ve credential stuffing **KAPALI**dır.

## ✨ Öne Çıkan Özellikler

| Özellik | Açıklama |
|---------|----------|
| 🥕 **Carrot Mode** | Sürekli otomatik tarama - baseline + delta tracking |
| 🔄 **Delta Intelligence** | CT log, DNS değişimi, JS hash izleme ile ASM |
| ✅ **Verified Gating** | Multi-sensor corroboration, high/critical only if verified |
| 📦 **Evidence Bundle** | Otomatik maskeli HTTP request/response paketleme |
| ⚡ **Adaptive Rate** | 429/503 tespiti → otomatik yavaşlama |
| 🛡️ **ScopeGuard** | Out-of-scope hedefler otomatik engellenir + audit log |
| 📄 **TXT Rapor** | Her komut sonrası current directory'e zorunlu rapor |
| 🔧 **Config Lint** | Scope ve config dosyası doğrulama |
| 📊 **Presets** | stealth / balanced / aggressive profiller |

## 🚀 Hızlı Başlangıç

### Windows Kurulumu

```powershell
# 1. Klonla
git clone https://github.com/nigpig/nigpig.git
cd nigpig

# 2. Kur
.\scripts\install.ps1

# 3. Doğrula
.\build\nigpig.exe doctor
```

### Linux/Kali Kurulumu

```bash
# 1. Klonla
git clone https://github.com/nigpig/nigpig.git
cd nigpig

# 2. Kur
chmod +x scripts/install.sh
./scripts/install.sh

# 3. Doğrula
nigpig doctor
```

## 📖 Komutlar

```bash
# Sistem kontrolü
nigpig doctor
nigpig doctor --install          # Eksik araçları kur

# Workspace oluştur
nigpig init

# Hedef yönetimi
nigpig target add --domain example.com --scope scope.yaml
nigpig target list

# 🥕 CARROT MODU (önerilen)
nigpig carrot                    # İnteraktif wizard
nigpig carrot --domain example.com
nigpig carrot --domain example.com --profile stealth
nigpig carrot --domain example.com --yes  # Tüm varsayılanlar

# Tek seferlik tarama
nigpig run --target example.com

# Rapor
nigpig report --target example.com --format md,json

# Bildirim
nigpig notify --report ./report.md --channel telegram

# Devam ettir
nigpig resume --run-id abc12345

# Presets
nigpig presets list
nigpig presets show balanced

# Config doğrulama
nigpig config lint --scope scope.yaml
```

## 🥕 Carrot Mode

Carrot, sürekli otomatik tarama modudur:

1. **Baseline koşusu**: Tam recon + discovery + checks
2. **Delta döngüleri**: Sadece değişen varlıkları tara
   - Yeni subdomain
   - Yeni canlı endpoint
   - JS hash değişimi → endpoint extraction
   - DNS değişikliği

### Wizard

Her soruda `0` = preset varsayılanı:

```
🥕 CARROT MODU - Sürekli Otomatik Tarama

📋 GEREKLİ ALANLAR
  🎯 Hedef domain/hostname: example.com
  📋 Scope (0=generate): 0
     → example.com + *.example.com
  ⚡ Profil (0=balanced): 0
  📁 Program adı: 0
  📬 Bildirim (0=none): 0

📊 OPSİYONEL ALANLAR
  A) BÜTÇELER
     Max runtime (saat) (0=12): 0
     Max req/saat (0=1000): 0
     ...
```

## 📄 TXT Rapor Çıktısı

**Her komut** sonrası current directory'e otomatik TXT rapor yazılır:

```
NigPig_2026-01-01_18-30-45_example.com_balanced_run-abc12345.txt
```

İçerik:
1. Özet (tool, tarih, OS, run-id, hedef, profil, scope)
2. Çalışma Parametreleri (bütçeler, ağ, döngü, auth, bildirim)
3. Aşamalar ve İstatistikler (recon, live, URL, checks, verify)
4. Bulgular Özeti (severity dağılımı)
5. Hatalar / Uyarılar (degrade mode, rate-limit, out-of-scope)
6. Dosya Referansları (workspace, MD/JSON, evidence)

## 🔧 Pipeline

```
recon → resolve → live_http → discover_urls → normalize → safe_checks → verify → triage → report → notify → sleep → delta
```

| Aşama | Açıklama | Araç |
|-------|----------|------|
| recon | Subdomain keşfi | subfinder (+amass) |
| resolve | DNS çözümleme | dnsx |
| live_http | Canlı host tespiti | httpx |
| discover_urls | URL keşfi | katana (+gau) |
| safe_checks | Güvenli kontroller | nuclei |
| verify | Bulgu doğrulama | dahili (recheck + control) |
| triage | Önceliklendirme | dahili |
| report | Rapor oluşturma | dahili (MD/JSON/TXT) |
| notify | Bildirim | Telegram/Discord/Slack |

## 📊 Presets

| Preset | Concurrency | Req/Hour | Cycle | Açıklama |
|--------|-------------|----------|-------|----------|
| **stealth** | 2 | 100 | 120 dk | Düşük iz, gizli tarama |
| **balanced** | 10 | 1000 | 60 dk | Dengeli (varsayılan) |
| **aggressive** | 50 | 5000 | 30 dk | Yüksek hız (ama hala güvenli) |

```bash
nigpig presets show balanced
```

## 🔒 Güvenlik

### Varsayılan KAPALI
- ❌ Destructive testler
- ❌ Brute-force / credential stuffing
- ❌ Auth testing
- ❌ Aşırı yoğun denemeler

### Varsayılan AÇIK
- ✅ ScopeGuard (out-of-scope engelleme + audit)
- ✅ Adaptive rate limiting
- ✅ Secret redaction
- ✅ Verified gating (high/critical only if verified)

### Scope Dosyası

```yaml
program: "example-program"
target: "example.com"

in_scope:
  domains:
    - "example.com"
    - "*.example.com"
  ports: [80, 443]

out_of_scope:
  domains:
    - "blog.example.com"
  paths:
    - "/logout"
    - "/delete-*"

rules:
  destructive_tests: false
  brute_force: false
  rate_limit: 10
```

### Config Lint

```bash
nigpig config lint --scope scope.yaml --config nigpig.yaml
```

## 🛠 Gerekli Araçlar

| Araç | Zorunlu | Açıklama |
|------|---------|----------|
| subfinder | ✅ | Subdomain keşfi |
| dnsx | ✅ | DNS çözümleme |
| httpx | ✅ | HTTP probing |
| katana | ✅ | Web crawling |
| nuclei | ✅ | Zafiyet tarama |
| ffuf | ❌ | Fuzzing |
| amass | ❌ | Gelişmiş subdomain |
| gau | ❌ | URL arşivi |
| gowitness | ❌ | Ekran görüntüsü |

```bash
# Eksikleri kontrol et ve kur
nigpig doctor --install
```

## 📁 Proje Yapısı

```
nigpig/
├── cmd/nigpig/          # Entry point
├── internal/
│   ├── cli/             # Cobra komutları
│   ├── core/            # Pipeline, delta, verify, types
│   ├── config/          # Config, presets, lint
│   ├── auth/            # Session management
│   ├── store/           # SQLite persistence
│   ├── scope/           # ScopeGuard
│   ├── report/          # Rapor oluşturma
│   └── notify/          # Bildirimler
├── configs/             # Örnek config/scope/presets
├── scripts/             # Kurulum scriptleri
└── docs/
```

## 🔧 Troubleshooting

### Go kurulu değil
```bash
# Windows
winget install GoLang.Go

# Linux
sudo apt install golang-go
```

### PATH problemi
```bash
# Linux
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# Windows PowerShell
[Environment]::SetEnvironmentVariable('PATH', $env:PATH + ';' + $env:USERPROFILE + '\go\bin', 'User')
```

### TXT rapor yazılamıyor
- Current directory'ye yazma izni kontrol edin
- Workspace'e fallback yapılır

## 📜 Lisans

MIT License

---

**🐷 İyi avlar!**
