# 🛠 Troubleshooting / Sorun Giderme

Bu belge, NigPig kullanırken karşılaşabileceğiniz yaygın sorunları ve çözümlerini içerir.

## Kurulum Sorunları

### Go kurulu değil

**Belirti:**
```
go : The term 'go' is not recognized as the name of a cmdlet...
```

**Çözüm:**

Windows:
```powershell
winget install GoLang.Go
# veya https://go.dev/dl/ adresinden indirin
```

Linux/Kali:
```bash
sudo apt update
sudo apt install golang-go
# veya https://go.dev/dl/ adresinden indirin
```

### PATH'te GOPATH/bin yok

**Belirti:**
```
⚠️ $GOPATH/bin PATH'te değil!
```

**Çözüm:**

Linux/macOS:
```bash
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

Windows PowerShell:
```powershell
[Environment]::SetEnvironmentVariable('PATH', $env:PATH + ';' + $env:USERPROFILE + '\go\bin', 'User')
# PowerShell'i yeniden başlatın
```

### Araç kurulumu başarısız

**Belirti:**
```
Kuruluyor: subfinder... HATA: ...
```

**Çözüm:**

Manuel kurulum deneyin:
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

Eğer hala hata varsa:
1. Go versiyonunu kontrol edin: `go version` (1.21+ gerekli)
2. İnternet bağlantısını kontrol edin
3. Proxy ayarlarını kontrol edin

## Çalışma Sorunları

### TXT rapor yazılamadı

**Belirti:**
```
❌ TXT rapor yazılamadı: permission denied
```

**Çözümler:**

1. Current directory'ye yazma izni kontrol edin:
   ```bash
   ls -la .
   # veya
   Get-Acl .
   ```

2. Farklı bir dizinden çalıştırın:
   ```bash
   cd /tmp
   nigpig carrot --domain example.com
   ```

3. Workspace'e fallback yapılır - rapor orada aranabilir:
   ```bash
   ls ~/.nigpig/workspaces/example.com/reports/
   ```

### Rate limit / 429 hataları

**Belirti:**
```
⚠️ Throttle olayları: 15
```

**Çözümler:**

1. Daha yavaş profil kullanın:
   ```bash
   nigpig carrot --domain example.com --profile stealth
   ```

2. Manuel budget override:
   ```bash
   nigpig carrot --domain example.com --max-requests 100 --concurrency 2
   ```

3. Carrot otomatik yavaşlar, bekleyin.

### Out-of-scope engelleme

**Belirti:**
```
⚠️ Out-of-scope engellemeleri: 50
```

**Açıklama:**
ScopeGuard, scope dışı hedeflere istek yapmayı engeller. Bu DOĞRU davranıştır.

**Eğer yanlışsa:**
Scope dosyanızı genişletin:
```yaml
in_scope:
  domains:
    - "*.example.com"
    - "api.example.com"
```

### Araç bulunamadı (degrade mode)

**Belirti:**
```
⚠️ UYARILAR - Degrade Mode
  • subfinder kurulu değil
```

**Çözüm:**

```bash
nigpig doctor --install
```

veya manuel:
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### Auth session expired

**Belirti:**
```
⚠️ Auth refresh needed
```

**Çözüm:**

Auth profile güncellenmeli. Token/cookie'ler expire olmuş olabilir.

## Performans Sorunları

### Tarama çok yavaş

**Çözümler:**

1. Daha agresif profil:
   ```bash
   nigpig carrot --domain example.com --profile aggressive
   ```

2. Concurrency artırın (dikkatli):
   ```bash
   nigpig carrot --domain example.com --concurrency 20
   ```

### Çok fazla false positive

**Çözümler:**

1. NigPig zaten verified gating kullanır - sadece verified bulgular high/critical olur

2. Verify aşamasını bekleyin

3. `needs-manual` bulguları manuel kontrol edin

### Çok fazla memory kullanımı

**Çözümler:**

1. URL limiti düşürün:
   ```bash
   nigpig carrot --domain example.com --max-urls 10000
   ```

2. Concurrency düşürün

## Windows-Özel Sorunlar

### Execution policy

**Belirti:**
```
scripts\install.ps1 cannot be loaded because running scripts is disabled
```

**Çözüm:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Path çok uzun

Windows MAX_PATH limiti (260 karakter) sorun yaratabilir.

**Çözüm:**
NigPig home'u daha kısa bir path'e taşıyın:
```powershell
$env:NIGPIG_HOME = "C:\np"
```

## Linux/Kali-Özel Sorunlar

### Permission denied

**Belirti:**
```
permission denied: ./nigpig
```

**Çözüm:**
```bash
chmod +x ./nigpig
chmod +x scripts/install.sh
```

### ulimit

Çok fazla concurrent connection için:
```bash
ulimit -n 10000
```

## Yardım Almak

1. `nigpig doctor` çalıştırın
2. TXT raporundaki hata mesajlarını kontrol edin
3. Verbose mode deneyin: `nigpig carrot -v --domain example.com`
4. GitHub Issues açın

---

**🐷 Sorun çözülemezse, TXT raporunu paylaşarak yardım isteyin!**
