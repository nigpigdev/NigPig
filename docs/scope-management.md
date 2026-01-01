# 🔒 Scope Management

Bu belge NigPig'de scope yönetimini açıklar.

## Scope Neden Önemli?

NigPig **SADECE** yetkili olduğunuz hedefleri tarar. Scope dosyası:

- İzin verilen domain'leri tanımlar
- Yasaklı path'leri belirler
- Rate limit'leri ayarlar
- Tehlikeli testleri engeller

## Scope Dosyası Yapısı

```yaml
# scope.yaml

# Program bilgileri
program: "example-bugbounty"
target: "example.com"
platform: "hackerone"  # hackerone, bugcrowd, intigriti, manual

# İzin verilen hedefler
in_scope:
  domains:
    - "example.com"
    - "*.example.com"
    - "api.example.com"
    - "app.example.com"
  
  # İzin verilen portlar
  ports:
    - 80
    - 443
    - 8080
    - 8443
  
  # IP aralıkları (opsiyonel)
  ips: []
  cidrs: []

# Yasaklı hedefler
out_of_scope:
  domains:
    - "blog.example.com"
    - "*.cdn.example.com"
    - "status.example.com"
  
  # Yasaklı path pattern'ları
  paths:
    - "/logout"
    - "/delete-*"
    - "/admin/delete"
    - "*/password-reset"
  
  # Yasaklı keyword'ler
  keywords:
    - "third-party"
    - "analytics"

# Test kuralları
rules:
  # Yıkıcı testler KAPALI
  destructive_tests: false
  
  # Brute force KAPALI
  brute_force: false
  
  # Auth testing KAPALI
  auth_testing: false
  
  # Cloud testing KAPALI
  cloud_testing: false
  
  # Rate limit (req/sn/host)
  rate_limit: 10
  
  # Max concurrent connections per host
  max_connections: 5
  
  # robots.txt'e uy
  respect_robots: true

# Notlar
notes: |
  - Login gerektiren alanlar test edilmeyecek
  - Sadece production ortamı
```

## Scope Oluşturma

### Otomatik Oluşturma

Carrot wizard'da `0` girin:
```
📋 Scope (0=generate): 0
   → example.com + *.example.com otomatik oluşturulacak
```

### Manuel Oluşturma

```bash
nigpig target add --domain example.com --scope ./scope.yaml
```

### Platform Import

HackerOne, Bugcrowd veya Intigriti scope dosyasını import edin:

```bash
# Otomatik platform tespiti
nigpig scope import ./h1-scope.json

# Platform belirtme
nigpig scope import --platform hackerone ./h1-scope.json

# Çıktı dosyası belirtme
nigpig scope import ./h1-scope.json --output ./scope.yaml
```

## Scope Doğrulama

```bash
nigpig config lint --scope scope.yaml
```

Çıktı:
```
🔍 NigPig Config Lint

  scope.yaml kontrol ediliyor...

  ✅ scope.yaml: Geçerli

  veya

  ⚠️ scope.yaml: Uyarılar var
     WARN [conflict] scope: in-scope '*.example.com' vs out-of-scope 'blog.example.com'
```

## Scope Görüntüleme

```bash
nigpig scope show ./scope.yaml
```

## ScopeGuard

NigPig'in her aşamasında ScopeGuard çalışır:

1. **URL kontrolü**: Her URL in-scope mu?
2. **Audit logging**: Out-of-scope istekler loglanır
3. **Engelleme**: Out-of-scope hedeflere istek yapılmaz

### Audit Log

Out-of-scope engellemeler kaydedilir:
```
~/.nigpig/workspaces/example.com/audit.jsonl
```

```json
{"timestamp":"2026-01-01T18:30:45Z","target":"https://other.com/api","reason":"not_in_scope","module":"discover"}
```

## Örnekler

### Minimal Scope

```yaml
target: "example.com"
in_scope:
  domains:
    - "example.com"
```

### Wildcard Scope

```yaml
target: "example.com"
in_scope:
  domains:
    - "*.example.com"  # Tüm subdomain'ler
```

### Strict Scope

```yaml
target: "example.com"
in_scope:
  domains:
    - "api.example.com"   # Sadece API
    - "app.example.com"   # ve App
  ports:
    - 443                 # Sadece HTTPS

out_of_scope:
  paths:
    - "/health"
    - "/metrics"
    - "/admin/*"

rules:
  rate_limit: 5           # Çok yavaş
  destructive_tests: false
```

---

**⚠️ Her zaman hedefin scope'unu doğrulayın!**
