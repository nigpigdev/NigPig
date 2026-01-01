# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║                   🐷 NigPig Windows Kurulum Scripti                       ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
#
# Bu script NigPig için gerekli Go araçlarını Windows'a kurar.
# PowerShell'den çalıştırın: .\scripts\install.ps1

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║              🐷 NigPig Windows Kurulum Scripti                ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Go kontrolü
function Test-GoInstalled {
    try {
        $goVersion = go version 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Go bulundu: $goVersion" -ForegroundColor Green
            return $true
        }
    } catch {}
    return $false
}

if (-not (Test-GoInstalled)) {
    Write-Host "❌ Go kurulu değil!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Go'yu şu yöntemlerden biriyle kurun:" -ForegroundColor Yellow
    Write-Host "  1. https://go.dev/dl/ adresinden indirin"
    Write-Host "  2. winget install GoLang.Go"
    Write-Host "  3. choco install golang"
    Write-Host ""
    exit 1
}

# GOPATH kontrolü
$goPath = $env:GOPATH
if ([string]::IsNullOrEmpty($goPath)) {
    $goPath = Join-Path $env:USERPROFILE "go"
    Write-Host "ℹ️  GOPATH: $goPath" -ForegroundColor Cyan
}

$goBin = Join-Path $goPath "bin"
if (-not ($env:PATH -split ';' | Where-Object { $_ -eq $goBin })) {
    Write-Host "⚠️  $goBin PATH'te değil, ekleniyor..." -ForegroundColor Yellow
    $env:PATH = "$goBin;$env:PATH"
}

# ProjectDiscovery araçları
Write-Host ""
Write-Host "[1/5] ProjectDiscovery araçları kuruluyor..." -ForegroundColor Cyan
Write-Host ""

$pdTools = @(
    @{Name="subfinder"; Package="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
    @{Name="httpx"; Package="github.com/projectdiscovery/httpx/cmd/httpx@latest"},
    @{Name="katana"; Package="github.com/projectdiscovery/katana/cmd/katana@latest"},
    @{Name="nuclei"; Package="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
    @{Name="dnsx"; Package="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"}
)

foreach ($tool in $pdTools) {
    Write-Host "   📦 $($tool.Name) kuruluyor..." -NoNewline
    try {
        go install -v $tool.Package 2>&1 | Out-Null
        Write-Host " ✅" -ForegroundColor Green
    } catch {
        Write-Host " ⚠️" -ForegroundColor Yellow
    }
}

# Ek araçlar
Write-Host ""
Write-Host "[2/5] Ek araçlar kuruluyor..." -ForegroundColor Cyan
Write-Host ""

$extraTools = @(
    @{Name="ffuf"; Package="github.com/ffuf/ffuf/v2@latest"},
    @{Name="gau"; Package="github.com/lc/gau/v2/cmd/gau@latest"},
    @{Name="waybackurls"; Package="github.com/tomnomnom/waybackurls@latest"}
)

foreach ($tool in $extraTools) {
    Write-Host "   📦 $($tool.Name) kuruluyor..." -NoNewline
    try {
        go install -v $tool.Package 2>&1 | Out-Null
        Write-Host " ✅" -ForegroundColor Green
    } catch {
        Write-Host " ⚠️ (opsiyonel)" -ForegroundColor Yellow
    }
}

# Nuclei şablonları
Write-Host ""
Write-Host "[3/5] Nuclei şablonları güncelleniyor..." -ForegroundColor Cyan

$nucleiPath = Join-Path $goBin "nuclei.exe"
if (Test-Path $nucleiPath) {
    try {
        & $nucleiPath -update-templates -silent 2>&1 | Out-Null
        Write-Host "   ✅ Şablonlar güncellendi" -ForegroundColor Green
    } catch {
        Write-Host "   ⚠️ Şablon güncelleme hatası" -ForegroundColor Yellow
    }
} else {
    Write-Host "   ⚠️ Nuclei bulunamadı" -ForegroundColor Yellow
}

# NigPig derleme
Write-Host ""
Write-Host "[4/5] NigPig derleniyor..." -ForegroundColor Cyan

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectDir = Split-Path -Parent $scriptDir
Set-Location $projectDir

if (-not (Test-Path "build")) {
    New-Item -ItemType Directory -Path "build" | Out-Null
}

Write-Host "   Bağımlılıklar indiriliyor..."
go mod download 2>&1 | Out-Null
go mod tidy 2>&1 | Out-Null

Write-Host "   Derleniyor..."
$buildResult = go build -ldflags="-X 'main.Version=1.0.0'" -o "build\nigpig.exe" "cmd\nigpig\main.go" 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "   ✅ NigPig derlendi: $projectDir\build\nigpig.exe" -ForegroundColor Green
} else {
    Write-Host "   ❌ Derleme hatası: $buildResult" -ForegroundColor Red
}

# PATH ekleme önerisi
Write-Host ""
Write-Host "[5/5] Kurulum özeti..." -ForegroundColor Cyan
Write-Host ""

# Araç kontrolü
$tools = @("subfinder", "httpx", "katana", "nuclei", "ffuf", "dnsx", "gau")
Write-Host "Kurulu araçlar:" -ForegroundColor White
foreach ($tool in $tools) {
    $toolPath = Join-Path $goBin "$tool.exe"
    if (Test-Path $toolPath) {
        Write-Host "   ✅ $tool" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️ $tool (kurulmadı)" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "✅ KURULUM TAMAMLANDI!" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "Sonraki adımlar:" -ForegroundColor White
Write-Host "   1. Yeni PowerShell penceresi açın"
Write-Host "   2. .\build\nigpig.exe doctor"
Write-Host "   3. .\build\nigpig.exe init"
Write-Host "   4. .\build\nigpig.exe examples"
Write-Host ""

# PATH'e kalıcı ekleme önerisi
Write-Host "💡 İPUCU: NigPig'i her yerden çalıştırmak için:" -ForegroundColor Yellow
Write-Host "   [Environment]::SetEnvironmentVariable('PATH', `$env:PATH + ';$projectDir\build', 'User')" -ForegroundColor Gray
Write-Host ""
Write-Host "🐷 İyi avlar!" -ForegroundColor Cyan
Write-Host ""
