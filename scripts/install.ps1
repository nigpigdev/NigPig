# NigPig Windows Kurulum Scripti
# PowerShell 5.1+ gereklidir

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   NigPig Windows Kurulum Scripti" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Go kontrolu
Write-Host "[*] Go kurulumu kontrol ediliyor..." -ForegroundColor White
$goPath = Get-Command go -ErrorAction SilentlyContinue
if (-not $goPath) {
    Write-Host "[!] Go kurulu degil!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Go'yu su sekilde kurabilirsiniz:" -ForegroundColor Yellow
    Write-Host "   winget install GoLang.Go" -ForegroundColor White
    Write-Host "   veya: https://go.dev/dl/" -ForegroundColor White
    Write-Host ""
    exit 1
}

$goVersion = go version
Write-Host "[+] $goVersion" -ForegroundColor Green

# GOPATH kontrolu
$goPathEnv = $env:GOPATH
if (-not $goPathEnv) {
    $goPathEnv = "$env:USERPROFILE\go"
}
$goBin = "$goPathEnv\bin"

Write-Host "[*] GOPATH: $goPathEnv" -ForegroundColor White
Write-Host "[*] GOBIN: $goBin" -ForegroundColor White

# PATH kontrolu
if (-not ($env:PATH -like "*$goBin*")) {
    Write-Host "[!] $goBin PATH'te degil, ekleniyor..." -ForegroundColor Yellow
    $env:PATH = "$goBin;$env:PATH"
}

# ProjectDiscovery araclari
Write-Host ""
Write-Host "[1/5] ProjectDiscovery araclari kuruluyor..." -ForegroundColor Cyan

$pdTools = @(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "github.com/projectdiscovery/katana/cmd/katana@latest",
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
)

foreach ($tool in $pdTools) {
    $toolName = ($tool -split "/")[-1] -replace "@.*", ""
    Write-Host "   Kuruluyor: $toolName" -ForegroundColor White
    try {
        go install -v $tool 2>&1 | Out-Null
        Write-Host "   [+] $toolName kuruldu" -ForegroundColor Green
    }
    catch {
        Write-Host "   [!] $toolName kurulamadi" -ForegroundColor Yellow
    }
}

# Ek araclar
Write-Host ""
Write-Host "[2/5] Ek araclar kuruluyor..." -ForegroundColor Cyan

$extraTools = @(
    "github.com/ffuf/ffuf/v2@latest",
    "github.com/lc/gau/v2/cmd/gau@latest",
    "github.com/sensepost/gowitness@latest"
)

foreach ($tool in $extraTools) {
    $toolName = ($tool -split "/")[-1] -replace "@.*", ""
    Write-Host "   Kuruluyor: $toolName" -ForegroundColor White
    try {
        go install -v $tool 2>&1 | Out-Null
        Write-Host "   [+] $toolName kuruldu" -ForegroundColor Green
    }
    catch {
        Write-Host "   [!] $toolName kurulamadi (opsiyonel)" -ForegroundColor Yellow
    }
}

# Nuclei templates
Write-Host ""
Write-Host "[3/5] Nuclei templates guncelleniyor..." -ForegroundColor Cyan
$nucleiPath = Get-Command nuclei -ErrorAction SilentlyContinue
if ($nucleiPath) {
    nuclei -update-templates -silent 2>&1 | Out-Null
    Write-Host "   [+] Templates guncellendi" -ForegroundColor Green
}
else {
    Write-Host "   [!] Nuclei bulunamadi" -ForegroundColor Yellow
}

# NigPig derleme
Write-Host ""
Write-Host "[4/5] NigPig derleniyor..." -ForegroundColor Cyan

$projectDir = Split-Path -Parent $PSScriptRoot
$buildDir = Join-Path $projectDir "build"

if (-not (Test-Path $buildDir)) {
    New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
}

Push-Location $projectDir
try {
    go build -o "$buildDir\nigpig.exe" ./cmd/nigpig 2>&1
    if (Test-Path "$buildDir\nigpig.exe") {
        Write-Host "   [+] NigPig derlendi: $buildDir\nigpig.exe" -ForegroundColor Green
    }
    else {
        Write-Host "   [!] Derleme basarisiz" -ForegroundColor Red
    }
}
catch {
    Write-Host "   [!] Derleme hatasi: $_" -ForegroundColor Red
}
Pop-Location

# Dogrulama
Write-Host ""
Write-Host "[5/5] Kurulum dogrulamasi..." -ForegroundColor Cyan

$tools = @("subfinder", "dnsx", "httpx", "katana", "nuclei")
$missing = @()

foreach ($tool in $tools) {
    $cmd = Get-Command $tool -ErrorAction SilentlyContinue
    if ($cmd) {
        Write-Host "   [+] $tool kurulu" -ForegroundColor Green
    }
    else {
        Write-Host "   [!] $tool eksik" -ForegroundColor Yellow
        $missing += $tool
    }
}

# Ozet
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   Kurulum Tamamlandi" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($missing.Count -gt 0) {
    Write-Host "[!] Eksik araclar: $($missing -join ', ')" -ForegroundColor Yellow
    Write-Host "    Terminali yeniden baslatin ve tekrar deneyin" -ForegroundColor Yellow
}
else {
    Write-Host "[+] Tum zorunlu araclar kurulu!" -ForegroundColor Green
}

Write-Host ""
Write-Host "Sonraki adimlar:" -ForegroundColor White
Write-Host "   1. Terminali yeniden baslat" -ForegroundColor White
Write-Host "   2. .\build\nigpig.exe doctor" -ForegroundColor White
Write-Host "   3. .\build\nigpig.exe carrot --domain example.com" -ForegroundColor White
Write-Host ""

# PATH uyarisi
if (-not ($env:PATH -like "*$buildDir*")) {
    Write-Host "[!] build klasorunu PATH'e eklemek icin:" -ForegroundColor Yellow
    Write-Host "   [Environment]::SetEnvironmentVariable('PATH', `$env:PATH + ';$buildDir', 'User')" -ForegroundColor White
}

Write-Host ""
Write-Host "Iyi avlar!" -ForegroundColor Cyan
Write-Host ""
