@echo off
REM ╔═══════════════════════════════════════════════════════════════════════════╗
REM ║                   🐷 NigPig Windows Kurulum Scripti                       ║
REM ╚═══════════════════════════════════════════════════════════════════════════╝
REM
REM Bu script NigPig için gerekli Go araçlarını Windows'a kurar.
REM PowerShell veya CMD'den çalıştırabilirsiniz.

echo.
echo ╔═══════════════════════════════════════════════════════════════╗
echo ║              🐷 NigPig Windows Kurulum Scripti                ║
echo ╚═══════════════════════════════════════════════════════════════╝
echo.

REM Go kontrolü
where go >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo ❌ Go kurulu değil!
    echo.
    echo Go'yu şu adresten indirin:
    echo   https://go.dev/dl/
    echo.
    echo Veya winget ile:
    echo   winget install GoLang.Go
    echo.
    pause
    exit /b 1
)

echo ✅ Go bulundu
go version
echo.

REM GOPATH kontrolü
if "%GOPATH%"=="" (
    set GOPATH=%USERPROFILE%\go
    echo ℹ️  GOPATH ayarlandı: %GOPATH%
)

echo [1/5] ProjectDiscovery araçları kuruluyor...
echo.

echo    📦 subfinder kuruluyor...
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo    📦 httpx kuruluyor...
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

echo    📦 katana kuruluyor...
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

echo    📦 nuclei kuruluyor...
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

echo    📦 dnsx kuruluyor...
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

echo.
echo [2/5] Ek araçlar kuruluyor...
echo.

echo    📦 ffuf kuruluyor...
go install -v github.com/ffuf/ffuf/v2@latest

echo    📦 gau kuruluyor...
go install -v github.com/lc/gau/v2/cmd/gau@latest

echo.
echo [3/5] Nuclei şablonları güncelleniyor...
echo.

%GOPATH%\bin\nuclei.exe -update-templates -silent

echo.
echo [4/5] NigPig derleniyor...
echo.

cd /d "%~dp0.."
if not exist "build" mkdir build
go mod download
go mod tidy
go build -ldflags="-X 'main.Version=1.0.0'" -o build\nigpig.exe cmd\nigpig\main.go

if %ERRORLEVEL% neq 0 (
    echo ❌ Derleme hatası!
    pause
    exit /b 1
)

echo ✅ NigPig derlendi: build\nigpig.exe
echo.

echo [5/5] PATH'e ekleniyor...
echo.

REM Kullanıcıya PATH ekleme önerisi
echo NigPig'i her yerden çalıştırabilmek için:
echo   1. build\nigpig.exe dosyasını %GOPATH%\bin klasörüne kopyalayın
echo   2. Veya build klasörünü PATH'e ekleyin
echo.

echo ═══════════════════════════════════════════════════════════════
echo ✅ KURULUM TAMAMLANDI!
echo ═══════════════════════════════════════════════════════════════
echo.
echo Kurulu araçlar:
echo.

where subfinder >nul 2>nul && echo   ✅ subfinder || echo   ⚠️ subfinder bulunamadı
where httpx >nul 2>nul && echo   ✅ httpx || echo   ⚠️ httpx bulunamadı
where katana >nul 2>nul && echo   ✅ katana || echo   ⚠️ katana bulunamadı
where nuclei >nul 2>nul && echo   ✅ nuclei || echo   ⚠️ nuclei bulunamadı
where ffuf >nul 2>nul && echo   ✅ ffuf || echo   ⚠️ ffuf bulunamadı

echo.
echo Sonraki adımlar:
echo   1. Yeni terminal açın (PATH güncellemesi için)
echo   2. build\nigpig.exe doctor
echo   3. build\nigpig.exe init
echo   4. build\nigpig.exe examples
echo.
echo 🐷 İyi avlar!
echo.
pause
