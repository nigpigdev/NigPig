#!/usr/bin/env bash
# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║                   🐷 NigPig Linux/Kali Kurulum Scripti                    ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
#
# Bu script NigPig ve gerekli Go araçlarını Linux/Kali'ye kurar.
# Kullanım: chmod +x install.sh && ./install.sh

set -e

# Renkler
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║              🐷 NigPig Linux/Kali Kurulum Scripti             ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Root kontrolü
if [ "$EUID" -eq 0 ]; then
    echo -e "${YELLOW}⚠️  Root olarak çalıştırılmamalı, normal kullanıcı olarak çalıştırın.${NC}"
    exit 1
fi

# OS kontrolü
if [[ ! -f /etc/os-release ]]; then
    echo -e "${RED}❌ Desteklenmeyen işletim sistemi${NC}"
    exit 1
fi

source /etc/os-release
echo -e "  İşletim Sistemi: ${GREEN}$NAME $VERSION${NC}"
echo ""

# Go kontrolü
echo -e "${CYAN}[1/5] Go kontrolü...${NC}"
if command -v go &> /dev/null; then
    GO_VERSION=$(go version | awk '{print $3}')
    echo -e "  ${GREEN}✓ Go kurulu: $GO_VERSION${NC}"
else
    echo -e "${YELLOW}  Go kurulu değil, kuruluyor...${NC}"
    
    # Go kurulumu
    if [[ "$ID" == "kali" ]] || [[ "$ID" == "debian" ]] || [[ "$ID" == "ubuntu" ]]; then
        sudo apt update
        sudo apt install -y golang-go
    elif [[ "$ID" == "arch" ]] || [[ "$ID" == "manjaro" ]]; then
        sudo pacman -S --noconfirm go
    elif [[ "$ID" == "fedora" ]]; then
        sudo dnf install -y golang
    else
        echo -e "${RED}❌ Go otomatik kurulamadı. Manuel kurun: https://go.dev/dl/${NC}"
        exit 1
    fi
    
    echo -e "  ${GREEN}✓ Go kuruldu${NC}"
fi

# GOPATH ayarla
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin"

# PATH kontrolü
if ! echo "$PATH" | grep -q "$GOPATH/bin"; then
    echo -e "${YELLOW}  PATH'e GOPATH/bin ekleniyor...${NC}"
    
    # Shell'e ekle
    SHELL_RC=""
    if [[ -f ~/.zshrc ]]; then
        SHELL_RC=~/.zshrc
    elif [[ -f ~/.bashrc ]]; then
        SHELL_RC=~/.bashrc
    fi
    
    if [[ -n "$SHELL_RC" ]]; then
        echo 'export GOPATH="$HOME/go"' >> "$SHELL_RC"
        echo 'export PATH="$PATH:$GOPATH/bin"' >> "$SHELL_RC"
        echo -e "  ${GREEN}✓ PATH güncellendi: $SHELL_RC${NC}"
    fi
fi

# ProjectDiscovery araçları
echo ""
echo -e "${CYAN}[2/5] ProjectDiscovery araçları kuruluyor...${NC}"

TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
)

for tool in "${TOOLS[@]}"; do
    name=$(echo "$tool" | grep -oP '[^/]+(?=@)')
    echo -n "  📦 $name kuruluyor..."
    if go install -v "$tool" &> /dev/null; then
        echo -e " ${GREEN}✓${NC}"
    else
        echo -e " ${YELLOW}⚠️${NC}"
    fi
done

# Ek araçlar (opsiyonel)
echo ""
echo -e "${CYAN}[3/5] Ek araçlar kuruluyor (opsiyonel)...${NC}"

OPTIONAL_TOOLS=(
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/tomnomnom/waybackurls@latest"
)

for tool in "${OPTIONAL_TOOLS[@]}"; do
    name=$(echo "$tool" | grep -oP '[^/]+(?=@)')
    echo -n "  📦 $name kuruluyor..."
    if go install -v "$tool" &> /dev/null; then
        echo -e " ${GREEN}✓${NC}"
    else
        echo -e " ${YELLOW}⚠️ (opsiyonel)${NC}"
    fi
done

# Nuclei şablonları
echo ""
echo -e "${CYAN}[4/5] Nuclei şablonları güncelleniyor...${NC}"
if command -v nuclei &> /dev/null || [[ -f "$GOPATH/bin/nuclei" ]]; then
    "$GOPATH/bin/nuclei" -update-templates -silent 2>/dev/null || nuclei -update-templates -silent 2>/dev/null || true
    echo -e "  ${GREEN}✓ Şablonlar güncellendi${NC}"
else
    echo -e "  ${YELLOW}⚠️ Nuclei bulunamadı${NC}"
fi

# NigPig derleme
echo ""
echo -e "${CYAN}[5/5] NigPig derleniyor...${NC}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

if [[ ! -f "go.mod" ]]; then
    echo -e "${RED}❌ go.mod bulunamadı. Proje dizininde olduğunuzdan emin olun.${NC}"
    exit 1
fi

mkdir -p build
go mod download
go mod tidy

if go build -ldflags="-X 'main.Version=1.0.0'" -o build/nigpig ./cmd/nigpig; then
    echo -e "  ${GREEN}✓ NigPig derlendi: $PROJECT_DIR/build/nigpig${NC}"
else
    echo -e "${RED}❌ Derleme hatası${NC}"
    exit 1
fi

# Kurulum özeti
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✅ KURULUM TAMAMLANDI!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "Kurulu araçlar:"

for tool in subfinder dnsx httpx katana nuclei ffuf gau waybackurls; do
    if command -v "$tool" &> /dev/null || [[ -f "$GOPATH/bin/$tool" ]]; then
        echo -e "  ${GREEN}✓ $tool${NC}"
    else
        echo -e "  ${YELLOW}⚠️ $tool (kurulmadı)${NC}"
    fi
done

echo ""
echo -e "Sonraki adımlar:"
echo "  1. Terminali yeniden başlatın (PATH için)"
echo "  2. ./build/nigpig doctor"
echo "  3. ./build/nigpig init"
echo "  4. ./build/nigpig carrot"
echo ""
echo -e "${CYAN}🐷 İyi avlar!${NC}"
