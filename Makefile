.PHONY: build clean test run doctor deps install help

# Varsayılanlar
BINARY_NAME=nigpig
BINARY_DIR=build
VERSION=1.0.0
LDFLAGS=-ldflags "-X 'main.Version=$(VERSION)'"

# Renkli çıktı
ifeq ($(OS),Windows_NT)
    CYAN=
    GREEN=
    YELLOW=
    RESET=
    RM=if exist $(BINARY_DIR) rmdir /s /q $(BINARY_DIR)
    MKDIR=if not exist $(BINARY_DIR) mkdir $(BINARY_DIR)
    BINARY=$(BINARY_DIR)/$(BINARY_NAME).exe
else
    CYAN=\033[36m
    GREEN=\033[32m
    YELLOW=\033[33m
    RESET=\033[0m
    RM=rm -rf $(BINARY_DIR)
    MKDIR=mkdir -p $(BINARY_DIR)
    BINARY=$(BINARY_DIR)/$(BINARY_NAME)
endif

help: ## Bu yardım mesajını göster
	@echo ""
	@echo "$(CYAN)🐷 NigPig Makefile$(RESET)"
	@echo ""
	@echo "$(GREEN)Kullanılabilir komutlar:$(RESET)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(CYAN)%-15s$(RESET) %s\n", $$1, $$2}'
	@echo ""

build: ## Projeyi derle
	@echo "$(CYAN)🔨 Derleniyor...$(RESET)"
	@$(MKDIR)
	go build $(LDFLAGS) -o $(BINARY) ./cmd/nigpig
	@echo "$(GREEN)✓ Derleme tamamlandı: $(BINARY)$(RESET)"

clean: ## Derleme dosyalarını temizle
	@echo "$(YELLOW)🧹 Temizleniyor...$(RESET)"
	@$(RM)
	@go clean
	@echo "$(GREEN)✓ Temizlendi$(RESET)"

test: ## Testleri çalıştır
	@echo "$(CYAN)🧪 Testler çalışıyor...$(RESET)"
	go test -v ./...

run: build ## Derle ve çalıştır
	@echo "$(CYAN)🚀 Çalıştırılıyor...$(RESET)"
	@$(BINARY) $(ARGS)

doctor: build ## Sistem kontrolü yap
	@$(BINARY) doctor

deps: ## Bağımlılıkları indir
	@echo "$(CYAN)📦 Bağımlılıklar indiriliyor...$(RESET)"
	go mod download
	go mod tidy
	@echo "$(GREEN)✓ Bağımlılıklar hazır$(RESET)"

install: build ## Sisteme kur
	@echo "$(CYAN)📥 Kuruluyor...$(RESET)"
ifeq ($(OS),Windows_NT)
	@copy $(BINARY) $(GOPATH)\bin\ 2>nul || copy $(BINARY) $(USERPROFILE)\go\bin\
else
	@cp $(BINARY) $(GOPATH)/bin/ 2>/dev/null || cp $(BINARY) ~/go/bin/
endif
	@echo "$(GREEN)✓ Kurulum tamamlandı$(RESET)"

lint: ## Kod kalitesi kontrolü
	@echo "$(CYAN)🔍 Lint çalışıyor...$(RESET)"
	@go vet ./...
	@echo "$(GREEN)✓ Lint tamamlandı$(RESET)"

fmt: ## Kodu formatla
	@echo "$(CYAN)📝 Formatlanıyor...$(RESET)"
	@go fmt ./...
	@echo "$(GREEN)✓ Formatlama tamamlandı$(RESET)"

all: deps build test ## Hepsini yap: deps, build, test
