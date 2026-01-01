package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/nigpig/nigpig/internal/core"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "NigPig çalışma alanı oluştur",
	Long: `NigPig çalışma alanını ve varsayılan yapılandırma dosyalarını oluşturur.

Oluşturulan dosyalar:
  ~/.nigpig/config.yaml        - Ana yapılandırma
  ~/.nigpig/profiles/          - Tarama profilleri
  ~/.nigpig/workspaces/        - Hedef çalışma alanları

Windows'ta: %APPDATA%\NigPig veya ~/.nigpig`,
	Example: `  nigpig init
  nigpig init --force  # Mevcut dosyaları üzerine yaz`,
	Run: runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)
	initCmd.Flags().Bool("force", false, "Mevcut dosyaları üzerine yaz")
}

func runInit(cmd *cobra.Command, args []string) {
	force, _ := cmd.Flags().GetBool("force")

	fmt.Println()
	color.Cyan("🐷 NigPig Çalışma Alanı Kurulumu")
	fmt.Println()

	nigpigHome := core.GetNigPigHome()
	printStep("NigPig home: " + nigpigHome)

	// Create directories
	dirs := []string{
		nigpigHome,
		filepath.Join(nigpigHome, "workspaces"),
		filepath.Join(nigpigHome, "profiles"),
		filepath.Join(nigpigHome, "templates"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			printError("Klasör oluşturulamadı: " + dir)
			return
		}
	}
	printSuccess("Klasörler oluşturuldu")

	// Create config file
	configPath := filepath.Join(nigpigHome, "config.yaml")
	if !fileExists(configPath) || force {
		if err := createDefaultConfig(configPath); err != nil {
			printError("config.yaml oluşturulamadı: " + err.Error())
		} else {
			printSuccess("config.yaml oluşturuldu")
		}
	} else {
		printInfo("config.yaml zaten mevcut (--force ile üzerine yazabilirsiniz)")
	}

	// Create profiles
	profiles := map[string]string{
		"stealth.yaml":    stealthProfileContent,
		"balanced.yaml":   balancedProfileContent,
		"aggressive.yaml": aggressiveProfileContent,
	}

	for name, content := range profiles {
		profilePath := filepath.Join(nigpigHome, "profiles", name)
		if !fileExists(profilePath) || force {
			if err := core.WriteFileAtomic(profilePath, []byte(content), 0644); err != nil {
				printError(name + " oluşturulamadı")
			} else {
				printSuccess(name + " oluşturuldu")
			}
		}
	}

	// Create example scope
	scopePath := filepath.Join(nigpigHome, "scope.example.yaml")
	if !fileExists(scopePath) || force {
		if err := core.WriteFileAtomic(scopePath, []byte(exampleScopeContent), 0644); err != nil {
			printError("scope.example.yaml oluşturulamadı")
		} else {
			printSuccess("scope.example.yaml oluşturuldu")
		}
	}

	// Summary
	fmt.Println()
	color.Green("✅ NigPig çalışma alanı hazır!")
	fmt.Println()
	fmt.Println("Sonraki adımlar:")
	fmt.Println("  1. nigpig doctor        # Bağımlılıkları kontrol et")
	fmt.Println("  2. nigpig carrot        # Taramaya başla")
	fmt.Println()

	// Write report
	details := map[string]interface{}{
		"home":     nigpigHome,
		"profiles": len(profiles),
		"force":    force,
	}
	reportPath := WriteCommandReport("init", true, "", details)
	if reportPath != "" {
		color.White("📄 Rapor: %s", reportPath)
		fmt.Println()
	}
}

func createDefaultConfig(path string) error {
	content := `# NigPig Yapılandırması
# Oluşturulma: ` + core.CurrentTime().Format("2006-01-02 15:04:05") + `

general:
  verbose: false
  json_output: false
  language: "tr"

default_profile: "balanced"

workspace:
  auto_cleanup_days: 30

notifications:
  telegram:
    enabled: false
    bot_token: ""
    chat_id: ""
  
  discord:
    enabled: false
    webhook_url: ""
  
  slack:
    enabled: false
    webhook_url: ""

security:
  destructive_tests: false
  brute_force: false
  auth_testing: false
  redact_secrets: true

cache:
  ttl_days: 7
  max_size_mb: 500

logging:
  level: "info"
`
	return core.WriteFileAtomic(path, []byte(content), 0644)
}

const stealthProfileContent = `# Stealth Profile
name: "stealth"
description: "Düşük yoğunluklu, gizli tarama"

budgets:
  max_runtime_hours: 24
  max_requests_per_hour: 100
  max_concurrency: 2
  max_new_urls_per_cycle: 10000

cycle:
  interval_minutes: 120
  delta_only_mode: true

network:
  timeout_seconds: 30
  retries: 2
  backoff: "exponential"
  jitter_ms: 2000

safety:
  passive_only: true
  no_auth: true
  no_destructive: true
  no_cloud: true
`

const balancedProfileContent = `# Balanced Profile
name: "balanced"
description: "Dengeli tarama profili - varsayılan"

budgets:
  max_runtime_hours: 12
  max_requests_per_hour: 1000
  max_concurrency: 10
  max_new_urls_per_cycle: 50000

cycle:
  interval_minutes: 60
  delta_only_mode: true

network:
  timeout_seconds: 15
  retries: 2
  backoff: "exponential"
  jitter_ms: 500

safety:
  passive_only: false
  no_auth: true
  no_destructive: true
  no_cloud: true
`

const aggressiveProfileContent = `# Aggressive Profile
name: "aggressive"
description: "Yüksek hızlı tarama"

budgets:
  max_runtime_hours: 6
  max_requests_per_hour: 5000
  max_concurrency: 50
  max_new_urls_per_cycle: 100000

cycle:
  interval_minutes: 30
  delta_only_mode: true

network:
  timeout_seconds: 10
  retries: 3
  backoff: "linear"
  jitter_ms: 100

safety:
  passive_only: false
  no_auth: true
  no_destructive: true
  no_cloud: false
`

const exampleScopeContent = `# NigPig Scope Örneği
# Bu dosyayı kopyalayıp hedefinize göre düzenleyin

program: "example-program"
target: "example.com"

in_scope:
  domains:
    - "example.com"
    - "*.example.com"
  ports:
    - 80
    - 443

out_of_scope:
  domains:
    - "blog.example.com"
  paths:
    - "/logout"
    - "/delete-*"

rules:
  destructive_tests: false
  brute_force: false
  auth_testing: false
  rate_limit: 10
`
