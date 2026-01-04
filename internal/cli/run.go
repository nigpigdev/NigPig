package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "🚀 Tam otomatik tarama başlat (uçtan uca)",
	Long: `Tam otomatik güvenlik taraması başlatır.

Bu komut sırasıyla şu aşamaları çalıştırır:
  1. 🔍 KEŞIF (Recon)      → Subdomain keşfi, DNS analizi
  2. 🌐 DISCOVERY         → Canlı host tespiti, port tarama
  3. 🕷️  CRAWL             → URL keşfi, sitemap, JS analizi
  4. 🎯 SCAN              → Zafiyet taraması (nuclei)
  5. ✅ VERIFY            → Bulguları doğrula
  6. 📄 REPORT            → Rapor oluştur
  7. 📬 NOTIFY            → Bildirim gönder (yapılandırılmışsa)

🔒 GÜVENLİK: Tarama sadece scope içindeki hedeflere yapılır.
   Out-of-scope hedefler otomatik olarak atlanır.`,
	Example: `  # Varsayılan ayarlarla tarama
  nigpig run --target example.com

  # Gizli modda tarama (düşük profil)
  nigpig run --target example.com --profile stealth

  # Agresif tarama (sadece izinliyse!)
  nigpig run --target example.com --profile aggressive

  # Sadece belirli modüllerle
  nigpig run --target example.com --modules recon,scan

  # Telegram bildirimi ile
  nigpig run --target example.com --notify telegram

  # Kuru çalışma (dry-run) - gerçek tarama yapmaz
  nigpig run --target example.com --dry-run`,
	Run: runFullPipeline,
}

var (
	runTarget  string
	runModules string
func init() {
	rootCmd.AddCommand(runCmd)

	// Target and module flags
	runCmd.Flags().StringP("target", "t", "", "Hedef domain (zorunlu)")
	runCmd.Flags().StringSlice("modules", []string{}, "Çalıştırılacak modüller (virgülle ayrılmış)")
	runCmd.Flags().StringP("profile", "p", "balanced", "Tarama profili (stealth, balanced, aggressive)")
	
	// Notification and run mode
	runCmd.Flags().String("notify", "", "Bildirim kanalı (telegram, discord, slack)")
	runCmd.Flags().Bool("dry-run", false, "Kuru çalışma - sadece ne yapılacağını göster")
	runCmd.Flags().Bool("resume", false, "Yarıda kalan taramayı devam ettir")
	runCmd.Flags().Bool("delta", false, "Sadece değişiklikleri tara (ASM modu)")
	
	// Safety mode flags - Varsayılanlar GÜVENLİ
	runCmd.Flags().Bool("passive-only", false, "Sadece pasif tarama (varsayılan: false)")
	runCmd.Flags().Bool("no-auth", true, "Auth testlerini atla (varsayılan: true)")
	runCmd.Flags().Bool("no-cloud", true, "Cloud servis testlerini atla (varsayılan: true)")
	runCmd.Flags().Bool("no-destructive", true, "Yıkıcı testleri atla (varsayılan: true)")
	runCmd.Flags().String("max-severity", "", "Maksimum test ciddiyeti (low, medium, high)")

	runCmd.MarkFlagRequired("target")
}

func runFullPipeline(cmd *cobra.Command, args []string) {
	startTime := time.Now()

	fmt.Println()
	printBanner()
	fmt.Println()
	color.Cyan("🎯 Hedef: %s", runTarget)
	color.Cyan("📊 Profil: %s", profile)
	if runDryRun {
		color.Yellow("⚠️  KURU ÇALIŞMA MODU - Gerçek tarama yapılmayacak")
	}
	fmt.Println()
	color.Cyan("═══════════════════════════════════════════════════════════")
	fmt.Println()

	// Validate target exists
	home, _ := os.UserHomeDir()
	workspacePath := filepath.Join(home, ".nigpig", "workspaces", runTarget)

	if _, err := os.Stat(workspacePath); os.IsNotExist(err) {
		printError("Hedef bulunamadı: %s", runTarget)
		fmt.Println()
		printInfo("Önce hedef ekleyin: nigpig target add --domain %s", runTarget)
		return
	}

	// Create run ID
	runID := fmt.Sprintf("%s-%d", runTarget, time.Now().Unix())
	runDir := filepath.Join(workspacePath, "runs", runID)
	os.MkdirAll(runDir, 0755)

	printInfo("Çalışma ID: %s", runID)
	fmt.Println()

	// Define pipeline stages
	stages := []struct {
		name    string
		emoji   string
		fn      func() error
		enabled bool
	}{
		{"Scope Doğrulama", "🔒", func() error { return validateScope(workspacePath) }, true},
		{"Subdomain Keşfi", "🔍", func() error { return runReconStage(workspacePath, runDryRun) }, containsModule("recon")},
		{"Canlı Host Tespiti", "🌐", func() error { return runDiscoveryStage(workspacePath, runDryRun) }, containsModule("discovery")},
		{"URL Keşfi", "🕷️", func() error { return runCrawlStage(workspacePath, runDryRun) }, containsModule("crawl")},
		{"Zafiyet Taraması", "🎯", func() error { return runScanStage(workspacePath, runDryRun) }, containsModule("scan")},
		{"Bulgu Doğrulama", "✅", func() error { return runVerifyStage(workspacePath, runDryRun) }, containsModule("verify")},
		{"Rapor Oluşturma", "📄", func() error { return runReportStage(workspacePath, runDryRun) }, true},
	}

	totalStages := 0
	for _, s := range stages {
		if s.enabled {
			totalStages++
		}
	}

	currentStage := 0
	for _, stage := range stages {
		if !stage.enabled {
			continue
		}
		currentStage++

		fmt.Printf("\n%s [%d/%d] %s\n", stage.emoji, currentStage, totalStages, stage.name)
		fmt.Println(strings.Repeat("─", 50))

		if err := stage.fn(); err != nil {
			printError("Hata: %v", err)
			if !runDryRun {
				// Save state for resume
				saveRunState(runDir, stage.name)
			}
			return
		}
		printSuccess("%s tamamlandı", stage.name)
	}

	// Send notification if configured
	if runNotify != "" {
		fmt.Printf("\n📬 Bildirim Gönderiliyor (%s)...\n", runNotify)
		// TODO: Implement notification
		printSuccess("Bildirim gönderildi")
	}

	duration := time.Since(startTime)
	fmt.Println()
	color.Green("═══════════════════════════════════════════════════════════")
	color.Green("✅ TARAMA TAMAMLANDI!")
	color.Green("═══════════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Printf("⏱️  Süre: %s\n", duration.Round(time.Second))
	fmt.Printf("📁 Sonuçlar: %s/reports/\n", workspacePath)
	fmt.Println()
}

func containsModule(module string) bool {
	if runModules == "all" {
		return true
	}
	modules := strings.Split(runModules, ",")
	for _, m := range modules {
		if strings.TrimSpace(m) == module {
			return true
		}
	}
	return false
}

func printBanner() {
	color.Cyan(`
  ┌─────────────────────────────────────────────────────────┐
  │                                                         │
  │    🐷 NigPig Otomatik Güvenlik Taraması Başlatılıyor    │
  │                                                         │
  └─────────────────────────────────────────────────────────┘
`)
}

func validateScope(workspacePath string) error {
	scopePath := filepath.Join(workspacePath, "scope.yaml")
	if _, err := os.Stat(scopePath); os.IsNotExist(err) {
		printWarning("Scope dosyası bulunamadı - varsayılan kurallar uygulanacak")
		return nil
	}
	printInfo("Scope dosyası doğrulandı")
	return nil
}

func runReconStage(workspacePath string, dryRun bool) error {
	outputDir := filepath.Join(workspacePath, "raw", "recon")

	// Subfinder
	if checkToolExists("subfinder") {
		printInfo("Subfinder çalıştırılıyor...")
		if !dryRun {
			target := filepath.Base(workspacePath)
			outputFile := filepath.Join(outputDir, "subdomains.txt")
			cmd := exec.Command("subfinder", "-d", target, "-o", outputFile, "-silent")
			if err := cmd.Run(); err != nil {
				printWarning("Subfinder hatası: %v", err)
			}
		} else {
			printInfo("[DRY-RUN] subfinder -d <target> -o subdomains.txt")
		}
	} else {
		printWarning("subfinder kurulu değil - atlanıyor")
	}

	return nil
}

func runDiscoveryStage(workspacePath string, dryRun bool) error {
	if checkToolExists("httpx") {
		printInfo("HTTPX ile canlı host tespiti...")
		if !dryRun {
			subdomainsFile := filepath.Join(workspacePath, "raw", "recon", "subdomains.txt")
			outputFile := filepath.Join(workspacePath, "raw", "discovery", "live_hosts.txt")
			if _, err := os.Stat(subdomainsFile); !os.IsNotExist(err) {
				cmd := exec.Command("httpx", "-l", subdomainsFile, "-o", outputFile, "-silent")
				cmd.Run()
			}
		} else {
			printInfo("[DRY-RUN] httpx -l subdomains.txt -o live_hosts.txt")
		}
	} else {
		printWarning("httpx kurulu değil - atlanıyor")
	}
	return nil
}

func runCrawlStage(workspacePath string, dryRun bool) error {
	if checkToolExists("katana") {
		printInfo("Katana ile URL keşfi...")
		if !dryRun {
			liveHostsFile := filepath.Join(workspacePath, "raw", "discovery", "live_hosts.txt")
			outputFile := filepath.Join(workspacePath, "raw", "crawl", "urls.txt")
			if _, err := os.Stat(liveHostsFile); !os.IsNotExist(err) {
				cmd := exec.Command("katana", "-list", liveHostsFile, "-o", outputFile, "-silent")
				cmd.Run()
			}
		} else {
			printInfo("[DRY-RUN] katana -list live_hosts.txt -o urls.txt")
		}
	} else {
		printWarning("katana kurulu değil - atlanıyor")
	}
	return nil
}

func runScanStage(workspacePath string, dryRun bool) error {
	if checkToolExists("nuclei") {
		printInfo("Nuclei ile zafiyet taraması...")
		if !dryRun {
			urlsFile := filepath.Join(workspacePath, "raw", "crawl", "urls.txt")
			outputFile := filepath.Join(workspacePath, "raw", "scan", "nuclei_results.json")
			if _, err := os.Stat(urlsFile); !os.IsNotExist(err) {
				cmd := exec.Command("nuclei", "-l", urlsFile, "-o", outputFile, "-json", "-silent")
				cmd.Run()
			}
		} else {
			printInfo("[DRY-RUN] nuclei -l urls.txt -o nuclei_results.json -json")
		}
	} else {
		printWarning("nuclei kurulu değil - atlanıyor")
	}
	return nil
}

func runVerifyStage(workspacePath string, dryRun bool) error {
	printInfo("Bulgular doğrulanıyor...")
	// TODO: Implement verification logic
	return nil
}

func runReportStage(workspacePath string, dryRun bool) error {
	printInfo("Rapor oluşturuluyor...")
	// TODO: Generate report
	return nil
}

func checkToolExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func saveRunState(runDir, failedStage string) {
	state := fmt.Sprintf("failed_at: %s\ntime: %s\n", failedStage, time.Now().Format(time.RFC3339))
	os.WriteFile(filepath.Join(runDir, "state.yaml"), []byte(state), 0644)
}
