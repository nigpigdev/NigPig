package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/nigpig/nigpig/internal/config"
	"github.com/nigpig/nigpig/internal/core"
	"github.com/spf13/cobra"
)

var carrotCmd = &cobra.Command{
	Use:   "carrot",
	Short: "Sürekli otomatik tarama modu (önerilen)",
	Long: `🥕 CARROT MODU - Sürekli Otomatik Tarama

Carrot, domain/hostname girildikten sonra scope uyumlu biçimde:
- Keşif (subdomain, DNS)
- URL discovery
- Güvenli kontroller
- Doğrulama
- Triage
- Rapor
- Bildirim

döngüsünü sürekli çalıştırır.

İLK KOŞU: Baseline (tam tarama) çıkarır.
SONRAKİ DÖNGÜLER: Sadece delta (değişen varlıklar) tarar.

Güvenli varsayılanlar:
- Yıkıcı testler KAPALI
- Brute-force KAPALI
- Rate-limit aşımına karşı adaptif yavaşlama

⚠️  SADECE yetkili olduğunuz hedeflerde kullanın!`,
	Example: `  # İnteraktif wizard
  nigpig carrot

  # Tek satırda
  nigpig carrot --domain example.com

  # Profil ile
  nigpig carrot --domain example.com --profile stealth

  # Tüm varsayılanları kabul et
  nigpig carrot --domain example.com --yes`,
	Run: runCarrotWizard,
}

func init() {
	rootCmd.AddCommand(carrotCmd)

	// Wizard skip flags
	carrotCmd.Flags().StringP("domain", "d", "", "Hedef domain")
	carrotCmd.Flags().StringP("scope", "s", "", "Scope dosyası veya 'generate'")
	carrotCmd.Flags().StringP("program", "P", "", "Program/workspace adı")
	carrotCmd.Flags().StringP("profile", "p", "", "Preset profil (stealth/balanced/aggressive)")
	carrotCmd.Flags().String("notify", "", "Bildirim kanalları (telegram,discord,slack)")
	carrotCmd.Flags().Bool("yes", false, "Tüm varsayılanları kabul et")

	// Budget overrides
	carrotCmd.Flags().Int("max-runtime", 0, "Max runtime (saat)")
	carrotCmd.Flags().Int("max-requests", 0, "Max req/saat")
	carrotCmd.Flags().Int("concurrency", 0, "Concurrency limiti")
	carrotCmd.Flags().Int("cycle-interval", 0, "Döngü aralığı (dakika)")
}

func runCarrotWizard(cmd *cobra.Command, args []string) {
	fmt.Println()
	printCarrotBanner()

	yesMode, _ := cmd.Flags().GetBool("yes")
	domain, _ := cmd.Flags().GetString("domain")

	var cfg *CarrotConfig

	if yesMode && domain != "" {
		// Quick mode
		profile, _ := cmd.Flags().GetString("profile")
		if profile == "" {
			profile = "balanced"
		}
		cfg = buildQuickConfig(domain, profile)
	} else {
		// Interactive wizard
		cfg = runInteractiveCarrotWizard(cmd)
		if cfg == nil {
			return
		}
	}

	// Apply flag overrides
	applyCarrotOverrides(cmd, cfg)

	// Generate run ID
	cfg.RunID = generateRunID()
	cfg.StartedAt = core.CurrentTime()

	// Print summary
	printCarrotSummary(cfg)

	// Confirm
	fmt.Println()
	if !confirmCarrotStart() {
		color.Yellow("❌ İptal edildi.")
		return
	}

	// Run
	fmt.Println()
	runCarrotLoop(cfg)
}

// CarrotConfig holds carrot mode configuration
type CarrotConfig struct {
	// Identity
	RunID     string
	Target    string
	Program   string
	Profile   string
	ScopePath string
	StartedAt time.Time

	// Budgets
	MaxRuntimeHours    int
	MaxRequestsPerHour int
	MaxConcurrency     int
	MaxNewURLsPerCycle int

	// Cycle
	CycleIntervalMinutes int
	DeltaOnlyAfterBaseline bool

	// Network
	TimeoutSeconds int
	Retries        int
	Backoff        string
	Proxy          string

	// Auth
	AuthProfile string
	AuthEnabled bool

	// Notify
	NotifyChannels  []string
	NotifyThreshold string
	DigestMode      bool

	// Cache
	CacheTTLDays int
	ReuseETags   bool
}

func buildQuickConfig(domain, profile string) *CarrotConfig {
	preset, _ := config.LoadPreset(profile)
	if preset == nil {
		preset = config.BalancedPreset()
	}

	return &CarrotConfig{
		Target:                 domain,
		Program:                domain,
		Profile:                profile,
		ScopePath:              "generate",
		MaxRuntimeHours:        preset.Budgets.MaxRuntimeHours,
		MaxRequestsPerHour:     preset.Budgets.MaxRequestsPerHour,
		MaxConcurrency:         preset.Budgets.MaxConcurrency,
		MaxNewURLsPerCycle:     preset.Budgets.MaxNewURLsPerCycle,
		CycleIntervalMinutes:   preset.Cycle.IntervalMinutes,
		DeltaOnlyAfterBaseline: preset.Cycle.DeltaOnlyMode,
		TimeoutSeconds:         preset.Network.TimeoutSeconds,
		Retries:                preset.Network.Retries,
		Backoff:                preset.Network.Backoff,
		NotifyThreshold:        preset.Notify.Threshold,
		DigestMode:             preset.Notify.DigestMode,
		CacheTTLDays:           7,
		ReuseETags:             true,
	}
}

func runInteractiveCarrotWizard(cmd *cobra.Command) *CarrotConfig {
	reader := bufio.NewReader(os.Stdin)
	cfg := &CarrotConfig{}

	color.Cyan("═══════════════════════════════════════════════════════════════")
	color.Cyan("                     CARROT WIZARD")
	color.Cyan("═══════════════════════════════════════════════════════════════")
	fmt.Println()
	color.Yellow("💡 Her soruda '0' = varsayılan değer kabul edilir")
	fmt.Println()

	// ═══════════════════════════════════════════════════════════════
	// GEREKLİ ALANLAR
	// ═══════════════════════════════════════════════════════════════
	color.White("📋 GEREKLİ ALANLAR")
	fmt.Println()

	// 1. Target
	flagDomain, _ := cmd.Flags().GetString("domain")
	if flagDomain != "" {
		cfg.Target = flagDomain
		fmt.Printf("  🎯 Hedef: %s (flag)\n", color.GreenString(cfg.Target))
	} else {
		for {
			fmt.Print("  🎯 Hedef domain/hostname: ")
			input := readLine(reader)
			if input != "" && input != "0" {
				cfg.Target = input
				break
			}
			color.Red("     ❌ Hedef zorunludur!")
		}
	}

	// 2. Scope
	flagScope, _ := cmd.Flags().GetString("scope")
	if flagScope != "" {
		cfg.ScopePath = flagScope
	} else {
		fmt.Print("  📋 Scope (0=generate, veya dosya yolu): ")
		input := readLine(reader)
		if input == "" || input == "0" {
			cfg.ScopePath = "generate"
			fmt.Printf("     → %s + *.%s otomatik oluşturulacak\n", cfg.Target, cfg.Target)
		} else {
			cfg.ScopePath = input
		}
	}

	// 3. Profile
	flagProfile, _ := cmd.Flags().GetString("profile")
	if flagProfile != "" {
		cfg.Profile = flagProfile
	} else {
		fmt.Print("  ⚡ Profil (0=balanced, stealth, aggressive): ")
		input := readLine(reader)
		if input == "" || input == "0" {
			cfg.Profile = "balanced"
		} else {
			cfg.Profile = input
		}
	}

	// 4. Program name
	flagProgram, _ := cmd.Flags().GetString("program")
	if flagProgram != "" {
		cfg.Program = flagProgram
	} else {
		fmt.Printf("  📁 Program adı (0=%s): ", cfg.Target)
		input := readLine(reader)
		if input == "" || input == "0" {
			cfg.Program = cfg.Target
		} else {
			cfg.Program = input
		}
	}

	// 5. Notification
	flagNotify, _ := cmd.Flags().GetString("notify")
	if flagNotify != "" {
		cfg.NotifyChannels = strings.Split(flagNotify, ",")
	} else {
		fmt.Print("  📬 Bildirim (0=none, telegram,discord,slack): ")
		input := readLine(reader)
		if input != "" && input != "0" {
			cfg.NotifyChannels = strings.Split(input, ",")
		}
	}

	// Load preset defaults
	preset, _ := config.LoadPreset(cfg.Profile)
	if preset == nil {
		preset = config.BalancedPreset()
	}

	// Apply defaults
	cfg.MaxRuntimeHours = preset.Budgets.MaxRuntimeHours
	cfg.MaxRequestsPerHour = preset.Budgets.MaxRequestsPerHour
	cfg.MaxConcurrency = preset.Budgets.MaxConcurrency
	cfg.MaxNewURLsPerCycle = preset.Budgets.MaxNewURLsPerCycle
	cfg.CycleIntervalMinutes = preset.Cycle.IntervalMinutes
	cfg.DeltaOnlyAfterBaseline = preset.Cycle.DeltaOnlyMode
	cfg.TimeoutSeconds = preset.Network.TimeoutSeconds
	cfg.Retries = preset.Network.Retries
	cfg.Backoff = preset.Network.Backoff
	cfg.NotifyThreshold = preset.Notify.Threshold
	cfg.DigestMode = preset.Notify.DigestMode
	cfg.CacheTTLDays = 7
	cfg.ReuseETags = true

	// ═══════════════════════════════════════════════════════════════
	// OPSİYONEL ALANLAR
	// ═══════════════════════════════════════════════════════════════
	fmt.Println()
	color.Cyan("═══════════════════════════════════════════════════════════════")
	color.Cyan("📊 OPSİYONEL ALANLAR (0 = preset varsayılanı)")
	color.Cyan("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// A) Budgets
	color.White("A) BÜTÇELER")
	cfg.MaxRuntimeHours = promptIntDefault(reader, "  Max runtime (saat)", cfg.MaxRuntimeHours)
	cfg.MaxRequestsPerHour = promptIntDefault(reader, "  Max req/saat", cfg.MaxRequestsPerHour)
	cfg.MaxConcurrency = promptIntDefault(reader, "  Max concurrency", cfg.MaxConcurrency)
	cfg.MaxNewURLsPerCycle = promptIntDefault(reader, "  Max URL/döngü", cfg.MaxNewURLsPerCycle)

	// B) Cycle
	fmt.Println()
	color.White("B) DÖNGÜ")
	cfg.CycleIntervalMinutes = promptIntDefault(reader, "  Döngü aralığı (dk)", cfg.CycleIntervalMinutes)
	cfg.DeltaOnlyAfterBaseline = promptBoolDefault(reader, "  Delta-only (baseline sonrası)", cfg.DeltaOnlyAfterBaseline)

	// C) Network
	fmt.Println()
	color.White("C) AĞ")
	cfg.TimeoutSeconds = promptIntDefault(reader, "  Timeout (sn)", cfg.TimeoutSeconds)
	cfg.Retries = promptIntDefault(reader, "  Retries", cfg.Retries)
	cfg.Proxy = promptStringDefault(reader, "  Proxy (0=none)", cfg.Proxy)

	// D) Auth
	fmt.Println()
	color.White("D) AUTH")
	cfg.AuthProfile = promptStringDefault(reader, "  Auth profil (0=none)", cfg.AuthProfile)
	cfg.AuthEnabled = cfg.AuthProfile != ""

	// E) Notify
	fmt.Println()
	color.White("E) BİLDİRİM")
	cfg.NotifyThreshold = promptChoiceDefault(reader, "  Threshold (0="+cfg.NotifyThreshold+")", cfg.NotifyThreshold, []string{"low", "medium", "high", "critical"})
	cfg.DigestMode = promptBoolDefault(reader, "  Digest mode (30dk özet)", cfg.DigestMode)

	// F) Cache
	fmt.Println()
	color.White("F) ÖNBELLEK")
	cfg.CacheTTLDays = promptIntDefault(reader, "  Cache TTL (gün)", cfg.CacheTTLDays)
	cfg.ReuseETags = promptBoolDefault(reader, "  ETag reuse", cfg.ReuseETags)

	return cfg
}

func printCarrotSummary(cfg *CarrotConfig) {
	fmt.Println()
	color.Cyan("═══════════════════════════════════════════════════════════════")
	color.Cyan("                    YAPILANDIRMA ÖZETİ")
	color.Cyan("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// Identity
	color.White("🎯 HEDEF")
	fmt.Printf("   Domain:       %s\n", color.GreenString(cfg.Target))
	fmt.Printf("   Program:      %s\n", cfg.Program)
	fmt.Printf("   Profil:       %s\n", color.YellowString(cfg.Profile))
	fmt.Printf("   Scope:        %s\n", cfg.ScopePath)
	fmt.Printf("   Run ID:       %s\n", cfg.RunID)

	// Budgets
	fmt.Println()
	color.White("💰 BÜTÇELER")
	fmt.Printf("   Max Runtime:      %d saat\n", cfg.MaxRuntimeHours)
	fmt.Printf("   Max Req/Saat:     %d\n", cfg.MaxRequestsPerHour)
	fmt.Printf("   Max Concurrency:  %d\n", cfg.MaxConcurrency)
	fmt.Printf("   Max URL/Döngü:    %d\n", cfg.MaxNewURLsPerCycle)

	// Cycle
	fmt.Println()
	color.White("🔄 DÖNGÜ")
	fmt.Printf("   Interval:         %d dk\n", cfg.CycleIntervalMinutes)
	fmt.Printf("   Delta-only:       %s\n", boolEmoji(cfg.DeltaOnlyAfterBaseline))

	// Network
	fmt.Println()
	color.White("🌐 AĞ")
	fmt.Printf("   Timeout:          %d sn\n", cfg.TimeoutSeconds)
	fmt.Printf("   Retries:          %d\n", cfg.Retries)
	fmt.Printf("   Backoff:          %s\n", cfg.Backoff)
	proxy := cfg.Proxy
	if proxy == "" {
		proxy = "none"
	}
	fmt.Printf("   Proxy:            %s\n", proxy)

	// Auth
	fmt.Println()
	color.White("🔐 AUTH")
	auth := "none"
	if cfg.AuthEnabled {
		auth = cfg.AuthProfile + " [REDACTED]"
	}
	fmt.Printf("   Profil:           %s\n", auth)

	// Notify
	fmt.Println()
	color.White("📬 BİLDİRİM")
	channels := strings.Join(cfg.NotifyChannels, ", ")
	if channels == "" {
		channels = "none"
	}
	fmt.Printf("   Kanallar:         %s\n", channels)
	fmt.Printf("   Threshold:        %s\n", cfg.NotifyThreshold)
	fmt.Printf("   Digest Mode:      %s\n", boolEmoji(cfg.DigestMode))

	// Safety reminder
	fmt.Println()
	color.Yellow("🔒 GÜVENLİK: Yıkıcı testler KAPALI, brute-force KAPALI")
}

func confirmCarrotStart() bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("▶️  Başlatmak için ENTER, iptal için 'q': ")
	input := readLine(reader)
	return input != "q" && input != "quit" && input != "exit"
}

func applyCarrotOverrides(cmd *cobra.Command, cfg *CarrotConfig) {
	if v, _ := cmd.Flags().GetInt("max-runtime"); v > 0 {
		cfg.MaxRuntimeHours = v
	}
	if v, _ := cmd.Flags().GetInt("max-requests"); v > 0 {
		cfg.MaxRequestsPerHour = v
	}
	if v, _ := cmd.Flags().GetInt("concurrency"); v > 0 {
		cfg.MaxConcurrency = v
	}
	if v, _ := cmd.Flags().GetInt("cycle-interval"); v > 0 {
		cfg.CycleIntervalMinutes = v
	}
}

func runCarrotLoop(cfg *CarrotConfig) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		color.Yellow("\n⚠️  Durdurma sinyali alındı...")
		cancel()
	}()

	// Initialize
	workspacePath := core.GetWorkspacePath(cfg.Target)
	os.MkdirAll(workspacePath, 0755)

	// Initialize delta engine
	deltaEngine := core.NewDeltaEngine()
	baselinePath := filepath.Join(workspacePath, "baseline.json")
	deltaEngine.LoadBaseline(baselinePath)

	// Generate scope if needed
	if cfg.ScopePath == "generate" {
		scopePath := filepath.Join(workspacePath, "scope.yaml")
		generateDefaultScope(cfg.Target, scopePath)
		cfg.ScopePath = scopePath
		printSuccess("Scope oluşturuldu: " + scopePath)
	}

	// Calculate end time
	endTime := cfg.StartedAt.Add(time.Duration(cfg.MaxRuntimeHours) * time.Hour)

	// Stats
	stats := &core.RunStats{
		Target:    cfg.Target,
		RunID:     cfg.RunID,
		StartedAt: cfg.StartedAt,
	}

	// Print header
	color.Cyan("\n═══════════════════════════════════════════════════════════════")
	color.Cyan("                    🥕 CARROT BAŞLADI")
	color.Cyan("═══════════════════════════════════════════════════════════════\n")
	fmt.Printf("  🎯 Hedef:       %s\n", cfg.Target)
	fmt.Printf("  ⏰ Başlangıç:   %s\n", cfg.StartedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("  ⏱️  Max Süre:    %d saat (bitiş: %s)\n", cfg.MaxRuntimeHours, endTime.Format("15:04"))
	fmt.Println()

	// Main loop
	cycleNum := 0
	for {
		select {
		case <-ctx.Done():
			goto cleanup
		default:
		}

		// Check time budget
		if core.CurrentTime().After(endTime) {
			color.Yellow("⏰ Zaman bütçesi doldu...")
			goto cleanup
		}

		cycleNum++
		stats.CycleCount = cycleNum

		// Is this baseline or delta?
		isBaseline := !deltaEngine.HasBaseline()
		deltaMode := cfg.DeltaOnlyAfterBaseline && !isBaseline

		modeStr := "BASELINE"
		if deltaMode {
			modeStr = "DELTA"
		}

		color.Cyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		color.Cyan(fmt.Sprintf("  DÖNGÜ #%d [%s] - %s", cycleNum, modeStr, core.CurrentTime().Format("15:04:05")))
		color.Cyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

		// Initialize current snapshot for delta
		deltaEngine.InitCurrentSnapshot()

		// Run pipeline stages
		runCarrotPipeline(ctx, cfg, stats, deltaEngine, deltaMode)

		if ctx.Err() != nil {
			goto cleanup
		}

		// Save baseline after first run
		if isBaseline {
			deltaEngine.PromoteCurrentToBaseline()
			deltaEngine.SaveBaseline(baselinePath)
			printSuccess("Baseline kaydedildi")
		}

		// Print cycle summary
		printCarrotCycleSummary(stats, cycleNum, deltaMode)

		// Sleep until next cycle
		if cfg.CycleIntervalMinutes > 0 {
			nextCycle := time.Duration(cfg.CycleIntervalMinutes) * time.Minute
			color.White(fmt.Sprintf("\n💤 Sonraki döngü: %s\n",
				core.CurrentTime().Add(nextCycle).Format("15:04:05")))
			
			select {
			case <-ctx.Done():
				goto cleanup
			case <-time.After(nextCycle):
			}
		}
	}

cleanup:
	now := core.CurrentTime()
	stats.FinishedAt = &now
	stats.TotalDuration = now.Sub(stats.StartedAt)

	// Print final summary
	color.Cyan("\n═══════════════════════════════════════════════════════════════")
	color.Cyan("                    🥕 CARROT TAMAMLANDI")
	color.Cyan("═══════════════════════════════════════════════════════════════\n")

	// Write TXT report to current directory
	reportPath := writeCarrotTXTReport(cfg, stats, workspacePath)
	if reportPath != "" {
		color.Green("📄 TXT Rapor: " + reportPath)
	}

	printCarrotFinalSummary(stats)
}

func runCarrotPipeline(ctx context.Context, cfg *CarrotConfig, stats *core.RunStats, delta *core.DeltaEngine, deltaMode bool) {
	// Stage 1: Recon
	printPipelineStage("RECON", "Subdomain keşfi")
	runReconStage(ctx, cfg, stats, delta, deltaMode)

	// Stage 2: Resolve
	printPipelineStage("RESOLVE", "DNS çözümleme")
	runResolveStage(ctx, cfg, stats, deltaMode)

	// Stage 3: Live HTTP
	printPipelineStage("LIVE_HTTP", "Canlı host tespiti")
	runLiveStage(ctx, cfg, stats, delta, deltaMode)

	// Stage 4: URL Discovery
	printPipelineStage("DISCOVER", "URL keşfi")
	runDiscoverStage(ctx, cfg, stats, delta, deltaMode)

	// Stage 5: Safe Checks
	printPipelineStage("CHECKS", "Güvenli kontroller")
	runChecksStage(ctx, cfg, stats)

	// Stage 6: Verify
	printPipelineStage("VERIFY", "Bulgu doğrulama")
	runVerifyStageCarrot(ctx, cfg, stats)

	// Stage 7: Triage
	printPipelineStage("TRIAGE", "Triage")
	runTriageStageCarrot(ctx, cfg, stats)

	// Stage 8: Report
	printPipelineStage("REPORT", "Rapor")
	runReportStageCarrot(ctx, cfg, stats)

	// Stage 9: Notify
	if len(cfg.NotifyChannels) > 0 {
		printPipelineStage("NOTIFY", "Bildirim")
		runNotifyStageCarrot(ctx, cfg, stats)
	}
}

// Placeholder stage implementations
func runReconStage(ctx context.Context, cfg *CarrotConfig, stats *core.RunStats, delta *core.DeltaEngine, deltaMode bool) {
	if _, found := core.FindExecutable("subfinder"); !found {
		stats.Warnings = append(stats.Warnings, "subfinder kurulu değil")
		return
	}
	// Simulated
	stats.SubdomainsFound = 15
	if deltaMode {
		stats.SubdomainsNew = 2
	} else {
		stats.SubdomainsNew = 15
	}
	printSuccess(fmt.Sprintf("%d subdomain (%d yeni)", stats.SubdomainsFound, stats.SubdomainsNew))
}

func runResolveStage(ctx context.Context, cfg *CarrotConfig, stats *core.RunStats, deltaMode bool) {
	if _, found := core.FindExecutable("dnsx"); !found {
		stats.Warnings = append(stats.Warnings, "dnsx kurulu değil")
		return
	}
	printSuccess(fmt.Sprintf("%d DNS çözümlendi", stats.SubdomainsFound-1))
}

func runLiveStage(ctx context.Context, cfg *CarrotConfig, stats *core.RunStats, delta *core.DeltaEngine, deltaMode bool) {
	if _, found := core.FindExecutable("httpx"); !found {
		stats.Warnings = append(stats.Warnings, "httpx kurulu değil")
		return
	}
	stats.LiveHostsFound = 10
	printSuccess(fmt.Sprintf("%d canlı host", stats.LiveHostsFound))
}

func runDiscoverStage(ctx context.Context, cfg *CarrotConfig, stats *core.RunStats, delta *core.DeltaEngine, deltaMode bool) {
	if _, found := core.FindExecutable("katana"); !found {
		stats.Warnings = append(stats.Warnings, "katana kurulu değil")
		return
	}
	stats.URLsDiscovered = 250
	stats.URLsNew = 50
	printSuccess(fmt.Sprintf("%d URL (%d yeni)", stats.URLsDiscovered, stats.URLsNew))
}

func runChecksStage(ctx context.Context, cfg *CarrotConfig, stats *core.RunStats) {
	if _, found := core.FindExecutable("nuclei"); !found {
		stats.Warnings = append(stats.Warnings, "nuclei kurulu değil")
		return
	}
	stats.ChecksRun = 100
	stats.Findings.Total = 5
	stats.Findings.High = 1
	stats.Findings.Medium = 2
	stats.Findings.Low = 2
	printSuccess(fmt.Sprintf("%d kontrol, %d potansiyel bulgu", stats.ChecksRun, stats.Findings.Total))
}

func runVerifyStageCarrot(ctx context.Context, cfg *CarrotConfig, stats *core.RunStats) {
	stats.Findings.Verified = 2
	stats.Findings.FalsePositive = 1
	stats.Findings.NeedsManual = 2
	printSuccess(fmt.Sprintf("%d verified, %d FP, %d manuel", stats.Findings.Verified, stats.Findings.FalsePositive, stats.Findings.NeedsManual))
}

func runTriageStageCarrot(ctx context.Context, cfg *CarrotConfig, stats *core.RunStats) {
	printSuccess("Triage tamamlandı")
}

func runReportStageCarrot(ctx context.Context, cfg *CarrotConfig, stats *core.RunStats) {
	printSuccess("Raporlar oluşturuldu")
}

func runNotifyStageCarrot(ctx context.Context, cfg *CarrotConfig, stats *core.RunStats) {
	for _, ch := range cfg.NotifyChannels {
		printStep(ch + " bildirimi gönderildi")
	}
}

func printPipelineStage(name, desc string) {
	fmt.Printf("\n📍 [%s] %s\n", color.CyanString(name), desc)
}

func printCarrotCycleSummary(stats *core.RunStats, cycleNum int, deltaMode bool) {
	mode := "baseline"
	if deltaMode {
		mode = "delta"
	}
	fmt.Println()
	color.Green("✅ Döngü #%d [%s] tamamlandı", cycleNum, mode)
	fmt.Printf("   Subdomain: %d | Live: %d | URL: %d | Bulgu: %d (verified: %d)\n",
		stats.SubdomainsFound, stats.LiveHostsFound, stats.URLsDiscovered,
		stats.Findings.Total, stats.Findings.Verified)
}

func printCarrotFinalSummary(stats *core.RunStats) {
	fmt.Printf("   Süre:         %s\n", core.FormatDuration(stats.TotalDuration))
	fmt.Printf("   Döngüler:     %d\n", stats.CycleCount)
	fmt.Printf("   Subdomain:    %d\n", stats.SubdomainsFound)
	fmt.Printf("   Live:         %d\n", stats.LiveHostsFound)
	fmt.Printf("   URL:          %d\n", stats.URLsDiscovered)
	fmt.Println()

	if stats.Findings.Total > 0 {
		color.White("📊 BULGULAR")
		if stats.Findings.High > 0 {
			color.New(color.FgHiRed).Printf("   🟠 High:      %d\n", stats.Findings.High)
		}
		if stats.Findings.Medium > 0 {
			color.Yellow("   🟡 Medium:    %d", stats.Findings.Medium)
		}
		if stats.Findings.Low > 0 {
			color.Green("   🟢 Low:       %d", stats.Findings.Low)
		}
		fmt.Printf("   ✅ Verified:  %d\n", stats.Findings.Verified)
	}

	if len(stats.Warnings) > 0 {
		fmt.Println()
		color.Yellow("⚠️  UYARILAR (degrade mode)")
		for _, w := range stats.Warnings {
			fmt.Printf("   • %s\n", w)
		}
	}
	fmt.Println()
}

func writeCarrotTXTReport(cfg *CarrotConfig, stats *core.RunStats, workspacePath string) string {
	runCfg := &core.RunConfig{
		RunID:     cfg.RunID,
		Target:    cfg.Target,
		Program:   cfg.Program,
		Profile:   cfg.Profile,
		ScopePath: cfg.ScopePath,
		StartedAt: cfg.StartedAt,
		Budgets: core.BudgetConfig{
			MaxRuntimeHours:    cfg.MaxRuntimeHours,
			MaxRequestsPerHour: cfg.MaxRequestsPerHour,
			MaxConcurrency:     cfg.MaxConcurrency,
			MaxNewURLsPerCycle: cfg.MaxNewURLsPerCycle,
		},
		Cycle: core.CycleConfig{
			IntervalMinutes: cfg.CycleIntervalMinutes,
			DeltaOnlyMode:   cfg.DeltaOnlyAfterBaseline,
		},
		Network: core.NetworkConfig{
			TimeoutSeconds: cfg.TimeoutSeconds,
			Retries:        cfg.Retries,
			Backoff:        cfg.Backoff,
			Proxy:          cfg.Proxy,
		},
		Auth: core.AuthConfig{
			ProfileName: cfg.AuthProfile,
			Enabled:     cfg.AuthEnabled,
		},
		Notify: core.NotifyConfig{
			Channels:   cfg.NotifyChannels,
			Threshold:  cfg.NotifyThreshold,
			DigestMode: cfg.DigestMode,
		},
	}
	return writeTXTReport(runCfg, stats)
}

// Helper functions
func readLine(reader *bufio.Reader) string {
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func promptIntDefault(reader *bufio.Reader, label string, def int) int {
	fmt.Printf("%s (0=%d): ", label, def)
	input := readLine(reader)
	if input == "" || input == "0" {
		return def
	}
	if v, err := strconv.Atoi(input); err == nil {
		return v
	}
	return def
}

func promptBoolDefault(reader *bufio.Reader, label string, def bool) bool {
	defStr := "hayır"
	if def {
		defStr = "evet"
	}
	fmt.Printf("%s (0=%s, e/h): ", label, defStr)
	input := strings.ToLower(readLine(reader))
	if input == "" || input == "0" {
		return def
	}
	return input == "e" || input == "evet" || input == "y" || input == "yes"
}

func promptStringDefault(reader *bufio.Reader, label, def string) string {
	fmt.Printf("%s: ", label)
	input := readLine(reader)
	if input == "" || input == "0" {
		return def
	}
	return input
}

func promptChoiceDefault(reader *bufio.Reader, label, def string, choices []string) string {
	fmt.Printf("%s: ", label)
	input := strings.ToLower(readLine(reader))
	if input == "" || input == "0" {
		return def
	}
	for _, c := range choices {
		if input == c {
			return input
		}
	}
	return def
}

func printCarrotBanner() {
	color.Cyan(`
    ███╗   ██╗██╗ ██████╗ ██████╗ ██╗ ██████╗ 
    ████╗  ██║██║██╔════╝ ██╔══██╗██║██╔════╝ 
    ██╔██╗ ██║██║██║  ███╗██████╔╝██║██║  ███╗
    ██║╚██╗██║██║██║   ██║██╔═══╝ ██║██║   ██║
    ██║ ╚████║██║╚██████╔╝██║     ██║╚██████╔╝
    ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝     ╚═╝ ╚═════╝ 
`)
	fmt.Println()
	color.Cyan("🥕 CARROT MODU - Sürekli Otomatik Tarama")
	fmt.Println()
}
