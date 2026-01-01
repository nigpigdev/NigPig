package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/nigpig/nigpig/internal/config"
	"github.com/spf13/cobra"
)

// Config command group
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Yapılandırma yönetimi",
	Long:  `NigPig yapılandırma dosyaları ve preset'leri yönetir.`,
}

// Lint subcommand
var configLintCmd = &cobra.Command{
	Use:   "lint",
	Short: "Yapılandırma dosyalarını doğrula",
	Long: `Scope ve config dosyalarını doğrular, hataları ve uyarıları raporlar.

Kontroller:
- YAML sözdizimi
- Zorunlu alanlar
- Güvenlik uyarıları
- Pattern konflikler
- Regex/glob doğrulama`,
	Example: `  nigpig config lint --scope scope.yaml
  nigpig config lint --config nigpig.yaml
  nigpig config lint --scope scope.yaml --config nigpig.yaml`,
	Run: runConfigLint,
}

// Presets subcommand
var presetsCmd = &cobra.Command{
	Use:   "presets",
	Short: "Preset profilleri yönet",
	Long:  `Mevcut preset profilleri listele ve detaylarını göster.`,
}

var presetsListCmd = &cobra.Command{
	Use:   "list",
	Short: "Tüm preset'leri listele",
	Run:   runPresetsList,
}

var presetsShowCmd = &cobra.Command{
	Use:   "show [preset]",
	Short: "Preset detaylarını göster",
	Args:  cobra.ExactArgs(1),
	Run:   runPresetsShow,
}

func init() {
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(presetsCmd)

	// Config lint
	configCmd.AddCommand(configLintCmd)
	configLintCmd.Flags().String("scope", "", "Doğrulanacak scope dosyası")
	configLintCmd.Flags().String("config", "", "Doğrulanacak config dosyası")

	// Presets
	presetsCmd.AddCommand(presetsListCmd)
	presetsCmd.AddCommand(presetsShowCmd)
}

func runConfigLint(cmd *cobra.Command, args []string) {
	scopePath, _ := cmd.Flags().GetString("scope")
	configPath, _ := cmd.Flags().GetString("config")

	if scopePath == "" && configPath == "" {
		printError("En az bir dosya belirtmelisiniz: --scope veya --config")
		return
	}

	fmt.Println()
	color.Cyan("🔍 NigPig Config Lint")
	fmt.Println()

	linter := config.NewLinter()
	hasErrors := false

	// Lint scope
	if scopePath != "" {
		printStep("Scope dosyası kontrol ediliyor: " + scopePath)
		result := linter.LintScope(scopePath)
		printLintResult(scopePath, result)
		if !result.Valid {
			hasErrors = true
		}
	}

	// Lint config
	if configPath != "" {
		printStep("Config dosyası kontrol ediliyor: " + configPath)
		result := linter.LintConfig(configPath)
		printLintResult(configPath, result)
		if !result.Valid {
			hasErrors = true
		}
	}

	fmt.Println()
	if hasErrors {
		color.Red("❌ Doğrulama hatası bulundu!")
		os.Exit(1)
	} else {
		color.Green("✅ Tüm dosyalar geçerli!")
	}

	// Write TXT report
	details := map[string]interface{}{
		"scope_path":  scopePath,
		"config_path": configPath,
		"valid":       !hasErrors,
	}
	WriteCommandReport("config-lint", !hasErrors, "", details)
}

func printLintResult(path string, result *config.LintResult) {
	fmt.Println()
	filename := filepath.Base(path)

	if result.Valid && len(result.Warnings) == 0 {
		color.Green("  ✅ %s: Geçerli", filename)
		return
	}

	if !result.Valid {
		color.Red("  ❌ %s: Hatalar var", filename)
	} else {
		color.Yellow("  ⚠️  %s: Uyarılar var", filename)
	}

	// Print errors
	for _, err := range result.Errors {
		fmt.Printf("     %s [%s] %s: %s\n",
			color.RedString("ERROR"),
			err.Type,
			color.WhiteString(err.Field),
			err.Message)
	}

	// Print warnings
	for _, warn := range result.Warnings {
		fmt.Printf("     %s [%s] %s: %s\n",
			color.YellowString("WARN"),
			warn.Type,
			color.WhiteString(warn.Field),
			warn.Message)
	}
}

func runPresetsList(cmd *cobra.Command, args []string) {
	fmt.Println()
	color.Cyan("📋 Mevcut Preset'ler")
	fmt.Println()

	presets := config.GetPresets()

	fmt.Printf("%-15s %-50s\n", "İSİM", "AÇIKLAMA")
	fmt.Println(strings.Repeat("─", 65))

	for name, preset := range presets {
		riskLevel := getRiskLevel(name)
		fmt.Printf("%-15s %-50s %s\n", 
			color.CyanString(name), 
			preset.Description,
			riskLevel)
	}

	fmt.Println()
	fmt.Println("Detay için: nigpig presets show <isim>")
}

func runPresetsShow(cmd *cobra.Command, args []string) {
	presetName := args[0]

	preset, err := config.LoadPreset(presetName)
	if err != nil {
		printError("Preset bulunamadı: " + presetName)
		return
	}

	fmt.Println()
	color.Cyan("📋 Preset: " + preset.Name)
	fmt.Println()
	fmt.Println("  " + preset.Description)
	fmt.Println()

	// Budgets
	color.White("💰 BÜTÇELER")
	fmt.Printf("   Max Runtime:      %d saat\n", preset.Budgets.MaxRuntimeHours)
	fmt.Printf("   Max Req/Saat:     %d\n", preset.Budgets.MaxRequestsPerHour)
	fmt.Printf("   Max Concurrency:  %d\n", preset.Budgets.MaxConcurrency)
	fmt.Printf("   Max URL/Döngü:    %d\n", preset.Budgets.MaxNewURLsPerCycle)

	// Cycle
	fmt.Println()
	color.White("🔄 DÖNGÜ")
	fmt.Printf("   Interval:         %d dk\n", preset.Cycle.IntervalMinutes)
	fmt.Printf("   Delta-only:       %v\n", boolEmoji(preset.Cycle.DeltaOnlyMode))

	// Network
	fmt.Println()
	color.White("🌐 AĞ")
	fmt.Printf("   Timeout:          %d sn\n", preset.Network.TimeoutSeconds)
	fmt.Printf("   Retries:          %d\n", preset.Network.Retries)
	fmt.Printf("   Backoff:          %s\n", preset.Network.Backoff)
	fmt.Printf("   Jitter:           %d ms\n", preset.Network.JitterMs)

	// Checks
	fmt.Println()
	color.White("🔍 KONTROLLER")
	fmt.Printf("   Passive-only:     %v\n", boolEmoji(preset.Checks.PassiveOnly))
	fmt.Printf("   Max Severity:     %s\n", preset.Checks.SeverityMax)
	if len(preset.Checks.ExcludedCategories) > 0 {
		fmt.Printf("   Hariç tutulan:    %s\n", strings.Join(preset.Checks.ExcludedCategories, ", "))
	}

	// Safety
	fmt.Println()
	color.White("🔒 GÜVENLİK")
	fmt.Printf("   No-auth tests:    %v\n", boolEmoji(preset.Safety.NoAuth))
	fmt.Printf("   No-destructive:   %v\n", boolEmoji(preset.Safety.NoDestructive))
	fmt.Printf("   No-cloud:         %v\n", boolEmoji(preset.Safety.NoCloud))

	// Notify
	fmt.Println()
	color.White("📬 BİLDİRİM")
	fmt.Printf("   Threshold:        %s\n", preset.Notify.Threshold)
	fmt.Printf("   Digest mode:      %v\n", boolEmoji(preset.Notify.DigestMode))
	if preset.Notify.DigestIntervalMin > 0 {
		fmt.Printf("   Digest interval:  %d dk\n", preset.Notify.DigestIntervalMin)
	}

	fmt.Println()
	fmt.Println("Kullanım: nigpig carrot --domain example.com --profile " + presetName)
}

func getRiskLevel(presetName string) string {
	switch presetName {
	case "stealth":
		return color.GreenString("[DÜŞÜK RİSK]")
	case "balanced":
		return color.YellowString("[ORTA RİSK]")
	case "aggressive":
		return color.RedString("[YÜKSEK RİSK]")
	default:
		return ""
	}
}
