package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nigpig/nigpig/internal/core"
)

// writeTXTReport writes the mandatory TXT report to current working directory
func writeTXTReport(config *core.RunConfig, stats *core.RunStats) string {
	filename := core.GenerateReportFilename(config.Target, config.Profile, config.RunID)
	cwd := core.CurrentWorkingDir()
	reportPath := filepath.Join(cwd, filename)
	reportPath = core.EnsureUniqueFilename(reportPath)

	content := buildTXTReportContent(config, stats)

	if err := core.WriteFileAtomic(reportPath, []byte(content), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "❌ TXT rapor yazılamadı: %v\n", err)
		// Fallback to workspace
		workspacePath := core.GetWorkspacePath(config.Target)
		fallbackPath := filepath.Join(workspacePath, "reports", filename)
		if err := core.WriteFileAtomic(fallbackPath, []byte(content), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Fallback rapor da yazılamadı: %v\n", err)
			return ""
		}
		return fallbackPath
	}

	return reportPath
}

func buildTXTReportContent(config *core.RunConfig, stats *core.RunStats) string {
	var sb strings.Builder

	// Header
	sb.WriteString("════════════════════════════════════════════════════════════════════════════════\n")
	sb.WriteString("                       🐷 NigPig - Güvenlik Tarama Raporu\n")
	sb.WriteString("════════════════════════════════════════════════════════════════════════════════\n\n")

	// 1) Summary
	sb.WriteString("┌─────────────────────────────────────────────────────────────────────────────┐\n")
	sb.WriteString("│ 1. ÖZET                                                                     │\n")
	sb.WriteString("└─────────────────────────────────────────────────────────────────────────────┘\n\n")

	sb.WriteString(fmt.Sprintf("  Tool:              NigPig v1.0.0\n"))
	sb.WriteString(fmt.Sprintf("  Tarih/Saat:        %s\n", config.StartedAt.Format("02 Ocak 2006, 15:04:05")))
	sb.WriteString(fmt.Sprintf("  İşletim Sistemi:   %s\n", core.GetOSInfo()))
	sb.WriteString(fmt.Sprintf("  Run-ID:            %s\n", config.RunID))
	sb.WriteString(fmt.Sprintf("  Hedef:             %s\n", config.Target))
	sb.WriteString(fmt.Sprintf("  Program:           %s\n", config.Program))
	sb.WriteString(fmt.Sprintf("  Profil:            %s\n", config.Profile))
	sb.WriteString(fmt.Sprintf("  Scope:             %s\n", config.ScopePath))

	if stats.FinishedAt != nil {
		sb.WriteString(fmt.Sprintf("  Bitiş:             %s\n", stats.FinishedAt.Format("02 Ocak 2006, 15:04:05")))
		sb.WriteString(fmt.Sprintf("  Toplam Süre:       %s\n", core.FormatDuration(stats.TotalDuration)))
	}
	sb.WriteString(fmt.Sprintf("  Döngü Sayısı:      %d\n", stats.CycleCount))

	// 2) Parameters
	sb.WriteString("\n┌─────────────────────────────────────────────────────────────────────────────┐\n")
	sb.WriteString("│ 2. ÇALIŞMA PARAMETRELERİ                                                    │\n")
	sb.WriteString("└─────────────────────────────────────────────────────────────────────────────┘\n\n")

	sb.WriteString("  [BÜTÇELER]\n")
	sb.WriteString(fmt.Sprintf("    Max Runtime:        %d saat\n", config.Budgets.MaxRuntimeHours))
	sb.WriteString(fmt.Sprintf("    Max Req/Saat:       %d\n", config.Budgets.MaxRequestsPerHour))
	sb.WriteString(fmt.Sprintf("    Concurrency:        %d\n", config.Budgets.MaxConcurrency))
	sb.WriteString(fmt.Sprintf("    Max URL/Döngü:      %d\n", config.Budgets.MaxNewURLsPerCycle))

	sb.WriteString("\n  [DÖNGÜ]\n")
	sb.WriteString(fmt.Sprintf("    Interval:           %d dk\n", config.Cycle.IntervalMinutes))
	sb.WriteString(fmt.Sprintf("    Delta-only:         %v\n", config.Cycle.DeltaOnlyMode))

	sb.WriteString("\n  [AĞ]\n")
	sb.WriteString(fmt.Sprintf("    Timeout:            %d sn\n", config.Network.TimeoutSeconds))
	sb.WriteString(fmt.Sprintf("    Retries:            %d\n", config.Network.Retries))
	sb.WriteString(fmt.Sprintf("    Backoff:            %s\n", config.Network.Backoff))
	proxy := config.Network.Proxy
	if proxy == "" {
		proxy = "none"
	}
	sb.WriteString(fmt.Sprintf("    Proxy:              %s\n", proxy))

	sb.WriteString("\n  [AUTH]\n")
	authStatus := "Hayır"
	if config.Auth.Enabled {
		authStatus = fmt.Sprintf("Evet (%s) [REDACTED]", config.Auth.ProfileName)
	}
	sb.WriteString(fmt.Sprintf("    Enabled:            %s\n", authStatus))

	sb.WriteString("\n  [BİLDİRİM]\n")
	channels := strings.Join(config.Notify.Channels, ", ")
	if channels == "" {
		channels = "none"
	}
	sb.WriteString(fmt.Sprintf("    Kanallar:           %s\n", channels))
	sb.WriteString(fmt.Sprintf("    Threshold:          %s\n", config.Notify.Threshold))
	sb.WriteString(fmt.Sprintf("    Digest Mode:        %v\n", config.Notify.DigestMode))

	// 3) Stages and Stats
	sb.WriteString("\n┌─────────────────────────────────────────────────────────────────────────────┐\n")
	sb.WriteString("│ 3. AŞAMALAR VE İSTATİSTİKLER                                                │\n")
	sb.WriteString("└─────────────────────────────────────────────────────────────────────────────┘\n\n")

	sb.WriteString("  [RECON]\n")
	sb.WriteString(fmt.Sprintf("    Subdomain bulundu:  %d\n", stats.SubdomainsFound))
	sb.WriteString(fmt.Sprintf("    Yeni subdomain:     %d\n", stats.SubdomainsNew))

	sb.WriteString("\n  [LIVE HTTP]\n")
	sb.WriteString(fmt.Sprintf("    Canlı endpoint:     %d\n", stats.LiveHostsFound))

	sb.WriteString("\n  [URL DISCOVERY]\n")
	sb.WriteString(fmt.Sprintf("    Toplam URL:         %d\n", stats.URLsDiscovered))
	sb.WriteString(fmt.Sprintf("    Yeni URL (delta):   %d\n", stats.URLsNew))

	sb.WriteString("\n  [CHECKS]\n")
	sb.WriteString(fmt.Sprintf("    Kontrol sayısı:     %d\n", stats.ChecksRun))
	sb.WriteString(fmt.Sprintf("    Template sayısı:    %d\n", stats.TemplatesUsed))

	sb.WriteString("\n  [VERIFY]\n")
	sb.WriteString(fmt.Sprintf("    Verified:           %d\n", stats.Findings.Verified))
	sb.WriteString(fmt.Sprintf("    False Positive:     %d\n", stats.Findings.FalsePositive))
	sb.WriteString(fmt.Sprintf("    Needs Manual:       %d\n", stats.Findings.NeedsManual))

	// 4) Findings Summary
	sb.WriteString("\n┌─────────────────────────────────────────────────────────────────────────────┐\n")
	sb.WriteString("│ 4. BULGULAR ÖZETİ                                                           │\n")
	sb.WriteString("└─────────────────────────────────────────────────────────────────────────────┘\n\n")

	sb.WriteString(fmt.Sprintf("  Toplam Bulgu:         %d\n\n", stats.Findings.Total))

	if stats.Findings.Total > 0 {
		sb.WriteString("  Severity Dağılımı:\n")
		if stats.Findings.Critical > 0 {
			sb.WriteString(fmt.Sprintf("    🔴 CRITICAL:        %d\n", stats.Findings.Critical))
		}
		if stats.Findings.High > 0 {
			sb.WriteString(fmt.Sprintf("    🟠 HIGH:            %d\n", stats.Findings.High))
		}
		if stats.Findings.Medium > 0 {
			sb.WriteString(fmt.Sprintf("    🟡 MEDIUM:          %d\n", stats.Findings.Medium))
		}
		if stats.Findings.Low > 0 {
			sb.WriteString(fmt.Sprintf("    🟢 LOW:             %d\n", stats.Findings.Low))
		}
		if stats.Findings.Info > 0 {
			sb.WriteString(fmt.Sprintf("    ℹ️  INFO:            %d\n", stats.Findings.Info))
		}

		sb.WriteString("\n  Detaylı bulgular için MD/JSON raporlarına bakınız.\n")
	} else {
		sb.WriteString("  ✅ Herhangi bir güvenlik bulgusu tespit edilmedi.\n")
	}

	// 5) Errors/Warnings
	if len(stats.Errors) > 0 || len(stats.Warnings) > 0 || stats.OutOfScopeBlocks > 0 || stats.ThrottleEvents > 0 {
		sb.WriteString("\n┌─────────────────────────────────────────────────────────────────────────────┐\n")
		sb.WriteString("│ 5. HATALAR / UYARILAR                                                       │\n")
		sb.WriteString("└─────────────────────────────────────────────────────────────────────────────┘\n\n")

		if len(stats.Errors) > 0 {
			sb.WriteString("  [HATALAR]\n")
			for _, e := range stats.Errors {
				sb.WriteString(fmt.Sprintf("    ❌ %s\n", e))
			}
		}

		if len(stats.Warnings) > 0 {
			sb.WriteString("\n  [UYARILAR - Degrade Mode]\n")
			for _, w := range stats.Warnings {
				sb.WriteString(fmt.Sprintf("    ⚠️  %s\n", w))
			}
		}

		if stats.ThrottleEvents > 0 || stats.BackoffEvents > 0 {
			sb.WriteString("\n  [RATE LİMİT]\n")
			sb.WriteString(fmt.Sprintf("    Throttle olayları:  %d\n", stats.ThrottleEvents))
			sb.WriteString(fmt.Sprintf("    Backoff olayları:   %d\n", stats.BackoffEvents))
		}

		if stats.OutOfScopeBlocks > 0 {
			sb.WriteString("\n  [OUT-OF-SCOPE]\n")
			sb.WriteString(fmt.Sprintf("    Engellenen istek:   %d\n", stats.OutOfScopeBlocks))
		}
	}

	// 6) File References
	sb.WriteString("\n┌─────────────────────────────────────────────────────────────────────────────┐\n")
	sb.WriteString("│ 6. DOSYA REFERANSLARI                                                       │\n")
	sb.WriteString("└─────────────────────────────────────────────────────────────────────────────┘\n\n")

	workspacePath := core.GetWorkspacePath(config.Target)
	sb.WriteString(fmt.Sprintf("  Workspace:            %s\n", workspacePath))
	sb.WriteString(fmt.Sprintf("  MD Rapor:             %s\n", filepath.Join(workspacePath, "reports", "latest.md")))
	sb.WriteString(fmt.Sprintf("  JSON Rapor:           %s\n", filepath.Join(workspacePath, "reports", "latest.json")))
	sb.WriteString(fmt.Sprintf("  Evidence:             %s\n", filepath.Join(workspacePath, "evidence")))
	sb.WriteString(fmt.Sprintf("  Bu TXT Rapor:         %s\n", core.GenerateReportFilename(config.Target, config.Profile, config.RunID)))

	// Footer
	sb.WriteString("\n════════════════════════════════════════════════════════════════════════════════\n")
	sb.WriteString(fmt.Sprintf("  Oluşturma zamanı: %s\n", core.CurrentTime().Format("2006-01-02 15:04:05")))
	sb.WriteString("  © NigPig - Bug Bounty & Güvenlik Tarama Otomasyonu\n")
	sb.WriteString("  ⚠️  Bu araç SADECE yetkili hedeflerde kullanılmalıdır!\n")
	sb.WriteString("════════════════════════════════════════════════════════════════════════════════\n")

	return sb.String()
}

// WriteCommandReport writes a simple report for any command
func WriteCommandReport(cmdName string, success bool, target string, details map[string]interface{}) string {
	runID := generateRunID()
	
	sanitizedCmd := core.SanitizeFilename(cmdName)
	sanitizedTarget := "general"
	if target != "" {
		sanitizedTarget = core.SanitizeFilename(target)
	}
	
	filename := fmt.Sprintf("NigPig_%s_%s_%s_run-%s.txt",
		core.CurrentTime().Format("2006-01-02_15-04-05"),
		sanitizedCmd,
		sanitizedTarget,
		runID[:8])

	cwd := core.CurrentWorkingDir()
	reportPath := filepath.Join(cwd, filename)
	reportPath = core.EnsureUniqueFilename(reportPath)

	var sb strings.Builder
	sb.WriteString("════════════════════════════════════════════════════════════════════════════════\n")
	sb.WriteString("                       🐷 NigPig - Komut Raporu\n")
	sb.WriteString("════════════════════════════════════════════════════════════════════════════════\n\n")

	sb.WriteString(fmt.Sprintf("  Komut:             nigpig %s\n", cmdName))
	sb.WriteString(fmt.Sprintf("  Tarih/Saat:        %s\n", core.CurrentTime().Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("  İşletim Sistemi:   %s\n", core.GetOSInfo()))
	sb.WriteString(fmt.Sprintf("  Run-ID:            %s\n", runID))

	if target != "" {
		sb.WriteString(fmt.Sprintf("  Hedef:             %s\n", target))
	}

	status := "✅ BAŞARILI"
	if !success {
		status = "❌ BAŞARISIZ"
	}
	sb.WriteString(fmt.Sprintf("  Durum:             %s\n", status))

	if len(details) > 0 {
		sb.WriteString("\n  [DETAYLAR]\n")
		for k, v := range details {
			sb.WriteString(fmt.Sprintf("    %-20s %v\n", k+":", v))
		}
	}

	sb.WriteString("\n════════════════════════════════════════════════════════════════════════════════\n")

	if err := core.WriteFileAtomic(reportPath, []byte(sb.String()), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "⚠️ TXT rapor yazılamadı: %v\n", err)
		return ""
	}

	return reportPath
}
