package cli

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/fatih/color"
	"github.com/nigpig/nigpig/internal/core"
	"github.com/spf13/cobra"
)

type toolInfo struct {
	name        string
	required    bool
	description string
	installCmd  string
}

var tools = []toolInfo{
	{"subfinder", true, "Subdomain keşfi", "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
	{"dnsx", true, "DNS çözümleme", "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
	{"httpx", true, "HTTP probing", "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"},
	{"katana", true, "Web crawling", "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"},
	{"nuclei", true, "Zafiyet tarama", "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
	{"ffuf", false, "Fuzzing", "go install -v github.com/ffuf/ffuf/v2@latest"},
	{"amass", false, "Gelişmiş subdomain", "go install -v github.com/owasp-amass/amass/v4/...@master"},
	{"gau", false, "URL arşivi", "go install -v github.com/lc/gau/v2/cmd/gau@latest"},
	{"gowitness", false, "Ekran görüntüsü", "go install -v github.com/sensepost/gowitness@latest"},
}

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Sistem bağımlılıklarını kontrol et",
	Long: `NigPig'in düzgün çalışması için gerekli bağımlılıkları kontrol eder.

Kontroller:
- Go kurulumu ve PATH
- Güvenlik araçları (subfinder, httpx, nuclei vb.)
- Yazma izinleri
- Network erişimi

Eksik araçlar tespit edilir ve kurulum yönergeleri gösterilir.`,
	Example: `  nigpig doctor
  nigpig doctor --install    # Eksik Go araçlarını kur
  nigpig doctor --verbose    # Detaylı çıktı`,
	Run: runDoctor,
}

func init() {
	rootCmd.AddCommand(doctorCmd)
	doctorCmd.Flags().Bool("install", false, "Eksik Go araçlarını otomatik kur")
	doctorCmd.Flags().Bool("verbose", false, "Detaylı çıktı")
}

func runDoctor(cmd *cobra.Command, args []string) {
	autoInstall, _ := cmd.Flags().GetBool("install")
	verbose, _ := cmd.Flags().GetBool("verbose")

	fmt.Println()
	color.Cyan("🩺 NigPig Sistem Kontrolü")
	fmt.Println()

	// System info
	printSection("SİSTEM BİLGİSİ")
	fmt.Printf("  İşletim Sistemi:   %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("  Go Versiyonu:      %s\n", runtime.Version())
	fmt.Printf("  NigPig Home:       %s\n", core.GetNigPigHome())
	fmt.Printf("  Çalışma Dizini:    %s\n", core.CurrentWorkingDir())

	// Go environment
	fmt.Println()
	printSection("GO ORTAMI")

	goPath, goFound := core.FindExecutable("go")
	if goFound {
		printOK("go", "Kurulu: "+goPath)

		// Check GOPATH
		goPathEnv := os.Getenv("GOPATH")
		if goPathEnv == "" {
			goPathEnv = os.Getenv("HOME") + "/go"
			if core.IsWindows {
				goPathEnv = os.Getenv("USERPROFILE") + "\\go"
			}
		}

		if verbose {
			printOK("GOPATH", goPathEnv)
		}

		// Check if GOPATH/bin is in PATH
		goBin := goPathEnv + string(os.PathSeparator) + "bin"
		pathEnv := os.Getenv("PATH")
		if strings.Contains(pathEnv, goBin) {
			printOK("PATH", "$GOPATH/bin mevcut")
		} else {
			printWarn("PATH", "$GOPATH/bin PATH'te değil!")
			printPathInstructions()
		}
	} else {
		printFail("go", "Go kurulu değil!")
		fmt.Println()
		color.Yellow("  Go'yu şu şekilde kurabilirsiniz:")
		if core.IsWindows {
			fmt.Println("    winget install GoLang.Go")
			fmt.Println("    veya: https://go.dev/dl/")
		} else {
			fmt.Println("    sudo apt install golang-go")
			fmt.Println("    veya: https://go.dev/dl/")
		}
	}

	// Security tools
	fmt.Println()
	printSection("GÜVENLİK ARAÇLARI")

	requiredMissing := 0
	optionalMissing := 0
	var toInstall []toolInfo

	for _, tool := range tools {
		path, found := core.FindExecutable(tool.name)

		reqLabel := "[zorunlu]"
		if !tool.required {
			reqLabel = "[opsiyonel]"
		}

		if found {
			version := getToolVersion(tool.name, path)
			desc := tool.description
			if version != "" {
				desc += " (v" + version + ")"
			}
			printOK(fmt.Sprintf("%-12s %s", tool.name, reqLabel), desc)
		} else {
			printFail(fmt.Sprintf("%-12s %s", tool.name, reqLabel), "Kurulu değil - "+tool.description)
			if tool.required {
				requiredMissing++
			} else {
				optionalMissing++
			}
			toInstall = append(toInstall, tool)
		}
	}

	// Write permissions
	fmt.Println()
	printSection("YAZIIM İZİNLERİ")

	// Check current directory
	cwdWritable := checkWritePermission(core.CurrentWorkingDir())
	if cwdWritable {
		printOK("Current dir", "Yazılabilir")
	} else {
		printFail("Current dir", "Yazma izni yok!")
	}

	// Check NigPig home
	homeWritable := checkWritePermission(core.GetNigPigHome())
	if homeWritable {
		printOK("NigPig home", "Yazılabilir")
	} else {
		printWarn("NigPig home", "Yazma izni kontrol edilemedi (henüz oluşturulmamış olabilir)")
	}

	// Summary
	fmt.Println()
	printSection("ÖZET")

	if requiredMissing == 0 && goFound {
		color.Green("  ✅ Tüm zorunlu bileşenler hazır!")
	} else {
		if !goFound {
			color.Red("  ❌ Go kurulu değil!")
		}
		if requiredMissing > 0 {
			color.Red("  ❌ %d zorunlu araç eksik!", requiredMissing)
		}
	}

	if optionalMissing > 0 {
		color.Yellow("  ⚠️  %d opsiyonel araç eksik (degrade mode'da çalışabilir)", optionalMissing)
	}

	// Install options
	if len(toInstall) > 0 && goFound {
		fmt.Println()

		if autoInstall {
			color.Cyan("  📦 Eksik araçlar kuruluyor...")
			fmt.Println()

			for _, tool := range toInstall {
				fmt.Printf("  Kuruluyor: %s... ", tool.name)
				err := runInstall(tool.installCmd)
				if err != nil {
					color.Red("HATA: %v", err)
				} else {
					color.Green("✓")
				}
			}

			fmt.Println()
			color.Cyan("  🔄 Nuclei template'leri güncelleniyor...")
			updateNucleiTemplates()
		} else {
			color.Yellow("  💡 Eksik araçları kurmak için:")
			fmt.Println()
			fmt.Println("    nigpig doctor --install")
			fmt.Println()
			fmt.Println("  Veya manuel:")
			for _, tool := range toInstall {
				if tool.required {
					fmt.Printf("    %s\n", tool.installCmd)
				}
			}
		}
	}

	// Write TXT report
	fmt.Println()
	details := map[string]interface{}{
		"os":               runtime.GOOS,
		"go_installed":     goFound,
		"required_missing": requiredMissing,
		"optional_missing": optionalMissing,
		"cwd_writable":     cwdWritable,
	}
	reportPath := WriteCommandReport("doctor", requiredMissing == 0 && goFound, "", details)
	if reportPath != "" {
		color.White("  📄 Rapor: %s", reportPath)
	}

	fmt.Println()
}

func printSection(title string) {
	color.White("═══════════════════════════════════════════════════════════════")
	color.White(" " + title)
	color.White("═══════════════════════════════════════════════════════════════")
	fmt.Println()
}

func printOK(name, desc string) {
	fmt.Printf("  %s %-30s %s\n", color.GreenString("✓"), name, color.GreenString(desc))
}

func printFail(name, desc string) {
	fmt.Printf("  %s %-30s %s\n", color.RedString("✗"), name, color.YellowString(desc))
}

func printWarn(name, desc string) {
	fmt.Printf("  %s %-30s %s\n", color.YellowString("⚠"), name, color.YellowString(desc))
}

func printPathInstructions() {
	fmt.Println()
	color.Yellow("  PATH'e $GOPATH/bin eklemek için:")
	if core.IsWindows {
		fmt.Println(`    PowerShell:`)
		fmt.Println(`    [Environment]::SetEnvironmentVariable('PATH', $env:PATH + ';' + $env:USERPROFILE + '\go\bin', 'User')`)
		fmt.Println(`    veya yeni terminal açın`)
	} else {
		fmt.Println("    echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc")
		fmt.Println("    source ~/.bashrc")
	}
	fmt.Println()
}

func getToolVersion(name, path string) string {
	out, err := exec.Command(path, "-version").CombinedOutput()
	if err != nil {
		out, err = exec.Command(path, "version").CombinedOutput()
	}
	if err != nil {
		return ""
	}

	// Extract version from output
	lines := strings.Split(string(out), "\n")
	if len(lines) > 0 {
		// Try to find version pattern
		for _, line := range lines {
			if strings.Contains(line, "v") || strings.Contains(line, ".") {
				parts := strings.Fields(line)
				for _, p := range parts {
					if strings.HasPrefix(p, "v") || (strings.Contains(p, ".") && len(p) < 20) {
						return strings.TrimPrefix(p, "v")
					}
				}
			}
		}
	}
	return ""
}

func checkWritePermission(path string) bool {
	// Try to create a test file
	testFile := path + string(os.PathSeparator) + ".nigpig_write_test"
	f, err := os.Create(testFile)
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(testFile)
	return true
}

func runInstall(cmd string) error {
	parts := strings.Fields(cmd)
	if len(parts) < 2 {
		return fmt.Errorf("invalid command")
	}
	c := exec.Command(parts[0], parts[1:]...)
	return c.Run()
}

func updateNucleiTemplates() {
	if path, found := core.FindExecutable("nuclei"); found {
		cmd := exec.Command(path, "-update-templates", "-silent")
		cmd.Run()
	}
}
