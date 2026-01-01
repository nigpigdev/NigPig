package cli

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/nigpig/nigpig/internal/core"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Version is set at build time
var Version = "1.0.0"

var rootCmd = &cobra.Command{
	Use:   "nigpig",
	Short: "NigPig - Bug Bounty & Güvenlik Tarama Otomasyonu",
	Long: `
    ███╗   ██╗██╗ ██████╗ ██████╗ ██╗ ██████╗ 
    ████╗  ██║██║██╔════╝ ██╔══██╗██║██╔════╝ 
    ██╔██╗ ██║██║██║  ███╗██████╔╝██║██║  ███╗
    ██║╚██╗██║██║██║   ██║██╔═══╝ ██║██║   ██║
    ██║ ╚████║██║╚██████╔╝██║     ██║╚██████╔╝
    ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝     ╚═╝ ╚═════╝ 

NigPig, bug bounty avcılığı ve web güvenlik açıkları bulmak için
tasarlanmış cross-platform CLI otomasyon aracıdır.

⚠️  SADECE yetkili olduğunuz hedeflerde kullanın!

Temel Komutlar:
  carrot      Sürekli otomatik tarama modu (önerilen)
  doctor      Sistem bağımlılıklarını kontrol et
  init        Çalışma alanı oluştur
  target      Hedef yönetimi

Tarama Komutları:
  recon       Subdomain keşfi
  scan        Zafiyet tarama
  report      Rapor oluştur
  notify      Bildirim gönder
  resume      Yarıda kalan taramayı devam ettir

Yardım:
  nigpig <komut> --help    Komut yardımı
  nigpig examples          Kullanım örnekleri`,
	Example: `  # Hızlı başlangıç
  nigpig doctor            # Bağımlılıkları kontrol et
  nigpig init              # Çalışma alanı oluştur
  nigpig carrot            # Sürekli tarama başlat (wizard)

  # Tek satırda carrot
  nigpig carrot --domain example.com --profile balanced

  # Sadece keşif
  nigpig recon --domain example.com

  # Sadece tarama
  nigpig scan --target example.com --modules xss,sqli`,
	Version: Version,
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringP("config", "c", "", "Config dosyası yolu")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Ayrıntılı çıktı")
	rootCmd.PersistentFlags().Bool("json", false, "JSON formatında çıktı")
	rootCmd.PersistentFlags().Bool("no-color", false, "Renksiz çıktı")
	rootCmd.PersistentFlags().Bool("no-banner", false, "Banner'ı gizle")

	// Bind to viper
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	viper.BindPFlag("json", rootCmd.PersistentFlags().Lookup("json"))
}

func initConfig() {
	// Check for no-color flag
	noColor, _ := rootCmd.PersistentFlags().GetBool("no-color")
	if noColor {
		color.NoColor = true
	}

	// Config file
	cfgFile, _ := rootCmd.PersistentFlags().GetString("config")
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		// Default config location
		viper.AddConfigPath(core.GetNigPigHome())
		viper.AddConfigPath(".")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	// Environment variables
	viper.SetEnvPrefix("NIGPIG")
	viper.AutomaticEnv()

	// Read config
	if err := viper.ReadInConfig(); err != nil {
		// Config file not found is OK
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// Other errors should be logged
			if viper.GetBool("verbose") {
				fmt.Fprintf(os.Stderr, "Config okunamadı: %v\n", err)
			}
		}
	}
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

