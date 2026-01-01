// NigPig - Bug Bounty & Güvenlik Tarama Otomasyonu
// Cross-platform: Windows + Linux (Kali)
package main

import (
	"github.com/nigpig/nigpig/internal/cli"
)

// Version is set at build time via ldflags
var Version = "1.0.0"

func main() {
	cli.Execute()
}
