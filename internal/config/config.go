// Package config provides configuration management with lint and presets
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the main NigPig configuration
type Config struct {
	General     GeneralConfig     `yaml:"general"`
	DefaultPreset string          `yaml:"default_preset"`
	Workspace   WorkspaceConfig   `yaml:"workspace"`
	Tools       ToolsConfig       `yaml:"tools"`
	Nuclei      NucleiConfig      `yaml:"nuclei"`
	Notify      NotifyConfig      `yaml:"notifications"`
	Security    SecurityConfig    `yaml:"security"`
	Cache       CacheConfig       `yaml:"cache"`
	Logging     LoggingConfig     `yaml:"logging"`
}

// GeneralConfig holds general settings
type GeneralConfig struct {
	Verbose    bool   `yaml:"verbose"`
	JSONOutput bool   `yaml:"json_output"`
	NoColor    bool   `yaml:"no_color"`
	Language   string `yaml:"language"`
}

// WorkspaceConfig holds workspace settings
type WorkspaceConfig struct {
	BasePath         string `yaml:"base_path"`
	AutoCleanupDays  int    `yaml:"auto_cleanup_days"`
}

// ToolsConfig holds external tool paths
type ToolsConfig struct {
	Subfinder  string `yaml:"subfinder"`
	Dnsx       string `yaml:"dnsx"`
	Httpx      string `yaml:"httpx"`
	Katana     string `yaml:"katana"`
	Nuclei     string `yaml:"nuclei"`
	Ffuf       string `yaml:"ffuf"`
	Amass      string `yaml:"amass"`
	Gau        string `yaml:"gau"`
	Gowitness  string `yaml:"gowitness"`
}

// NucleiConfig holds Nuclei-specific settings
type NucleiConfig struct {
	TemplatesPath     string   `yaml:"templates_path"`
	CustomTemplates   string   `yaml:"custom_templates"`
	ExcludedTemplates []string `yaml:"excluded_templates"`
	SeverityFilter    []string `yaml:"severity_filter"`
	RateLimit         int      `yaml:"rate_limit"`
	Concurrency       int      `yaml:"concurrency"`
}

// NotifyConfig holds notification settings
type NotifyConfig struct {
	Telegram TelegramConfig `yaml:"telegram"`
	Discord  DiscordConfig  `yaml:"discord"`
	Slack    SlackConfig    `yaml:"slack"`
	Email    EmailConfig    `yaml:"email"`
	Webhook  WebhookConfig  `yaml:"webhook"`
}

// TelegramConfig for Telegram notifications
type TelegramConfig struct {
	Enabled  bool   `yaml:"enabled"`
	BotToken string `yaml:"bot_token"`
	ChatID   string `yaml:"chat_id"`
}

// DiscordConfig for Discord notifications
type DiscordConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhook_url"`
}

// SlackConfig for Slack notifications
type SlackConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhook_url"`
}

// EmailConfig for email notifications
type EmailConfig struct {
	Enabled  bool   `yaml:"enabled"`
	SMTPHost string `yaml:"smtp_host"`
	SMTPPort int    `yaml:"smtp_port"`
	From     string `yaml:"from"`
	To       string `yaml:"to"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// WebhookConfig for generic webhooks
type WebhookConfig struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
	Method  string `yaml:"method"`
	Headers map[string]string `yaml:"headers"`
}

// SecurityConfig holds security settings
type SecurityConfig struct {
	DestructiveTests bool     `yaml:"destructive_tests"`
	BruteForce       bool     `yaml:"brute_force"`
	AuthTesting      bool     `yaml:"auth_testing"`
	CloudTesting     bool     `yaml:"cloud_testing"`
	RedactSecrets    bool     `yaml:"redact_secrets"`
	RedactPatterns   []string `yaml:"redact_patterns"`
}

// CacheConfig holds caching settings
type CacheConfig struct {
	TTLDays   int  `yaml:"ttl_days"`
	MaxSizeMB int  `yaml:"max_size_mb"`
	ReuseETags bool `yaml:"reuse_etags"`
}

// LoggingConfig holds logging settings
type LoggingConfig struct {
	Level      string `yaml:"level"`
	File       string `yaml:"file"`
	JSONFormat bool   `yaml:"json_format"`
}

// Preset represents a scanning preset
type Preset struct {
	Name        string        `yaml:"name"`
	Description string        `yaml:"description"`
	Budgets     BudgetPreset  `yaml:"budgets"`
	Cycle       CyclePreset   `yaml:"cycle"`
	Network     NetworkPreset `yaml:"network"`
	Checks      ChecksPreset  `yaml:"checks"`
	Notify      NotifyPreset  `yaml:"notify"`
	Safety      SafetyPreset  `yaml:"safety"`
}

// BudgetPreset holds budget settings
type BudgetPreset struct {
	MaxRuntimeHours    int `yaml:"max_runtime_hours"`
	MaxRequestsPerHour int `yaml:"max_requests_per_hour"`
	MaxConcurrency     int `yaml:"max_concurrency"`
	MaxNewURLsPerCycle int `yaml:"max_new_urls_per_cycle"`
}

// CyclePreset holds cycle settings
type CyclePreset struct {
	IntervalMinutes int  `yaml:"interval_minutes"`
	DeltaOnlyMode   bool `yaml:"delta_only_mode"`
}

// NetworkPreset holds network settings
type NetworkPreset struct {
	TimeoutSeconds int    `yaml:"timeout_seconds"`
	Retries        int    `yaml:"retries"`
	Backoff        string `yaml:"backoff"`
	JitterMs       int    `yaml:"jitter_ms"`
	UserAgent      string `yaml:"user_agent"`
}

// ChecksPreset holds check settings
type ChecksPreset struct {
	PassiveOnly        bool     `yaml:"passive_only"`
	ExcludedCategories []string `yaml:"excluded_categories"`
	SeverityMax        string   `yaml:"severity_max"`
}

// NotifyPreset holds notification settings
type NotifyPreset struct {
	Threshold       string `yaml:"threshold"`
	DigestMode      bool   `yaml:"digest_mode"`
	DigestIntervalMin int  `yaml:"digest_interval_minutes"`
}

// SafetyPreset holds safety settings
type SafetyPreset struct {
	PassiveOnly   bool `yaml:"passive_only"`
	NoAuth        bool `yaml:"no_auth"`
	NoDestructive bool `yaml:"no_destructive"`
	NoCloud       bool `yaml:"no_cloud"`
}

// LintResult represents config validation result
type LintResult struct {
	Valid    bool         `json:"valid"`
	Errors   []LintError  `json:"errors,omitempty"`
	Warnings []LintError  `json:"warnings,omitempty"`
}

// LintError represents a lint error or warning
type LintError struct {
	Type     string `json:"type"`
	Field    string `json:"field"`
	Message  string `json:"message"`
	Severity string `json:"severity"` // error, warning
}

// Linter validates configuration files
type Linter struct{}

// NewLinter creates a new linter
func NewLinter() *Linter {
	return &Linter{}
}

// LintScope validates a scope file
func (l *Linter) LintScope(path string) *LintResult {
	result := &LintResult{Valid: true}

	data, err := os.ReadFile(path)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, LintError{
			Type:     "file",
			Field:    "path",
			Message:  fmt.Sprintf("Cannot read file: %v", err),
			Severity: "error",
		})
		return result
	}

	var scope struct {
		Program  string `yaml:"program"`
		Target   string `yaml:"target"`
		InScope  struct {
			Domains []string `yaml:"domains"`
			Ports   []int    `yaml:"ports"`
		} `yaml:"in_scope"`
		OutOfScope struct {
			Domains  []string `yaml:"domains"`
			Paths    []string `yaml:"paths"`
			Keywords []string `yaml:"keywords"`
		} `yaml:"out_of_scope"`
		Rules struct {
			RateLimit int `yaml:"rate_limit"`
		} `yaml:"rules"`
	}

	if err := yaml.Unmarshal(data, &scope); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, LintError{
			Type:     "yaml",
			Field:    "",
			Message:  fmt.Sprintf("Invalid YAML: %v", err),
			Severity: "error",
		})
		return result
	}

	// Check required fields
	if scope.Target == "" {
		result.Valid = false
		result.Errors = append(result.Errors, LintError{
			Type:     "required",
			Field:    "target",
			Message:  "Target is required",
			Severity: "error",
		})
	}

	// Check in-scope domains
	if len(scope.InScope.Domains) == 0 {
		result.Warnings = append(result.Warnings, LintError{
			Type:     "empty",
			Field:    "in_scope.domains",
			Message:  "No in-scope domains defined",
			Severity: "warning",
		})
	}

	// Validate domain patterns
	for _, domain := range scope.InScope.Domains {
		if err := l.validateDomainPattern(domain); err != nil {
			result.Warnings = append(result.Warnings, LintError{
				Type:     "pattern",
				Field:    "in_scope.domains",
				Message:  fmt.Sprintf("Invalid pattern '%s': %v", domain, err),
				Severity: "warning",
			})
		}
	}

	// Check for conflicts
	for _, inDomain := range scope.InScope.Domains {
		for _, outDomain := range scope.OutOfScope.Domains {
			if l.patternsConflict(inDomain, outDomain) {
				result.Warnings = append(result.Warnings, LintError{
					Type:     "conflict",
					Field:    "scope",
					Message:  fmt.Sprintf("Potential conflict: in-scope '%s' vs out-of-scope '%s'", inDomain, outDomain),
					Severity: "warning",
				})
			}
		}
	}

	// Validate regex patterns in paths
	for _, path := range scope.OutOfScope.Paths {
		if strings.Contains(path, "*") {
			// Convert glob to regex and validate
			regexPattern := strings.ReplaceAll(path, "*", ".*")
			if _, err := regexp.Compile(regexPattern); err != nil {
				result.Warnings = append(result.Warnings, LintError{
					Type:     "regex",
					Field:    "out_of_scope.paths",
					Message:  fmt.Sprintf("Invalid pattern '%s': %v", path, err),
					Severity: "warning",
				})
			}
		}
	}

	// Rate limit check
	if scope.Rules.RateLimit > 100 {
		result.Warnings = append(result.Warnings, LintError{
			Type:     "value",
			Field:    "rules.rate_limit",
			Message:  fmt.Sprintf("High rate limit (%d/s) may trigger WAF/bans", scope.Rules.RateLimit),
			Severity: "warning",
		})
	}

	return result
}

// LintConfig validates a config file
func (l *Linter) LintConfig(path string) *LintResult {
	result := &LintResult{Valid: true}

	data, err := os.ReadFile(path)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, LintError{
			Type:     "file",
			Field:    "path",
			Message:  fmt.Sprintf("Cannot read file: %v", err),
			Severity: "error",
		})
		return result
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, LintError{
			Type:     "yaml",
			Field:    "",
			Message:  fmt.Sprintf("Invalid YAML: %v", err),
			Severity: "error",
		})
		return result
	}

	// Check security settings
	if config.Security.DestructiveTests {
		result.Warnings = append(result.Warnings, LintError{
			Type:     "security",
			Field:    "security.destructive_tests",
			Message:  "Destructive tests are ENABLED - use with caution",
			Severity: "warning",
		})
	}

	if config.Security.BruteForce {
		result.Warnings = append(result.Warnings, LintError{
			Type:     "security",
			Field:    "security.brute_force",
			Message:  "Brute force is ENABLED - use with caution",
			Severity: "warning",
		})
	}

	// Check notification secrets
	if config.Notify.Telegram.Enabled && config.Notify.Telegram.BotToken == "" {
		result.Errors = append(result.Errors, LintError{
			Type:     "required",
			Field:    "notifications.telegram.bot_token",
			Message:  "Telegram enabled but bot_token is empty",
			Severity: "error",
		})
		result.Valid = false
	}

	return result
}

func (l *Linter) validateDomainPattern(pattern string) error {
	// Basic validation
	if pattern == "" {
		return fmt.Errorf("empty pattern")
	}

	// Check for invalid wildcard usage
	if strings.Count(pattern, "*") > 1 && !strings.HasPrefix(pattern, "*.") {
		return fmt.Errorf("invalid wildcard placement")
	}

	return nil
}

func (l *Linter) patternsConflict(in, out string) bool {
	// Simple check: does out pattern match what in pattern would match?
	inNorm := strings.TrimPrefix(in, "*.")
	outNorm := strings.TrimPrefix(out, "*.")
	
	return strings.HasSuffix(inNorm, outNorm) || strings.HasSuffix(outNorm, inNorm)
}

// GetPresets returns available presets
func GetPresets() map[string]*Preset {
	return map[string]*Preset{
		"stealth":    StealthPreset(),
		"balanced":   BalancedPreset(),
		"aggressive": AggressivePreset(),
	}
}

// LoadPreset loads a preset by name
func LoadPreset(name string) (*Preset, error) {
	presets := GetPresets()
	if preset, ok := presets[name]; ok {
		return preset, nil
	}
	return nil, fmt.Errorf("preset not found: %s", name)
}

// StealthPreset returns stealth preset
func StealthPreset() *Preset {
	return &Preset{
		Name:        "stealth",
		Description: "Düşük yoğunluklu, gizli tarama profili",
		Budgets: BudgetPreset{
			MaxRuntimeHours:    24,
			MaxRequestsPerHour: 100,
			MaxConcurrency:     2,
			MaxNewURLsPerCycle: 10000,
		},
		Cycle: CyclePreset{
			IntervalMinutes: 120,
			DeltaOnlyMode:   true,
		},
		Network: NetworkPreset{
			TimeoutSeconds: 30,
			Retries:        2,
			Backoff:        "exponential",
			JitterMs:       2000,
		},
		Checks: ChecksPreset{
			PassiveOnly:        true,
			ExcludedCategories: []string{"brute", "dos", "fuzzing"},
			SeverityMax:        "medium",
		},
		Notify: NotifyPreset{
			Threshold:       "high",
			DigestMode:      true,
			DigestIntervalMin: 60,
		},
		Safety: SafetyPreset{
			PassiveOnly:   true,
			NoAuth:        true,
			NoDestructive: true,
			NoCloud:       true,
		},
	}
}

// BalancedPreset returns balanced preset
func BalancedPreset() *Preset {
	return &Preset{
		Name:        "balanced",
		Description: "Dengeli tarama profili - varsayılan",
		Budgets: BudgetPreset{
			MaxRuntimeHours:    12,
			MaxRequestsPerHour: 1000,
			MaxConcurrency:     10,
			MaxNewURLsPerCycle: 50000,
		},
		Cycle: CyclePreset{
			IntervalMinutes: 60,
			DeltaOnlyMode:   true,
		},
		Network: NetworkPreset{
			TimeoutSeconds: 15,
			Retries:        2,
			Backoff:        "exponential",
			JitterMs:       500,
		},
		Checks: ChecksPreset{
			PassiveOnly:        false,
			ExcludedCategories: []string{"brute", "dos"},
			SeverityMax:        "high",
		},
		Notify: NotifyPreset{
			Threshold:       "high",
			DigestMode:      true,
			DigestIntervalMin: 30,
		},
		Safety: SafetyPreset{
			PassiveOnly:   false,
			NoAuth:        true,
			NoDestructive: true,
			NoCloud:       true,
		},
	}
}

// AggressivePreset returns aggressive preset
func AggressivePreset() *Preset {
	return &Preset{
		Name:        "aggressive",
		Description: "Yüksek hızlı, geniş kapsamlı tarama profili",
		Budgets: BudgetPreset{
			MaxRuntimeHours:    6,
			MaxRequestsPerHour: 5000,
			MaxConcurrency:     50,
			MaxNewURLsPerCycle: 100000,
		},
		Cycle: CyclePreset{
			IntervalMinutes: 30,
			DeltaOnlyMode:   true,
		},
		Network: NetworkPreset{
			TimeoutSeconds: 10,
			Retries:        3,
			Backoff:        "linear",
			JitterMs:       100,
		},
		Checks: ChecksPreset{
			PassiveOnly:        false,
			ExcludedCategories: []string{"dos"},
			SeverityMax:        "critical",
		},
		Notify: NotifyPreset{
			Threshold:       "medium",
			DigestMode:      false,
			DigestIntervalMin: 0,
		},
		Safety: SafetyPreset{
			PassiveOnly:   false,
			NoAuth:        true,
			NoDestructive: true, // Still no destructive
			NoCloud:       false,
		},
	}
}

// LoadConfig loads config from file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// SaveConfig saves config to file
func SaveConfig(config *Config, path string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	os.MkdirAll(filepath.Dir(path), 0755)
	return os.WriteFile(path, data, 0644)
}
