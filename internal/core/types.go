// Package core provides types and shared functionality
package core

import (
	"time"
)

// RunConfig holds configuration for a run
type RunConfig struct {
	// Identity
	RunID     string    `json:"run_id"`
	Target    string    `json:"target"`
	Program   string    `json:"program"`
	Profile   string    `json:"profile"`
	ScopePath string    `json:"scope_path"`
	StartedAt time.Time `json:"started_at"`

	// Sub-configs
	Budgets BudgetConfig  `json:"budgets"`
	Cycle   CycleConfig   `json:"cycle"`
	Network NetworkConfig `json:"network"`
	Auth    AuthConfig    `json:"auth"`
	Notify  NotifyConfig  `json:"notify"`
	Cache   CacheConfig   `json:"cache"`
	Safety  SafetyConfig  `json:"safety"`
}

// BudgetConfig holds budget limits
type BudgetConfig struct {
	MaxRuntimeHours    int `json:"max_runtime_hours" yaml:"max_runtime_hours"`
	MaxRequestsPerHour int `json:"max_requests_per_hour" yaml:"max_requests_per_hour"`
	MaxConcurrency     int `json:"max_concurrency" yaml:"max_concurrency"`
	MaxNewURLsPerCycle int `json:"max_new_urls_per_cycle" yaml:"max_new_urls_per_cycle"`
}

// CycleConfig holds cycle settings
type CycleConfig struct {
	IntervalMinutes int  `json:"interval_minutes" yaml:"interval_minutes"`
	DeltaOnlyMode   bool `json:"delta_only_mode" yaml:"delta_only_mode"`
}

// NetworkConfig holds network settings
type NetworkConfig struct {
	TimeoutSeconds int    `json:"timeout_seconds" yaml:"timeout_seconds"`
	Retries        int    `json:"retries" yaml:"retries"`
	Backoff        string `json:"backoff" yaml:"backoff"`
	Proxy          string `json:"proxy" yaml:"proxy"`
	UserAgent      string `json:"user_agent" yaml:"user_agent"`
}

// AuthConfig holds authentication settings
type AuthConfig struct {
	ProfileName string `json:"profile_name" yaml:"profile_name"`
	Enabled     bool   `json:"enabled" yaml:"enabled"`
}

// NotifyConfig holds notification settings
type NotifyConfig struct {
	Channels            []string `json:"channels" yaml:"channels"`
	Threshold           string   `json:"threshold" yaml:"threshold"`
	DigestMode          bool     `json:"digest_mode" yaml:"digest_mode"`
	DigestIntervalMinutes int    `json:"digest_interval_minutes" yaml:"digest_interval_minutes"`
}

// CacheConfig holds cache settings
type CacheConfig struct {
	TTLDays    int  `json:"ttl_days" yaml:"ttl_days"`
	ReuseETags bool `json:"reuse_etags" yaml:"reuse_etags"`
}

// SafetyConfig holds safety settings
type SafetyConfig struct {
	PassiveOnly   bool   `json:"passive_only" yaml:"passive_only"`
	NoAuth        bool   `json:"no_auth" yaml:"no_auth"`
	NoDestructive bool   `json:"no_destructive" yaml:"no_destructive"`
	NoCloud       bool   `json:"no_cloud" yaml:"no_cloud"`
	MaxSeverity   string `json:"max_severity" yaml:"max_severity"`
}

// RunStats holds statistics for a run
type RunStats struct {
	// Identity
	Target   string    `json:"target"`
	RunID    string    `json:"run_id"`
	StartedAt time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	TotalDuration time.Duration `json:"total_duration"`
	CycleCount int `json:"cycle_count"`

	// Discovery stats
	SubdomainsFound int `json:"subdomains_found"`
	SubdomainsNew   int `json:"subdomains_new"`
	LiveHostsFound  int `json:"live_hosts_found"`
	URLsDiscovered  int `json:"urls_discovered"`
	URLsNew         int `json:"urls_new"`

	// Check stats
	ChecksRun      int `json:"checks_run"`
	TemplatesUsed  int `json:"templates_used"`

	// Finding stats
	Findings FindingStats `json:"findings"`

	// Rate limiting
	ThrottleEvents  int `json:"throttle_events"`
	BackoffEvents   int `json:"backoff_events"`
	OutOfScopeBlocks int `json:"out_of_scope_blocks"`

	// Errors and warnings
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// FindingStats holds finding statistics
type FindingStats struct {
	Total         int `json:"total"`
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
	Info          int `json:"info"`
	Verified      int `json:"verified"`
	FalsePositive int `json:"false_positive"`
	NeedsManual   int `json:"needs_manual"`
}

// Finding represents a security finding
type Finding struct {
	ID            string       `json:"id"`
	Title         string       `json:"title"`
	Category      string       `json:"category"`
	Severity      Severity     `json:"severity"`
	Confidence    float64      `json:"confidence"`
	AffectedAsset string       `json:"affected_asset"`
	AffectedURL   string       `json:"affected_url"`
	Parameter     string       `json:"parameter,omitempty"`
	Evidence      Evidence     `json:"evidence"`
	ReproNotes    string       `json:"repro_notes,omitempty"`
	ToolChain     []string     `json:"tool_chain"`
	VerifyStatus  VerifyStatus `json:"verify_status"`
	CreatedAt     time.Time    `json:"created_at"`
	UpdatedAt     time.Time    `json:"updated_at"`
	LastSeenAt    time.Time    `json:"last_seen_at"`
}

// Evidence holds evidence for a finding
type Evidence struct {
	Requests   []string `json:"requests,omitempty"`
	Responses  []string `json:"responses,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Screenshot string   `json:"screenshot,omitempty"`
	MatchedAt  string   `json:"matched_at,omitempty"`
}

// Severity levels
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// VerifyStatus represents verification status
type VerifyStatus string

const (
	VerifyNew         VerifyStatus = "new"
	VerifyVerified    VerifyStatus = "verified"
	VerifyFalsePositive VerifyStatus = "false_positive"
	VerifyNeedsManual VerifyStatus = "needs_manual"
)

// ProfileDefaults returns default configuration for a profile
func ProfileDefaults(profile string) *RunConfig {
	switch profile {
	case "stealth":
		return &RunConfig{
			Profile: "stealth",
			Budgets: BudgetConfig{
				MaxRuntimeHours:    24,
				MaxRequestsPerHour: 100,
				MaxConcurrency:     2,
				MaxNewURLsPerCycle: 10000,
			},
			Cycle: CycleConfig{
				IntervalMinutes: 120,
				DeltaOnlyMode:   true,
			},
			Network: NetworkConfig{
				TimeoutSeconds: 30,
				Retries:        2,
				Backoff:        "exponential",
			},
			Notify: NotifyConfig{
				Threshold:  "high",
				DigestMode: true,
			},
			Safety: SafetyConfig{
				PassiveOnly:   true,
				NoAuth:        true,
				NoDestructive: true,
				NoCloud:       true,
			},
		}
	case "aggressive":
		return &RunConfig{
			Profile: "aggressive",
			Budgets: BudgetConfig{
				MaxRuntimeHours:    6,
				MaxRequestsPerHour: 5000,
				MaxConcurrency:     50,
				MaxNewURLsPerCycle: 100000,
			},
			Cycle: CycleConfig{
				IntervalMinutes: 30,
				DeltaOnlyMode:   true,
			},
			Network: NetworkConfig{
				TimeoutSeconds: 10,
				Retries:        3,
				Backoff:        "linear",
			},
			Notify: NotifyConfig{
				Threshold:  "medium",
				DigestMode: false,
			},
			Safety: SafetyConfig{
				PassiveOnly:   false,
				NoAuth:        true,
				NoDestructive: true,
				NoCloud:       false,
			},
		}
	default: // balanced
		return &RunConfig{
			Profile: "balanced",
			Budgets: BudgetConfig{
				MaxRuntimeHours:    12,
				MaxRequestsPerHour: 1000,
				MaxConcurrency:     10,
				MaxNewURLsPerCycle: 50000,
			},
			Cycle: CycleConfig{
				IntervalMinutes: 60,
				DeltaOnlyMode:   true,
			},
			Network: NetworkConfig{
				TimeoutSeconds: 15,
				Retries:        2,
				Backoff:        "exponential",
			},
			Notify: NotifyConfig{
				Threshold:  "high",
				DigestMode: true,
			},
			Safety: SafetyConfig{
				PassiveOnly:   false,
				NoAuth:        true,
				NoDestructive: true,
				NoCloud:       true,
			},
		}
	}
}
