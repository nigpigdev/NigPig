// Package scope provides scope management and out-of-scope blocking
package scope

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Scope represents scope configuration
type Scope struct {
	Program   string     `yaml:"program"`
	Target    string     `yaml:"target"`
	Platform  string     `yaml:"platform"`
	InScope   InScope    `yaml:"in_scope"`
	OutScope  OutScope   `yaml:"out_of_scope"`
	Rules     Rules      `yaml:"rules"`
	Notes     string     `yaml:"notes"`
}

// InScope defines allowed targets
type InScope struct {
	Domains []string `yaml:"domains"`
	IPs     []string `yaml:"ips"`
	Ports   []int    `yaml:"ports"`
	CIDRs   []string `yaml:"cidrs"`
}

// OutScope defines blocked targets
type OutScope struct {
	Domains  []string `yaml:"domains"`
	Paths    []string `yaml:"paths"`
	Keywords []string `yaml:"keywords"`
}

// Rules defines testing rules
type Rules struct {
	DestructiveTests bool `yaml:"destructive_tests"`
	BruteForce       bool `yaml:"brute_force"`
	AuthTesting      bool `yaml:"auth_testing"`
	CloudTesting     bool `yaml:"cloud_testing"`
	RateLimit        int  `yaml:"rate_limit"`
	MaxConnections   int  `yaml:"max_connections"`
	RespectRobots    bool `yaml:"respect_robots"`
}

// Guard provides scope checking with audit logging
type Guard struct {
	scope      *Scope
	auditLog   *AuditLog
	patterns   []*regexp.Regexp
	mu         sync.RWMutex
}

// BlockReason describes why a target was blocked
type BlockReason string

const (
	BlockOutOfScopeDomain BlockReason = "out_of_scope_domain"
	BlockOutOfScopePath   BlockReason = "out_of_scope_path"
	BlockNotInScope       BlockReason = "not_in_scope"
	BlockKeyword          BlockReason = "blocked_keyword"
	BlockPort             BlockReason = "blocked_port"
)

// AuditEntry represents an audit log entry
type AuditEntry struct {
	Timestamp time.Time   `json:"timestamp"`
	Target    string      `json:"target"`
	Reason    BlockReason `json:"reason"`
	Details   string      `json:"details"`
	Module    string      `json:"module"`
}

// AuditLog handles audit logging
type AuditLog struct {
	path    string
	entries []AuditEntry
	mu      sync.Mutex
}

// NewGuard creates a new scope guard
func NewGuard(scopePath string) (*Guard, error) {
	scope, err := Load(scopePath)
	if err != nil {
		return nil, err
	}

	g := &Guard{
		scope: scope,
	}

	// Compile out-of-scope patterns
	for _, pattern := range scope.OutScope.Paths {
		// Convert glob to regex
		regexPattern := globToRegex(pattern)
		if re, err := regexp.Compile(regexPattern); err == nil {
			g.patterns = append(g.patterns, re)
		}
	}

	return g, nil
}

// NewGuardWithAudit creates a guard with audit logging
func NewGuardWithAudit(scopePath, workspacePath string) (*Guard, error) {
	g, err := NewGuard(scopePath)
	if err != nil {
		return nil, err
	}

	g.auditLog = &AuditLog{
		path: filepath.Join(workspacePath, "audit.jsonl"),
	}

	return g, nil
}

// Load loads scope from YAML file
func Load(path string) (*Scope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var scope Scope
	if err := yaml.Unmarshal(data, &scope); err != nil {
		return nil, err
	}

	// Set defaults
	if scope.Rules.RateLimit == 0 {
		scope.Rules.RateLimit = 10
	}
	if scope.Rules.MaxConnections == 0 {
		scope.Rules.MaxConnections = 5
	}

	return &scope, nil
}

// IsInScope checks if a domain is in scope
func (g *Guard) IsInScope(domain string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	domain = strings.ToLower(domain)

	// Check out-of-scope first
	for _, oos := range g.scope.OutScope.Domains {
		if matchDomain(domain, oos) {
			return false
		}
	}

	// Check in-scope
	for _, is := range g.scope.InScope.Domains {
		if matchDomain(domain, is) {
			return true
		}
	}

	return false
}

// CheckURL checks if a URL is in scope
// Returns (inScope, reason)
func (g *Guard) CheckURL(rawURL string) (bool, BlockReason, string) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false, BlockNotInScope, "invalid URL"
	}

	domain := parsed.Hostname()
	path := parsed.Path

	// Check domain
	isInScope := false
	for _, is := range g.scope.InScope.Domains {
		if matchDomain(domain, is) {
			isInScope = true
			break
		}
	}

	if !isInScope {
		return false, BlockNotInScope, "domain not in scope: " + domain
	}

	// Check out-of-scope domains
	for _, oos := range g.scope.OutScope.Domains {
		if matchDomain(domain, oos) {
			return false, BlockOutOfScopeDomain, "out of scope domain: " + oos
		}
	}

	// Check out-of-scope paths
	for _, pattern := range g.patterns {
		if pattern.MatchString(path) {
			return false, BlockOutOfScopePath, "out of scope path pattern"
		}
	}

	// Check keywords
	for _, keyword := range g.scope.OutScope.Keywords {
		if strings.Contains(strings.ToLower(rawURL), strings.ToLower(keyword)) {
			return false, BlockKeyword, "blocked keyword: " + keyword
		}
	}

	// Check port
	if len(g.scope.InScope.Ports) > 0 {
		port := parsed.Port()
		if port == "" {
			if parsed.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}

		portAllowed := false
		for _, p := range g.scope.InScope.Ports {
			if port == strconv.Itoa(p) {
				portAllowed = true
				break
			}
		}

		if !portAllowed {
			// Default ports are usually OK
			if port != "80" && port != "443" {
				return false, BlockPort, "port not in scope: " + port
			}
		}
	}

	return true, "", ""
}

// CheckAndLog checks URL and logs if blocked
func (g *Guard) CheckAndLog(rawURL, module string) bool {
	inScope, reason, details := g.CheckURL(rawURL)

	if !inScope && g.auditLog != nil {
		g.auditLog.Log(AuditEntry{
			Timestamp: time.Now(),
			Target:    rawURL,
			Reason:    reason,
			Details:   details,
			Module:    module,
		})
	}

	return inScope
}

// FilterURLs filters a list of URLs, returning only in-scope ones
func (g *Guard) FilterURLs(urls []string, module string) []string {
	var inScope []string
	for _, u := range urls {
		if g.CheckAndLog(u, module) {
			inScope = append(inScope, u)
		}
	}
	return inScope
}

// FilterDomains filters a list of domains, returning only in-scope ones
func (g *Guard) FilterDomains(domains []string, module string) []string {
	var inScope []string
	for _, d := range domains {
		if g.IsInScope(d) {
			inScope = append(inScope, d)
		} else if g.auditLog != nil {
			g.auditLog.Log(AuditEntry{
				Timestamp: time.Now(),
				Target:    d,
				Reason:    BlockNotInScope,
				Details:   "domain not in scope",
				Module:    module,
			})
		}
	}
	return inScope
}

// CanRunDestructive checks if destructive tests are allowed
func (g *Guard) CanRunDestructive() bool {
	return g.scope.Rules.DestructiveTests
}

// CanRunBruteForce checks if brute force is allowed
func (g *Guard) CanRunBruteForce() bool {
	return g.scope.Rules.BruteForce
}

// CanTestAuth checks if auth testing is allowed
func (g *Guard) CanTestAuth() bool {
	return g.scope.Rules.AuthTesting
}

// GetRateLimit returns the rate limit
func (g *Guard) GetRateLimit() int {
	return g.scope.Rules.RateLimit
}

// GetBlockedCount returns number of blocked requests
func (g *Guard) GetBlockedCount() int {
	if g.auditLog == nil {
		return 0
	}
	g.auditLog.mu.Lock()
	defer g.auditLog.mu.Unlock()
	return len(g.auditLog.entries)
}

// AuditLog methods

// Log adds an entry to the audit log
func (a *AuditLog) Log(entry AuditEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.entries = append(a.entries, entry)

	// Async write to file (simplified - would use buffered writer in production)
	// For now just accumulate in memory
}

// GetEntries returns all audit entries
func (a *AuditLog) GetEntries() []AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]AuditEntry{}, a.entries...)
}

// Helper functions

func matchDomain(domain, pattern string) bool {
	domain = strings.ToLower(domain)
	pattern = strings.ToLower(pattern)

	// Wildcard matching
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // .example.com
		return strings.HasSuffix(domain, suffix) || domain == pattern[2:]
	}

	return domain == pattern
}

func globToRegex(glob string) string {
	// Convert glob pattern to regex
	regex := regexp.QuoteMeta(glob)
	regex = strings.ReplaceAll(regex, `\*`, `.*`)
	regex = strings.ReplaceAll(regex, `\?`, `.`)
	return "^" + regex + "$"
}

// GenerateScope creates a minimal scope for a target
func GenerateScope(target string) *Scope {
	return &Scope{
		Program: target,
		Target:  target,
		InScope: InScope{
			Domains: []string{target, "*." + target},
			Ports:   []int{80, 443, 8080, 8443},
		},
		OutScope: OutScope{
			Paths: []string{"/logout", "/delete-*"},
		},
		Rules: Rules{
			DestructiveTests: false,
			BruteForce:       false,
			AuthTesting:      false,
			RateLimit:        10,
			MaxConnections:   5,
			RespectRobots:    true,
		},
	}
}

// Save saves scope to YAML file
func (s *Scope) Save(path string) error {
	data, err := yaml.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
