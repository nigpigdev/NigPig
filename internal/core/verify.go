// Package core provides verification and corroboration for findings
package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// Verifier handles multi-step verification of findings
type Verifier struct {
	config        VerifyConfig
	redactor      *Redactor
	corroborator  *Corroborator
}

// VerifyConfig holds verification settings
type VerifyConfig struct {
	RecheckEnabled    bool          `yaml:"recheck_enabled"`
	RecheckDelay      time.Duration `yaml:"recheck_delay"`
	ControlRequest    bool          `yaml:"control_request"`
	RequireVerified   bool          `yaml:"require_verified_for_high"` // high/critical only if verified
}

// VerifyResult holds verification result
type VerifyResult struct {
	FindingID       string       `json:"finding_id"`
	Status          VerifyStatus `json:"status"`
	Confidence      float64      `json:"confidence"`
	RecheckPassed   bool         `json:"recheck_passed"`
	ControlPassed   bool         `json:"control_passed"`
	Corroborations  int          `json:"corroborations"`
	Reason          string       `json:"reason,omitempty"`
	VerifiedAt      time.Time    `json:"verified_at"`
}

// DefaultVerifyConfig returns default verify configuration
func DefaultVerifyConfig() VerifyConfig {
	return VerifyConfig{
		RecheckEnabled:  true,
		RecheckDelay:    30 * time.Second,
		ControlRequest:  true,
		RequireVerified: true,
	}
}

// NewVerifier creates a new verifier
func NewVerifier(config VerifyConfig) *Verifier {
	return &Verifier{
		config:       config,
		redactor:     NewRedactor(),
		corroborator: NewCorroborator(),
	}
}

// Verify performs multi-step verification
func (v *Verifier) Verify(finding *Finding) *VerifyResult {
	result := &VerifyResult{
		FindingID:  finding.ID,
		Status:     VerifyNew,
		Confidence: finding.Confidence,
		VerifiedAt: CurrentTime(),
	}

	// Step 1: Check corroboration
	corroborations := v.corroborator.GetCorroborationCount(finding)
	result.Corroborations = corroborations

	// Boost confidence for corroborated findings
	if corroborations >= 2 {
		result.Confidence += 0.2
		if result.Confidence > 1.0 {
			result.Confidence = 1.0
		}
	}

	// Step 2: Simulated recheck (in production would make actual request)
	if v.config.RecheckEnabled {
		// Simulate recheck - in real implementation, make HTTP request
		result.RecheckPassed = true // Placeholder
	}

	// Step 3: Control request (in production would make control request)
	if v.config.ControlRequest {
		result.ControlPassed = true // Placeholder
	}

	// Determine final status
	if result.RecheckPassed && result.ControlPassed && corroborations >= 2 {
		result.Status = VerifyVerified
		result.Confidence = 0.9
	} else if result.RecheckPassed && result.ControlPassed {
		result.Status = VerifyVerified
		result.Confidence = 0.8
	} else if result.RecheckPassed || corroborations >= 1 {
		result.Status = VerifyNeedsManual
		result.Confidence = 0.6
		result.Reason = "Partial verification - manual review recommended"
	} else {
		result.Status = VerifyFalsePositive
		result.Confidence = 0.3
		result.Reason = "Could not verify finding"
	}

	return result
}

// ShouldReportHighSeverity checks if finding should be reported as high/critical
func (v *Verifier) ShouldReportHighSeverity(finding *Finding, result *VerifyResult) bool {
	if !v.config.RequireVerified {
		return true
	}
	return result.Status == VerifyVerified
}

// Corroborator tracks multi-source corroboration
type Corroborator struct {
	observations map[string][]Observation
}

// Observation represents a single observation of a potential issue
type Observation struct {
	Source    string    `json:"source"`
	Timestamp time.Time `json:"timestamp"`
	Signature string    `json:"signature"`
	Details   string    `json:"details"`
}

// NewCorroborator creates a new corroborator
func NewCorroborator() *Corroborator {
	return &Corroborator{
		observations: make(map[string][]Observation),
	}
}

// Record records an observation
func (c *Corroborator) Record(finding *Finding, source string) {
	signature := c.generateSignature(finding)
	
	obs := Observation{
		Source:    source,
		Timestamp: CurrentTime(),
		Signature: signature,
		Details:   finding.Title,
	}
	
	c.observations[signature] = append(c.observations[signature], obs)
}

// GetCorroborationCount returns number of independent sources
func (c *Corroborator) GetCorroborationCount(finding *Finding) int {
	signature := c.generateSignature(finding)
	observations := c.observations[signature]
	
	// Count unique sources
	sources := make(map[string]bool)
	for _, obs := range observations {
		sources[obs.Source] = true
	}
	
	return len(sources)
}

// HasMultipleObservations checks if finding was seen multiple times
func (c *Corroborator) HasMultipleObservations(finding *Finding) bool {
	signature := c.generateSignature(finding)
	return len(c.observations[signature]) >= 2
}

// generateSignature creates a signature for finding grouping
func (c *Corroborator) generateSignature(finding *Finding) string {
	// Group by: type + affected asset (normalized) + parameter
	key := fmt.Sprintf("%s|%s|%s", finding.Category, normalizeURL(finding.AffectedURL), finding.Parameter)
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:8])
}

// EvidenceBundle represents evidence for a verified finding
type EvidenceBundle struct {
	FindingID     string            `json:"finding_id"`
	Title         string            `json:"title"`
	Severity      Severity          `json:"severity"`
	Confidence    float64           `json:"confidence"`
	VerifyStatus  VerifyStatus      `json:"verify_status"`
	AffectedURL   string            `json:"affected_url"`
	Parameter     string            `json:"parameter,omitempty"`
	Requests      []RedactedHTTP    `json:"requests"`
	Screenshots   []string          `json:"screenshots,omitempty"`
	ToolChain     []string          `json:"tool_chain"`
	Timestamps    []string          `json:"timestamps"`
	RunID         string            `json:"run_id"`
	GeneratedAt   time.Time         `json:"generated_at"`
}

// RedactedHTTP holds redacted HTTP request/response
type RedactedHTTP struct {
	Type     string `json:"type"` // request, response
	Method   string `json:"method,omitempty"`
	URL      string `json:"url,omitempty"`
	Status   int    `json:"status,omitempty"`
	Headers  string `json:"headers"` // redacted
	Body     string `json:"body"`    // redacted, truncated
}

// EvidenceBundler creates evidence bundles
type EvidenceBundler struct {
	workspacePath string
	redactor      *Redactor
}

// NewEvidenceBundler creates a new evidence bundler
func NewEvidenceBundler(workspacePath string) *EvidenceBundler {
	return &EvidenceBundler{
		workspacePath: workspacePath,
		redactor:      NewRedactor(),
	}
}

// CreateBundle creates an evidence bundle for a finding
func (eb *EvidenceBundler) CreateBundle(finding *Finding, runID string) (*EvidenceBundle, error) {
	bundle := &EvidenceBundle{
		FindingID:    finding.ID,
		Title:        finding.Title,
		Severity:     finding.Severity,
		Confidence:   finding.Confidence,
		VerifyStatus: finding.VerifyStatus,
		AffectedURL:  eb.redactor.Redact(finding.AffectedURL),
		Parameter:    finding.Parameter,
		ToolChain:    finding.ToolChain,
		RunID:        runID,
		GeneratedAt:  CurrentTime(),
	}

	// Add redacted request
	if finding.Evidence.Requests != nil && len(finding.Evidence.Requests) > 0 {
		for _, req := range finding.Evidence.Requests {
			bundle.Requests = append(bundle.Requests, RedactedHTTP{
				Type:    "request",
				Headers: eb.redactor.Redact(truncate(req, 1000)),
			})
		}
	}

	// Add redacted response
	if finding.Evidence.Responses != nil && len(finding.Evidence.Responses) > 0 {
		for _, resp := range finding.Evidence.Responses {
			bundle.Requests = append(bundle.Requests, RedactedHTTP{
				Type:    "response",
				Headers: eb.redactor.Redact(truncate(resp, 2000)),
			})
		}
	}

	// Add timestamps
	bundle.Timestamps = append(bundle.Timestamps, 
		finding.CreatedAt.Format(time.RFC3339),
		finding.UpdatedAt.Format(time.RFC3339))

	// Save bundle
	bundlePath := filepath.Join(eb.workspacePath, "evidence", finding.ID)
	if err := os.MkdirAll(bundlePath, 0755); err != nil {
		return nil, err
	}

	// Write bundle JSON
	bundleJSON, _ := json.MarshalIndent(bundle, "", "  ")
	bundleFile := filepath.Join(bundlePath, "bundle.json")
	if err := WriteFileAtomic(bundleFile, bundleJSON, 0644); err != nil {
		return nil, err
	}

	return bundle, nil
}

// GetBundlePath returns the path to evidence bundle
func (eb *EvidenceBundler) GetBundlePath(findingID string) string {
	return filepath.Join(eb.workspacePath, "evidence", findingID)
}

// Redactor handles sensitive data redaction
type Redactor struct {
	patterns []RedactPattern
}

// RedactPattern defines a redaction pattern
type RedactPattern struct {
	Name    string
	Pattern *regexp.Regexp
	Replace string
}

// NewRedactor creates a new redactor with default patterns
func NewRedactor() *Redactor {
	patterns := []struct {
		name    string
		pattern string
		replace string
	}{
		{"Authorization", `(?i)(authorization:\s*)[^\r\n]+`, "${1}[REDACTED]"},
		{"Cookie", `(?i)(cookie:\s*)[^\r\n]+`, "${1}[REDACTED]"},
		{"Set-Cookie", `(?i)(set-cookie:\s*)[^\r\n]+`, "${1}[REDACTED]"},
		{"Bearer", `(?i)(bearer\s+)[a-zA-Z0-9\-_\.]+`, "${1}[REDACTED]"},
		{"API Key", `(?i)(api[_-]?key[=:\s]+)[a-zA-Z0-9\-_\.]+`, "${1}[REDACTED]"},
		{"Password", `(?i)(password[=:\s]+)[^\s&"']+`, "${1}[REDACTED]"},
		{"Token", `(?i)(token[=:\s]+)[a-zA-Z0-9\-_\.]+`, "${1}[REDACTED]"},
		{"Secret", `(?i)(secret[=:\s]+)[a-zA-Z0-9\-_\.]+`, "${1}[REDACTED]"},
		{"AWS Key", `AKIA[0-9A-Z]{16}`, "[AWS_KEY_REDACTED]"},
		{"JWT", `eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]*`, "[JWT_REDACTED]"},
		{"Private Key", `-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----`, "[PRIVATE_KEY_REDACTED]"},
	}

	r := &Redactor{}
	for _, p := range patterns {
		if re, err := regexp.Compile(p.pattern); err == nil {
			r.patterns = append(r.patterns, RedactPattern{
				Name:    p.name,
				Pattern: re,
				Replace: p.replace,
			})
		}
	}

	return r
}

// Redact applies all redaction patterns
func (r *Redactor) Redact(s string) string {
	result := s
	for _, p := range r.patterns {
		result = p.Pattern.ReplaceAllString(result, p.Replace)
	}
	return result
}

// RedactMap redacts all values in a map
func (r *Redactor) RedactMap(m map[string]string) map[string]string {
	result := make(map[string]string)
	for k, v := range m {
		result[k] = r.Redact(v)
	}
	return result
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "\n... [truncated]"
}
