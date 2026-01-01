// Package core provides delta intelligence for ASM
package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// DeltaEngine provides attack surface monitoring and delta detection
type DeltaEngine struct {
	baseline    *BaselineSnapshot
	current     *BaselineSnapshot
	changes     []DeltaResult
	jsPatterns  []*regexp.Regexp
	mu          sync.RWMutex
}

// NewDeltaEngine creates a new delta engine
func NewDeltaEngine() *DeltaEngine {
	de := &DeltaEngine{
		jsPatterns: compileJSPatterns(),
	}
	return de
}

// LoadBaseline loads baseline from file
func (de *DeltaEngine) LoadBaseline(path string) error {
	de.mu.Lock()
	defer de.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// No baseline yet
			de.baseline = nil
			return nil
		}
		return err
	}

	var baseline BaselineSnapshot
	if err := json.Unmarshal(data, &baseline); err != nil {
		return err
	}

	de.baseline = &baseline
	return nil
}

// SaveBaseline saves current state as baseline
func (de *DeltaEngine) SaveBaseline(path string) error {
	de.mu.RLock()
	defer de.mu.RUnlock()

	if de.current == nil {
		return nil
	}

	data, err := json.MarshalIndent(de.current, "", "  ")
	if err != nil {
		return err
	}

	os.MkdirAll(filepath.Dir(path), 0755)
	return WriteFileAtomic(path, data, 0644)
}

// HasBaseline checks if baseline exists
func (de *DeltaEngine) HasBaseline() bool {
	de.mu.RLock()
	defer de.mu.RUnlock()
	return de.baseline != nil
}

// GetBaseline returns the baseline snapshot
func (de *DeltaEngine) GetBaseline() *BaselineSnapshot {
	de.mu.RLock()
	defer de.mu.RUnlock()
	return de.baseline
}

// InitCurrentSnapshot initializes current snapshot
func (de *DeltaEngine) InitCurrentSnapshot() {
	de.mu.Lock()
	defer de.mu.Unlock()

	de.current = &BaselineSnapshot{
		Timestamp:    CurrentTime(),
		Subdomains:   make(map[string]AssetRecord),
		Endpoints:    make(map[string]AssetRecord),
		URLs:         make(map[string]AssetRecord),
		JSHashes:     make(map[string]string),
		Fingerprints: make(map[string]string),
	}
	de.changes = nil
}

// RecordSubdomain records a subdomain
func (de *DeltaEngine) RecordSubdomain(subdomain string) *DeltaResult {
	de.mu.Lock()
	defer de.mu.Unlock()

	subdomain = strings.ToLower(subdomain)
	now := CurrentTime()

	// Check if new
	isNew := false
	if de.baseline != nil {
		if _, exists := de.baseline.Subdomains[subdomain]; !exists {
			isNew = true
		}
	} else {
		isNew = true
	}

	// Record in current
	record := AssetRecord{
		Value:     subdomain,
		FirstSeen: now,
		LastSeen:  now,
	}
	if existing, ok := de.current.Subdomains[subdomain]; ok {
		record.FirstSeen = existing.FirstSeen
	}
	de.current.Subdomains[subdomain] = record

	if isNew && de.baseline != nil {
		delta := &DeltaResult{
			Type:        DeltaNewSubdomain,
			Asset:       subdomain,
			Priority:    50,
			Description: "New subdomain discovered",
		}
		de.changes = append(de.changes, *delta)
		return delta
	}

	return nil
}

// RecordEndpoint records an endpoint
func (de *DeltaEngine) RecordEndpoint(url string, statusCode int, fingerprint string) *DeltaResult {
	de.mu.Lock()
	defer de.mu.Unlock()

	normalized := normalizeURL(url)
	now := CurrentTime()

	// Check if new or changed
	var delta *DeltaResult
	if de.baseline != nil {
		if existing, exists := de.baseline.Endpoints[normalized]; exists {
			// Check fingerprint change
			if existing.Fingerprint != "" && fingerprint != "" && existing.Fingerprint != fingerprint {
				delta = &DeltaResult{
					Type:        DeltaFingerprintChanged,
					Asset:       url,
					OldValue:    existing.Fingerprint,
					NewValue:    fingerprint,
					Priority:    40,
					Description: "Endpoint fingerprint changed",
				}
			}
		} else {
			delta = &DeltaResult{
				Type:        DeltaNewEndpoint,
				Asset:       url,
				Priority:    45,
				Description: "New endpoint discovered",
			}
		}
	}

	// Record in current
	record := AssetRecord{
		Value:       url,
		FirstSeen:   now,
		LastSeen:    now,
		StatusCode:  statusCode,
		Fingerprint: fingerprint,
	}
	if existing, ok := de.current.Endpoints[normalized]; ok {
		record.FirstSeen = existing.FirstSeen
	}
	de.current.Endpoints[normalized] = record

	if delta != nil {
		de.changes = append(de.changes, *delta)
	}

	return delta
}

// RecordJSFile records a JS file and checks for changes
func (de *DeltaEngine) RecordJSFile(url string, content []byte) (*DeltaResult, []string) {
	de.mu.Lock()
	defer de.mu.Unlock()

	hash := hashContent(content)
	normalized := normalizeURL(url)

	// Check if hash changed
	var delta *DeltaResult
	if de.baseline != nil {
		if oldHash, exists := de.baseline.JSHashes[normalized]; exists {
			if oldHash != hash {
				delta = &DeltaResult{
					Type:        DeltaJSHashChanged,
					Asset:       url,
					OldValue:    oldHash[:16] + "...",
					NewValue:    hash[:16] + "...",
					Priority:    60, // High priority - JS changes often reveal new endpoints
					Description: "JavaScript file content changed",
				}
			}
		}
	}

	// Record current hash
	de.current.JSHashes[normalized] = hash

	if delta != nil {
		de.changes = append(de.changes, *delta)
	}

	// Extract endpoints from JS
	endpoints := de.extractEndpointsFromJS(string(content))

	return delta, endpoints
}

// RecordDNSChange records a DNS resolution change
func (de *DeltaEngine) RecordDNSChange(domain string, oldIPs, newIPs []string) *DeltaResult {
	de.mu.Lock()
	defer de.mu.Unlock()

	if sameIPs(oldIPs, newIPs) {
		return nil
	}

	delta := &DeltaResult{
		Type:        DeltaDNSChanged,
		Asset:       domain,
		OldValue:    strings.Join(oldIPs, ","),
		NewValue:    strings.Join(newIPs, ","),
		Priority:    35,
		Description: "DNS resolution changed",
	}

	de.changes = append(de.changes, *delta)
	return delta
}

// GetChanges returns all detected changes
func (de *DeltaEngine) GetChanges() []DeltaResult {
	de.mu.RLock()
	defer de.mu.RUnlock()
	return append([]DeltaResult{}, de.changes...)
}

// GetPrioritizedChanges returns changes sorted by priority
func (de *DeltaEngine) GetPrioritizedChanges() []DeltaResult {
	changes := de.GetChanges()
	
	// Simple bubble sort by hotspot score (could use sort.Slice)
	for i := 0; i < len(changes)-1; i++ {
		for j := i + 1; j < len(changes); j++ {
			if changes[i].HotspotScore() < changes[j].HotspotScore() {
				changes[i], changes[j] = changes[j], changes[i]
			}
		}
	}
	
	return changes
}

// GetNewSubdomains returns only new subdomains
func (de *DeltaEngine) GetNewSubdomains() []string {
	de.mu.RLock()
	defer de.mu.RUnlock()

	var newSubs []string
	for _, change := range de.changes {
		if change.Type == DeltaNewSubdomain {
			newSubs = append(newSubs, change.Asset)
		}
	}
	return newSubs
}

// GetNewEndpoints returns only new endpoints
func (de *DeltaEngine) GetNewEndpoints() []string {
	de.mu.RLock()
	defer de.mu.RUnlock()

	var newEndpoints []string
	for _, change := range de.changes {
		if change.Type == DeltaNewEndpoint {
			newEndpoints = append(newEndpoints, change.Asset)
		}
	}
	return newEndpoints
}

// GetChangedJSFiles returns JS files with changed hashes
func (de *DeltaEngine) GetChangedJSFiles() []string {
	de.mu.RLock()
	defer de.mu.RUnlock()

	var changed []string
	for _, change := range de.changes {
		if change.Type == DeltaJSHashChanged {
			changed = append(changed, change.Asset)
		}
	}
	return changed
}

// PromoteCurrentToBaseline promotes current snapshot to baseline
func (de *DeltaEngine) PromoteCurrentToBaseline() {
	de.mu.Lock()
	defer de.mu.Unlock()
	de.baseline = de.current
	de.current = nil
	de.changes = nil
}

// extractEndpointsFromJS extracts potential endpoints from JS content
func (de *DeltaEngine) extractEndpointsFromJS(content string) []string {
	var endpoints []string
	seen := make(map[string]bool)

	for _, pattern := range de.jsPatterns {
		matches := pattern.FindAllString(content, -1)
		for _, match := range matches {
			// Clean up the match
			match = strings.Trim(match, `"'` + "`")
			if !seen[match] && isValidEndpoint(match) {
				seen[match] = true
				endpoints = append(endpoints, match)
			}
		}
	}

	return endpoints
}

// compileJSPatterns compiles regex patterns for JS endpoint extraction
func compileJSPatterns() []*regexp.Regexp {
	patterns := []string{
		// API paths
		`["'` + "`" + `](/api/[a-zA-Z0-9/_-]+)["'` + "`" + `]`,
		`["'` + "`" + `](/v[0-9]+/[a-zA-Z0-9/_-]+)["'` + "`" + `]`,
		
		// Relative paths
		`["'` + "`" + `](/[a-zA-Z][a-zA-Z0-9/_-]{2,50})["'` + "`" + `]`,
		
		// Full URLs
		`https?://[a-zA-Z0-9][a-zA-Z0-9.-]+/[a-zA-Z0-9/_-]+`,
		
		// GraphQL
		`["'` + "`" + `](/graphql[a-zA-Z0-9/_-]*)["'` + "`" + `]`,
		
		// REST patterns
		`["'` + "`" + `](/[a-z]+/:[a-zA-Z]+)["'` + "`" + `]`,
	}

	var compiled []*regexp.Regexp
	for _, p := range patterns {
		if re, err := regexp.Compile(p); err == nil {
			compiled = append(compiled, re)
		}
	}
	return compiled
}

// Helper functions

func hashContent(content []byte) string {
	h := sha256.Sum256(content)
	return hex.EncodeToString(h[:])
}

func normalizeURL(rawURL string) string {
	// Simple normalization - could be more sophisticated
	rawURL = strings.ToLower(rawURL)
	rawURL = strings.TrimSuffix(rawURL, "/")
	rawURL = strings.ReplaceAll(rawURL, ":80/", "/")
	rawURL = strings.ReplaceAll(rawURL, ":443/", "/")
	return rawURL
}

func sameIPs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]bool)
	for _, ip := range a {
		m[ip] = true
	}
	for _, ip := range b {
		if !m[ip] {
			return false
		}
	}
	return true
}

func isValidEndpoint(s string) bool {
	if len(s) < 2 || len(s) > 200 {
		return false
	}
	// Filter out obvious non-endpoints
	invalids := []string{".js", ".css", ".png", ".jpg", ".gif", ".svg", ".woff", ".ico"}
	for _, inv := range invalids {
		if strings.HasSuffix(s, inv) {
			return false
		}
	}
	return strings.HasPrefix(s, "/") || strings.HasPrefix(s, "http")
}
