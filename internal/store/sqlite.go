package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/nigpig/nigpig/internal/core"
)

// Store handles SQLite database operations
type Store struct {
	db   *sql.DB
	path string
	mu   sync.RWMutex
}

// NewStore creates a new store for a workspace
func NewStore(workspacePath string) (*Store, error) {
	if err := os.MkdirAll(workspacePath, 0755); err != nil {
		return nil, err
	}

	dbPath := filepath.Join(workspacePath, "nigpig.db")
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}

	store := &Store{
		db:   db,
		path: dbPath,
	}

	if err := store.migrate(); err != nil {
		db.Close()
		return nil, err
	}

	return store, nil
}

// Close closes the database
func (s *Store) Close() error {
	return s.db.Close()
}

// migrate creates the database schema
func (s *Store) migrate() error {
	schema := `
	-- Runs table
	CREATE TABLE IF NOT EXISTS runs (
		id TEXT PRIMARY KEY,
		target TEXT NOT NULL,
		program TEXT,
		profile TEXT,
		config_json TEXT,
		status TEXT DEFAULT 'running',
		started_at DATETIME,
		finished_at DATETIME,
		stats_json TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Subdomains table
	CREATE TABLE IF NOT EXISTS subdomains (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		run_id TEXT,
		domain TEXT NOT NULL,
		source TEXT,
		resolved_ips TEXT,
		first_seen_at DATETIME,
		last_seen_at DATETIME,
		status TEXT DEFAULT 'new',
		UNIQUE(run_id, domain),
		FOREIGN KEY (run_id) REFERENCES runs(id)
	);

	-- URLs table
	CREATE TABLE IF NOT EXISTS urls (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		run_id TEXT,
		url TEXT NOT NULL,
		normalized_url TEXT,
		method TEXT DEFAULT 'GET',
		status_code INTEGER,
		content_type TEXT,
		content_hash TEXT,
		source TEXT,
		first_seen_at DATETIME,
		last_seen_at DATETIME,
		checked_at DATETIME,
		UNIQUE(run_id, normalized_url),
		FOREIGN KEY (run_id) REFERENCES runs(id)
	);

	-- Findings table
	CREATE TABLE IF NOT EXISTS findings (
		id TEXT PRIMARY KEY,
		run_id TEXT,
		title TEXT NOT NULL,
		category TEXT,
		severity TEXT,
		confidence REAL,
		affected_asset TEXT,
		affected_url TEXT,
		parameter TEXT,
		evidence_json TEXT,
		repro_notes TEXT,
		tool_chain TEXT,
		verify_status TEXT DEFAULT 'new',
		created_at DATETIME,
		updated_at DATETIME,
		last_seen_at DATETIME,
		FOREIGN KEY (run_id) REFERENCES runs(id)
	);

	-- Delta tracking table
	CREATE TABLE IF NOT EXISTS delta_state (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		run_id TEXT,
		item_type TEXT,
		item_id TEXT,
		item_hash TEXT,
		seen_at DATETIME,
		UNIQUE(run_id, item_type, item_id),
		FOREIGN KEY (run_id) REFERENCES runs(id)
	);

	-- Audit log for out-of-scope blocks
	CREATE TABLE IF NOT EXISTS audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		run_id TEXT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		event_type TEXT,
		target TEXT,
		reason TEXT,
		details TEXT,
		FOREIGN KEY (run_id) REFERENCES runs(id)
	);

	-- Indexes
	CREATE INDEX IF NOT EXISTS idx_subdomains_domain ON subdomains(domain);
	CREATE INDEX IF NOT EXISTS idx_urls_url ON urls(normalized_url);
	CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
	CREATE INDEX IF NOT EXISTS idx_findings_verify ON findings(verify_status);
	CREATE INDEX IF NOT EXISTS idx_delta_type ON delta_state(item_type);
	`

	_, err := s.db.Exec(schema)
	return err
}

// Run operations

// SaveRun saves or updates a run
func (s *Store) SaveRun(config *core.RunConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	configJSON, _ := json.Marshal(config)

	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO runs (id, target, program, profile, config_json, started_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, config.RunID, config.Target, config.Program, config.Profile, configJSON, config.StartedAt)

	return err
}

// UpdateRunStats updates run statistics
func (s *Store) UpdateRunStats(runID string, stats *core.RunStats) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	statsJSON, _ := json.Marshal(stats)
	var finishedAt interface{}
	if stats.FinishedAt != nil {
		finishedAt = *stats.FinishedAt
	}

	_, err := s.db.Exec(`
		UPDATE runs SET stats_json = ?, finished_at = ?, status = ? WHERE id = ?
	`, statsJSON, finishedAt, "completed", runID)

	return err
}

// GetRun retrieves a run by ID
func (s *Store) GetRun(runID string) (*core.RunConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var configJSON string
	err := s.db.QueryRow(`SELECT config_json FROM runs WHERE id = ?`, runID).Scan(&configJSON)
	if err != nil {
		return nil, err
	}

	var config core.RunConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// Subdomain operations

// SaveSubdomain saves a discovered subdomain
func (s *Store) SaveSubdomain(runID, domain, source string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	_, err := s.db.Exec(`
		INSERT INTO subdomains (run_id, domain, source, first_seen_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(run_id, domain) DO UPDATE SET 
			last_seen_at = ?, source = COALESCE(source || ',' || ?, source)
	`, runID, domain, source, now, now, now, source)

	return err
}

// GetSubdomains retrieves subdomains for a run
func (s *Store) GetSubdomains(runID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`SELECT domain FROM subdomains WHERE run_id = ?`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			continue
		}
		domains = append(domains, domain)
	}

	return domains, nil
}

// GetNewSubdomains returns subdomains not seen before
func (s *Store) GetNewSubdomains(runID string, since time.Time) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT domain FROM subdomains 
		WHERE run_id = ? AND first_seen_at > ?
	`, runID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			continue
		}
		domains = append(domains, domain)
	}

	return domains, nil
}

// URL operations

// SaveURL saves a discovered URL
func (s *Store) SaveURL(runID, url, normalizedURL, source string, statusCode int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	_, err := s.db.Exec(`
		INSERT INTO urls (run_id, url, normalized_url, source, status_code, first_seen_at, last_seen_at, checked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(run_id, normalized_url) DO UPDATE SET 
			last_seen_at = ?, checked_at = ?, status_code = ?
	`, runID, url, normalizedURL, source, statusCode, now, now, now, now, now, statusCode)

	return err
}

// GetURLs retrieves URLs for a run
func (s *Store) GetURLs(runID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`SELECT url FROM urls WHERE run_id = ?`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var urls []string
	for rows.Next() {
		var url string
		if err := rows.Scan(&url); err != nil {
			continue
		}
		urls = append(urls, url)
	}

	return urls, nil
}

// Finding operations

// SaveFinding saves a finding
func (s *Store) SaveFinding(runID string, finding *core.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	evidenceJSON, _ := json.Marshal(finding.Evidence)
	toolChain := ""
	if len(finding.ToolChain) > 0 {
		data, _ := json.Marshal(finding.ToolChain)
		toolChain = string(data)
	}

	now := time.Now()
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO findings 
		(id, run_id, title, category, severity, confidence, affected_asset, affected_url, 
		 parameter, evidence_json, repro_notes, tool_chain, verify_status, created_at, updated_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, finding.ID, runID, finding.Title, finding.Category, finding.Severity, finding.Confidence,
		finding.AffectedAsset, finding.AffectedURL, finding.Parameter, evidenceJSON,
		finding.ReproNotes, toolChain, finding.VerifyStatus, finding.CreatedAt, now, now)

	return err
}

// GetFindings retrieves findings for a run
func (s *Store) GetFindings(runID string) ([]*core.Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT id, title, category, severity, confidence, affected_asset, affected_url, 
			   parameter, evidence_json, repro_notes, tool_chain, verify_status, created_at
		FROM findings WHERE run_id = ?
	`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []*core.Finding
	for rows.Next() {
		f := &core.Finding{}
		var evidenceJSON, toolChainJSON string
		var severity, verifyStatus string

		err := rows.Scan(&f.ID, &f.Title, &f.Category, &severity, &f.Confidence,
			&f.AffectedAsset, &f.AffectedURL, &f.Parameter, &evidenceJSON,
			&f.ReproNotes, &toolChainJSON, &verifyStatus, &f.CreatedAt)
		if err != nil {
			continue
		}

		f.Severity = core.Severity(severity)
		f.VerifyStatus = core.VerifyStatus(verifyStatus)

		if evidenceJSON != "" {
			json.Unmarshal([]byte(evidenceJSON), &f.Evidence)
		}
		if toolChainJSON != "" {
			json.Unmarshal([]byte(toolChainJSON), &f.ToolChain)
		}

		findings = append(findings, f)
	}

	return findings, nil
}

// UpdateFindingStatus updates a finding's verification status
func (s *Store) UpdateFindingStatus(findingID string, status core.VerifyStatus, confidence float64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		UPDATE findings SET verify_status = ?, confidence = ?, updated_at = ? WHERE id = ?
	`, status, confidence, time.Now(), findingID)

	return err
}

// Delta operations

// SaveDeltaState saves state for delta comparison
func (s *Store) SaveDeltaState(runID, itemType, itemID, itemHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO delta_state (run_id, item_type, item_id, item_hash, seen_at)
		VALUES (?, ?, ?, ?, ?)
	`, runID, itemType, itemID, itemHash, time.Now())

	return err
}

// IsNewItem checks if an item is new (not seen before)
func (s *Store) IsNewItem(runID, itemType, itemID string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM delta_state WHERE run_id = ? AND item_type = ? AND item_id = ?
	`, runID, itemType, itemID).Scan(&count)

	return count == 0, err
}

// HasItemChanged checks if an item's hash has changed
func (s *Store) HasItemChanged(runID, itemType, itemID, newHash string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var oldHash string
	err := s.db.QueryRow(`
		SELECT item_hash FROM delta_state WHERE run_id = ? AND item_type = ? AND item_id = ?
	`, runID, itemType, itemID).Scan(&oldHash)

	if err == sql.ErrNoRows {
		return true, nil // New item
	}
	if err != nil {
		return false, err
	}

	return oldHash != newHash, nil
}

// Audit operations

// LogOutOfScope logs an out-of-scope block
func (s *Store) LogOutOfScope(runID, target, reason, details string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		INSERT INTO audit_log (run_id, event_type, target, reason, details)
		VALUES (?, 'out_of_scope', ?, ?, ?)
	`, runID, target, reason, details)

	return err
}

// GetOutOfScopeCount returns count of out-of-scope blocks
func (s *Store) GetOutOfScopeCount(runID string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM audit_log WHERE run_id = ? AND event_type = 'out_of_scope'
	`, runID).Scan(&count)

	return count, err
}

// Stats operations

// GetFindingsStats returns finding statistics
func (s *Store) GetFindingsStats(runID string) (*core.FindingStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := &core.FindingStats{}

	rows, err := s.db.Query(`
		SELECT severity, verify_status, COUNT(*) 
		FROM findings WHERE run_id = ?
		GROUP BY severity, verify_status
	`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var severity, verifyStatus string
		var count int
		if err := rows.Scan(&severity, &verifyStatus, &count); err != nil {
			continue
		}

		stats.Total += count

		switch core.Severity(severity) {
		case core.SeverityCritical:
			stats.Critical += count
		case core.SeverityHigh:
			stats.High += count
		case core.SeverityMedium:
			stats.Medium += count
		case core.SeverityLow:
			stats.Low += count
		case core.SeverityInfo:
			stats.Info += count
		}

		switch core.VerifyStatus(verifyStatus) {
		case core.VerifyVerified:
			stats.Verified += count
		case core.VerifyFalsePositive:
			stats.FalsePositive += count
		case core.VerifyNeedsManual:
			stats.NeedsManual += count
		}
	}

	return stats, nil
}

// Cleanup deletes old data
func (s *Store) Cleanup(olderThan time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-olderThan)

	_, err := s.db.Exec(`DELETE FROM audit_log WHERE timestamp < ?`, cutoff)
	if err != nil {
		return fmt.Errorf("audit_log cleanup: %w", err)
	}

	return nil
}
