// Package auth provides secure auth session management
package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// SessionManager handles authenticated sessions
type SessionManager struct {
	profiles     map[string]*AuthProfile
	activeSession *AuthSession
	healthCheck  *HealthChecker
	storage      *SecureStorage
	mu           sync.RWMutex
}

// AuthProfile represents authentication credentials
type AuthProfile struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"` // cookie, bearer, basic, header
	Target      string            `json:"target"`
	Cookies     map[string]string `json:"cookies,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	BearerToken string            `json:"bearer_token,omitempty"`
	Username    string            `json:"username,omitempty"`
	Password    string            `json:"password,omitempty"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	LastUsed    time.Time         `json:"last_used"`
}

// AuthSession represents an active authenticated session
type AuthSession struct {
	Profile     *AuthProfile
	IsValid     bool
	LastChecked time.Time
	Warnings    []string
}

// HealthChecker validates session health
type HealthChecker struct {
	checkURL     string
	expectedCode int
	expectedBody string
}

// SessionStatus represents session health status
type SessionStatus struct {
	ProfileName string        `json:"profile_name"`
	IsValid     bool          `json:"is_valid"`
	ExpiresIn   time.Duration `json:"expires_in,omitempty"`
	Status      string        `json:"status"` // active, expiring_soon, expired, invalid
	Message     string        `json:"message"`
	CheckedAt   time.Time     `json:"checked_at"`
}

// SecureStorage handles encrypted credential storage
type SecureStorage struct {
	path string
	key  []byte
}

// NewSessionManager creates a new session manager
func NewSessionManager(storagePath string) (*SessionManager, error) {
	storage, err := NewSecureStorage(storagePath)
	if err != nil {
		return nil, err
	}

	sm := &SessionManager{
		profiles: make(map[string]*AuthProfile),
		storage:  storage,
	}

	// Load existing profiles
	sm.loadProfiles()

	return sm, nil
}

// AddProfile adds a new auth profile
func (sm *SessionManager) AddProfile(profile *AuthProfile) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	profile.CreatedAt = time.Now()
	profile.LastUsed = time.Now()
	sm.profiles[profile.Name] = profile

	return sm.saveProfiles()
}

// GetProfile retrieves a profile
func (sm *SessionManager) GetProfile(name string) (*AuthProfile, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	profile, ok := sm.profiles[name]
	return profile, ok
}

// ActivateProfile activates a profile for use
func (sm *SessionManager) ActivateProfile(name string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	profile, ok := sm.profiles[name]
	if !ok {
		return fmt.Errorf("profile not found: %s", name)
	}

	sm.activeSession = &AuthSession{
		Profile:     profile,
		IsValid:     true,
		LastChecked: time.Now(),
	}

	profile.LastUsed = time.Now()
	return nil
}

// GetActiveSession returns the active session
func (sm *SessionManager) GetActiveSession() *AuthSession {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.activeSession
}

// CheckSessionHealth checks if the active session is still valid
func (sm *SessionManager) CheckSessionHealth() *SessionStatus {
	sm.mu.RLock()
	session := sm.activeSession
	sm.mu.RUnlock()

	if session == nil {
		return &SessionStatus{
			IsValid:   false,
			Status:    "no_session",
			Message:   "Aktif oturum yok",
			CheckedAt: time.Now(),
		}
	}

	status := &SessionStatus{
		ProfileName: session.Profile.Name,
		CheckedAt:   time.Now(),
	}

	// Check expiration
	if session.Profile.ExpiresAt != nil {
		if time.Now().After(*session.Profile.ExpiresAt) {
			status.IsValid = false
			status.Status = "expired"
			status.Message = "Oturum süresi dolmuş"
			
			sm.mu.Lock()
			sm.activeSession.IsValid = false
			sm.mu.Unlock()
			
			return status
		}

		expiresIn := time.Until(*session.Profile.ExpiresAt)
		status.ExpiresIn = expiresIn

		if expiresIn < 30*time.Minute {
			status.Status = "expiring_soon"
			status.Message = fmt.Sprintf("Oturum %v içinde dolacak", expiresIn.Round(time.Minute))
			status.IsValid = true
			return status
		}
	}

	status.IsValid = true
	status.Status = "active"
	status.Message = "Oturum aktif"
	return status
}

// SetHealthChecker configures health check endpoint
func (sm *SessionManager) SetHealthChecker(url string, expectedCode int, expectedBody string) {
	sm.healthCheck = &HealthChecker{
		checkURL:     url,
		expectedCode: expectedCode,
		expectedBody: expectedBody,
	}
}

// RunHealthCheck performs an actual health check request
func (sm *SessionManager) RunHealthCheck() *SessionStatus {
	session := sm.GetActiveSession()
	if session == nil || sm.healthCheck == nil {
		return sm.CheckSessionHealth()
	}

	status := &SessionStatus{
		ProfileName: session.Profile.Name,
		CheckedAt:   time.Now(),
	}

	// Build request with auth
	req, err := http.NewRequest("GET", sm.healthCheck.checkURL, nil)
	if err != nil {
		status.IsValid = false
		status.Status = "error"
		status.Message = err.Error()
		return status
	}

	// Add auth headers
	sm.applyAuth(req, session.Profile)

	// Make request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		status.IsValid = false
		status.Status = "error"
		status.Message = "Health check failed: " + err.Error()
		return status
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != sm.healthCheck.expectedCode {
		status.IsValid = false
		status.Status = "invalid"
		status.Message = fmt.Sprintf("Beklenmeyen status code: %d", resp.StatusCode)
		
		sm.mu.Lock()
		sm.activeSession.IsValid = false
		sm.activeSession.Warnings = append(sm.activeSession.Warnings, status.Message)
		sm.mu.Unlock()
		
		return status
	}

	status.IsValid = true
	status.Status = "active"
	status.Message = "Oturum doğrulandı"

	sm.mu.Lock()
	sm.activeSession.LastChecked = time.Now()
	sm.mu.Unlock()

	return status
}

// ApplyAuth applies auth headers to a request
func (sm *SessionManager) ApplyAuth(req *http.Request) {
	session := sm.GetActiveSession()
	if session == nil || !session.IsValid {
		return
	}
	sm.applyAuth(req, session.Profile)
}

func (sm *SessionManager) applyAuth(req *http.Request, profile *AuthProfile) {
	// Apply custom headers
	for key, value := range profile.Headers {
		req.Header.Set(key, value)
	}

	// Apply auth type
	switch profile.Type {
	case "bearer":
		if profile.BearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+profile.BearerToken)
		}
	case "basic":
		if profile.Username != "" {
			req.SetBasicAuth(profile.Username, profile.Password)
		}
	case "cookie":
		var cookies []string
		for name, value := range profile.Cookies {
			cookies = append(cookies, fmt.Sprintf("%s=%s", name, value))
		}
		if len(cookies) > 0 {
			req.Header.Set("Cookie", strings.Join(cookies, "; "))
		}
	}
}

// GetRedactedHeaders returns auth headers with redacted secrets
func (sm *SessionManager) GetRedactedHeaders(profile *AuthProfile) map[string]string {
	redacted := make(map[string]string)

	for k, v := range profile.Headers {
		if containsSensitive(k) {
			redacted[k] = "[REDACTED]"
		} else {
			redacted[k] = v
		}
	}

	switch profile.Type {
	case "bearer":
		redacted["Authorization"] = "Bearer [REDACTED]"
	case "basic":
		redacted["Authorization"] = "Basic [REDACTED]"
	case "cookie":
		redacted["Cookie"] = "[REDACTED]"
	}

	return redacted
}

// PauseOnAuthFailure marks session as needing refresh
func (sm *SessionManager) PauseOnAuthFailure(reason string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.activeSession != nil {
		sm.activeSession.IsValid = false
		sm.activeSession.Warnings = append(sm.activeSession.Warnings, reason)
	}
}

// NeedsRefresh checks if session needs refresh
func (sm *SessionManager) NeedsRefresh() bool {
	session := sm.GetActiveSession()
	if session == nil {
		return false
	}
	return !session.IsValid
}

// loadProfiles loads profiles from storage
func (sm *SessionManager) loadProfiles() error {
	data, err := sm.storage.Load()
	if err != nil {
		return err
	}
	if data == nil {
		return nil
	}
	return json.Unmarshal(data, &sm.profiles)
}

// saveProfiles saves profiles to storage
func (sm *SessionManager) saveProfiles() error {
	data, err := json.MarshalIndent(sm.profiles, "", "  ")
	if err != nil {
		return err
	}
	return sm.storage.Save(data)
}

// SecureStorage implementation

// NewSecureStorage creates encrypted storage
func NewSecureStorage(basePath string) (*SecureStorage, error) {
	keyPath := basePath + ".key"
	
	var key []byte
	
	// Try to load or generate key
	if keyData, err := os.ReadFile(keyPath); err == nil {
		key = keyData
	} else {
		// Generate new key
		key = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, err
		}
		
		// Save key with restricted permissions
		os.MkdirAll(filepath.Dir(keyPath), 0700)
		if err := os.WriteFile(keyPath, key, 0600); err != nil {
			return nil, err
		}
	}
	
	return &SecureStorage{
		path: basePath,
		key:  key,
	}, nil
}

// Save encrypts and saves data
func (ss *SecureStorage) Save(data []byte) error {
	block, err := aes.NewCipher(ss.key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	encrypted := gcm.Seal(nonce, nonce, data, nil)

	os.MkdirAll(filepath.Dir(ss.path), 0700)
	return os.WriteFile(ss.path, encrypted, 0600)
}

// Load decrypts and loads data
func (ss *SecureStorage) Load() ([]byte, error) {
	encrypted, err := os.ReadFile(ss.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	block, err := aes.NewCipher(ss.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// GetSecureStoragePath returns appropriate secure storage path for OS
func GetSecureStoragePath() string {
	if runtime.GOOS == "windows" {
		appData := os.Getenv("APPDATA")
		if appData != "" {
			return filepath.Join(appData, "NigPig", "credentials.enc")
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".nigpig", "credentials.enc")
}

func containsSensitive(key string) bool {
	lower := strings.ToLower(key)
	sensitiveWords := []string{"auth", "token", "key", "secret", "password", "cookie"}
	for _, word := range sensitiveWords {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}
