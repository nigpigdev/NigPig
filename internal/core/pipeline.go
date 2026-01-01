// Package core provides the pipeline orchestrator and scheduling
package core

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Pipeline orchestrates the execution of stages
type Pipeline struct {
	stages       []Stage
	config       *RunConfig
	state        *PipelineState
	rateControl  *AdaptiveRateControl
	backpressure *BackpressureController
	mu           sync.RWMutex
}

// Stage represents a pipeline stage
type Stage interface {
	Name() string
	Run(ctx context.Context, input StageInput) (*StageOutput, error)
	CanSkip(state *PipelineState) bool
}

// StageInput provides input for a stage
type StageInput struct {
	Config      *RunConfig
	State       *PipelineState
	DeltaMode   bool
	Baseline    *BaselineSnapshot
	RateControl *AdaptiveRateControl
}

// StageOutput holds stage results
type StageOutput struct {
	Items       []interface{}
	NewItems    int
	DeltaItems  int
	SkippedItems int
	Errors      []error
	Metrics     map[string]int64
}

// PipelineState tracks current pipeline state
type PipelineState struct {
	RunID           string
	CycleNum        int
	StartedAt       time.Time
	LastCycleAt     time.Time
	IsBaseline      bool
	
	// Discovery state
	Subdomains      []string
	LiveHosts       []string
	URLs            []string
	Endpoints       []string
	
	// Delta tracking
	NewSubdomains   []string
	NewHosts        []string
	NewURLs         []string
	ChangedAssets   []string
	
	// Findings
	Findings        []*Finding
	VerifiedFindings []*Finding
	
	// Metrics
	TotalRequests   int64
	ThrottleEvents  int
	BackoffEvents   int
	OOSBlocks       int
	
	// Errors
	Errors          []string
	Warnings        []string
	
	mu sync.RWMutex
}

// BaselineSnapshot holds baseline data for delta comparison
type BaselineSnapshot struct {
	Timestamp       time.Time              `json:"timestamp"`
	Subdomains      map[string]AssetRecord `json:"subdomains"`
	Endpoints       map[string]AssetRecord `json:"endpoints"`
	URLs            map[string]AssetRecord `json:"urls"`
	JSHashes        map[string]string      `json:"js_hashes"`
	Fingerprints    map[string]string      `json:"fingerprints"`
}

// AssetRecord tracks an asset's state
type AssetRecord struct {
	Value         string    `json:"value"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	Hash          string    `json:"hash,omitempty"`
	ETag          string    `json:"etag,omitempty"`
	LastModified  string    `json:"last_modified,omitempty"`
	StatusCode    int       `json:"status_code,omitempty"`
	Fingerprint   string    `json:"fingerprint,omitempty"`
}

// DeltaResult represents delta detection result
type DeltaResult struct {
	Type        DeltaType
	Asset       string
	OldValue    string
	NewValue    string
	Priority    int // higher = more important
	Description string
}

// DeltaType represents types of changes
type DeltaType string

const (
	DeltaNewSubdomain    DeltaType = "new_subdomain"
	DeltaNewEndpoint     DeltaType = "new_endpoint"
	DeltaNewURL          DeltaType = "new_url"
	DeltaJSHashChanged   DeltaType = "js_hash_changed"
	DeltaFingerprintChanged DeltaType = "fingerprint_changed"
	DeltaCertificateNew  DeltaType = "certificate_new"
	DeltaDNSChanged      DeltaType = "dns_changed"
)

// HotspotScore calculates priority score for delta
func (d *DeltaResult) HotspotScore() int {
	base := d.Priority
	
	// Boost for high-value patterns
	highValuePatterns := []string{
		"admin", "api", "internal", "dev", "staging",
		"upload", "config", "backup", "secret", "private",
	}
	
	for _, pattern := range highValuePatterns {
		if containsIgnoreCase(d.Asset, pattern) {
			base += 50
			break
		}
	}
	
	// Type-based scoring
	switch d.Type {
	case DeltaNewSubdomain:
		base += 30
	case DeltaJSHashChanged:
		base += 40 // JS changes often reveal new endpoints
	case DeltaCertificateNew:
		base += 35
	case DeltaNewEndpoint:
		base += 25
	}
	
	return base
}

// NewPipeline creates a new pipeline
func NewPipeline(config *RunConfig) *Pipeline {
	return &Pipeline{
		config: config,
		state: &PipelineState{
			RunID:     config.RunID,
			StartedAt: CurrentTime(),
		},
		rateControl:  NewAdaptiveRateControl(config),
		backpressure: NewBackpressureController(config.Budgets.MaxConcurrency),
	}
}

// AddStage adds a stage to the pipeline
func (p *Pipeline) AddStage(stage Stage) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stages = append(p.stages, stage)
}

// Run executes the pipeline
func (p *Pipeline) Run(ctx context.Context, deltaMode bool, baseline *BaselineSnapshot) error {
	p.state.mu.Lock()
	p.state.CycleNum++
	p.state.LastCycleAt = CurrentTime()
	p.state.IsBaseline = !deltaMode
	p.state.mu.Unlock()

	for _, stage := range p.stages {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Check if stage can be skipped
		if stage.CanSkip(p.state) {
			continue
		}

		// Prepare input
		input := StageInput{
			Config:      p.config,
			State:       p.state,
			DeltaMode:   deltaMode,
			Baseline:    baseline,
			RateControl: p.rateControl,
		}

		// Run stage
		output, err := stage.Run(ctx, input)
		if err != nil {
			p.state.mu.Lock()
			p.state.Errors = append(p.state.Errors, fmt.Sprintf("[%s] %v", stage.Name(), err))
			p.state.mu.Unlock()
			// Continue with next stage (degrade mode)
			continue
		}

		// Collect errors from output
		if output != nil && len(output.Errors) > 0 {
			p.state.mu.Lock()
			for _, e := range output.Errors {
				p.state.Errors = append(p.state.Errors, fmt.Sprintf("[%s] %v", stage.Name(), e))
			}
			p.state.mu.Unlock()
		}
	}

	return nil
}

// GetState returns current pipeline state
func (p *Pipeline) GetState() *PipelineState {
	p.state.mu.RLock()
	defer p.state.mu.RUnlock()
	return p.state
}

// AdaptiveRateControl manages request rates adaptively
type AdaptiveRateControl struct {
	config        *RunConfig
	currentRPM    int64
	maxRPM        int64
	currentConc   int32
	maxConc       int32
	throttleCount int32
	backoffCount  int32
	lastThrottle  time.Time
	cooldownUntil time.Time
	mu            sync.RWMutex
}

// NewAdaptiveRateControl creates rate controller
func NewAdaptiveRateControl(config *RunConfig) *AdaptiveRateControl {
	maxRPM := int64(config.Budgets.MaxRequestsPerHour / 60)
	if maxRPM < 1 {
		maxRPM = 1
	}
	
	return &AdaptiveRateControl{
		config:      config,
		currentRPM:  maxRPM / 2, // Start at half capacity
		maxRPM:      maxRPM,
		currentConc: int32(config.Budgets.MaxConcurrency / 2),
		maxConc:     int32(config.Budgets.MaxConcurrency),
	}
}

// Acquire tries to acquire a request slot
func (arc *AdaptiveRateControl) Acquire(ctx context.Context) bool {
	arc.mu.RLock()
	if CurrentTime().Before(arc.cooldownUntil) {
		arc.mu.RUnlock()
		// In cooldown, wait with jitter
		jitter := time.Duration(100+arc.backoffCount*50) * time.Millisecond
		select {
		case <-ctx.Done():
			return false
		case <-time.After(jitter):
		}
	} else {
		arc.mu.RUnlock()
	}
	
	return true
}

// RecordThrottle records a throttle event (429/503/captcha)
func (arc *AdaptiveRateControl) RecordThrottle() {
	arc.mu.Lock()
	defer arc.mu.Unlock()
	
	atomic.AddInt32(&arc.throttleCount, 1)
	arc.lastThrottle = CurrentTime()
	
	// Reduce rate
	arc.currentRPM = arc.currentRPM * 70 / 100 // Reduce by 30%
	if arc.currentRPM < 1 {
		arc.currentRPM = 1
	}
	
	// Reduce concurrency
	arc.currentConc = arc.currentConc * 70 / 100
	if arc.currentConc < 1 {
		arc.currentConc = 1
	}
	
	// Set cooldown
	backoffDuration := time.Duration(atomic.LoadInt32(&arc.backoffCount)+1) * 5 * time.Second
	arc.cooldownUntil = CurrentTime().Add(backoffDuration)
	atomic.AddInt32(&arc.backoffCount, 1)
}

// RecordSuccess records a successful request
func (arc *AdaptiveRateControl) RecordSuccess() {
	arc.mu.Lock()
	defer arc.mu.Unlock()
	
	// If stable for a while, gradually increase
	if CurrentTime().Sub(arc.lastThrottle) > 2*time.Minute {
		if arc.currentRPM < arc.maxRPM {
			arc.currentRPM = arc.currentRPM * 105 / 100 // Increase by 5%
			if arc.currentRPM > arc.maxRPM {
				arc.currentRPM = arc.maxRPM
			}
		}
		if arc.currentConc < arc.maxConc {
			arc.currentConc++
			if arc.currentConc > arc.maxConc {
				arc.currentConc = arc.maxConc
			}
		}
	}
}

// GetConcurrency returns current allowed concurrency
func (arc *AdaptiveRateControl) GetConcurrency() int {
	arc.mu.RLock()
	defer arc.mu.RUnlock()
	return int(arc.currentConc)
}

// GetStats returns rate control statistics
func (arc *AdaptiveRateControl) GetStats() (throttles, backoffs int) {
	return int(atomic.LoadInt32(&arc.throttleCount)), int(atomic.LoadInt32(&arc.backoffCount))
}

// BackpressureController manages backpressure
type BackpressureController struct {
	maxQueue    int
	currentLoad int32
	mu          sync.RWMutex
}

// NewBackpressureController creates backpressure controller
func NewBackpressureController(maxConcurrency int) *BackpressureController {
	return &BackpressureController{
		maxQueue: maxConcurrency * 10,
	}
}

// CanProduce checks if producer should continue
func (bp *BackpressureController) CanProduce() bool {
	return atomic.LoadInt32(&bp.currentLoad) < int32(bp.maxQueue)
}

// Produce increments the load
func (bp *BackpressureController) Produce() {
	atomic.AddInt32(&bp.currentLoad, 1)
}

// Consume decrements the load
func (bp *BackpressureController) Consume() {
	atomic.AddInt32(&bp.currentLoad, -1)
}

// GetLoad returns current load
func (bp *BackpressureController) GetLoad() int {
	return int(atomic.LoadInt32(&bp.currentLoad))
}

// Helper
func containsIgnoreCase(s, substr string) bool {
	return len(s) >= len(substr) && 
		(s == substr || 
		 len(substr) > 0 && 
		 (s[0] == substr[0] || s[0]+32 == substr[0] || s[0]-32 == substr[0]))
}
