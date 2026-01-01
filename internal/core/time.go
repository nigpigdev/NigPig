// Package core provides time utilities
package core

import (
	"fmt"
	"time"
)

// CurrentTime returns the current time
// Centralized for potential mocking in tests
func CurrentTime() time.Time {
	return time.Now()
}

// FormatDuration formats a duration for display
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d saniye", int(d.Seconds()))
	}
	if d < time.Hour {
		mins := int(d.Minutes())
		secs := int(d.Seconds()) % 60
		return fmt.Sprintf("%d dk %d sn", mins, secs)
	}

	hours := int(d.Hours())
	mins := int(d.Minutes()) % 60
	return fmt.Sprintf("%d saat %d dk", hours, mins)
}

// ParseDuration parses a duration string with Turkish support
func ParseDuration(s string) (time.Duration, error) {
	// Standard Go parsing first
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}

	// Try simple number (default: seconds)
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err == nil {
		return time.Duration(n) * time.Second, nil
	}

	return 0, fmt.Errorf("invalid duration: %s", s)
}
