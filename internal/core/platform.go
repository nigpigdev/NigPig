// Package core provides cross-platform utilities
package core

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// IsWindows indicates if running on Windows
var IsWindows = runtime.GOOS == "windows"

// IsLinux indicates if running on Linux
var IsLinux = runtime.GOOS == "linux"

// IsDarwin indicates if running on macOS
var IsDarwin = runtime.GOOS == "darwin"

// GetHomeDir returns the user's home directory
func GetHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		if IsWindows {
			return os.Getenv("USERPROFILE")
		}
		return os.Getenv("HOME")
	}
	return home
}

// GetNigPigHome returns the NigPig config directory
func GetNigPigHome() string {
	// Check environment variable first
	if envHome := os.Getenv("NIGPIG_HOME"); envHome != "" {
		return envHome
	}

	if IsWindows {
		appData := os.Getenv("APPDATA")
		if appData != "" {
			return filepath.Join(appData, "NigPig")
		}
	}
	return filepath.Join(GetHomeDir(), ".nigpig")
}

// GetWorkspacePath returns the workspace path for a target
func GetWorkspacePath(target string) string {
	sanitized := SanitizeFilename(target)
	return filepath.Join(GetNigPigHome(), "workspaces", sanitized)
}

// GetTempDir returns a temp directory for NigPig
func GetTempDir() string {
	return filepath.Join(os.TempDir(), "nigpig")
}

// NormalizePath normalizes path separators for the current OS
func NormalizePath(path string) string {
	if IsWindows {
		return strings.ReplaceAll(path, "/", "\\")
	}
	return strings.ReplaceAll(path, "\\", "/")
}

// ExecutableName returns the executable name with proper extension
func ExecutableName(name string) string {
	if IsWindows && !strings.HasSuffix(name, ".exe") {
		return name + ".exe"
	}
	return name
}

// SanitizeFilename removes/replaces invalid characters for cross-platform filenames
func SanitizeFilename(name string) string {
	// Windows-invalid characters: < > : " / \ | ? *
	// Also replace spaces and control characters
	invalids := regexp.MustCompile(`[<>:"/\\|?*\s\x00-\x1f]`)
	result := invalids.ReplaceAllString(name, "_")

	// Truncate if too long
	if len(result) > 40 {
		result = result[:40]
	}

	return result
}

// GenerateReportFilename generates a report filename
// Format: NigPig_YYYY-MM-DD_HH-mm-ss_<TARGET>_<PROFILE>_run-<RUNID>.txt
func GenerateReportFilename(target, profile, runID string) string {
	timestamp := CurrentTime().Format("2006-01-02_15-04-05")
	sanitizedTarget := SanitizeFilename(target)
	sanitizedProfile := SanitizeFilename(profile)
	shortRunID := runID
	if len(runID) > 8 {
		shortRunID = runID[:8]
	}

	return fmt.Sprintf("NigPig_%s_%s_%s_run-%s.txt",
		timestamp, sanitizedTarget, sanitizedProfile, shortRunID)
}

// EnsureUniqueFilename ensures filename is unique by adding suffix
func EnsureUniqueFilename(path string) string {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return path
	}

	ext := filepath.Ext(path)
	base := path[:len(path)-len(ext)]

	for i := 1; i < 100; i++ {
		newPath := fmt.Sprintf("%s_%02d%s", base, i, ext)
		if _, err := os.Stat(newPath); os.IsNotExist(err) {
			return newPath
		}
	}

	return path
}

// WriteFileAtomic writes a file atomically using temp file + rename
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Create temp file in same directory
	tempFile := path + ".tmp"
	if err := os.WriteFile(tempFile, data, perm); err != nil {
		return err
	}

	// Rename (atomic on most systems)
	return os.Rename(tempFile, path)
}

// FindExecutable finds an executable in PATH or common locations
func FindExecutable(name string) (string, bool) {
	// Try PATH first
	exeName := ExecutableName(name)
	if path, err := exec.LookPath(exeName); err == nil {
		return path, true
	}

	// Try common Go install locations
	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		goPath = filepath.Join(GetHomeDir(), "go")
	}

	commonPaths := []string{
		filepath.Join(goPath, "bin", exeName),
		filepath.Join(GetHomeDir(), ".local", "bin", exeName),
		filepath.Join("/usr/local/bin", exeName),
		filepath.Join("/usr/bin", exeName),
	}

	for _, p := range commonPaths {
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
	}

	return "", false
}

// GetShell returns the appropriate shell for the OS
func GetShell() (string, []string) {
	if IsWindows {
		// Try PowerShell first, then cmd
		if _, err := exec.LookPath("powershell.exe"); err == nil {
			return "powershell.exe", []string{"-NoProfile", "-NonInteractive", "-Command"}
		}
		return "cmd.exe", []string{"/C"}
	}
	// Linux/macOS
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	return shell, []string{"-c"}
}

// RunCommand runs a command and returns output
func RunCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// GetOSInfo returns OS information string
func GetOSInfo() string {
	return fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
}

// CurrentWorkingDir returns current working directory
func CurrentWorkingDir() string {
	cwd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return cwd
}
