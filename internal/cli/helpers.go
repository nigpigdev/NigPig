package cli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/nigpig/nigpig/internal/core"
	"github.com/nigpig/nigpig/internal/scope"
)

// generateRunID generates a unique run ID
func generateRunID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// generateDefaultScope creates a default scope file for a target
func generateDefaultScope(target, path string) error {
	s := scope.GenerateScope(target)
	return s.Save(path)
}

// boolEmoji returns emoji for boolean
func boolEmoji(b bool) string {
	if b {
		return "✅"
	}
	return "❌"
}

// printSuccess prints a success message
func printSuccess(msg string) {
	fmt.Printf("  %s %s\n", color.GreenString("✓"), msg)
}

// printError prints an error message
func printError(msg string) {
	fmt.Printf("  %s %s\n", color.RedString("✗"), msg)
}

// printWarning prints a warning message
func printWarning(msg string) {
	fmt.Printf("  %s %s\n", color.YellowString("⚠"), msg)
}

// printInfo prints an info message
func printInfo(msg string) {
	fmt.Printf("  %s %s\n", color.CyanString("ℹ"), msg)
}

// printStep prints a step message
func printStep(msg string) {
	fmt.Printf("  %s %s\n", color.WhiteString("→"), msg)
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ensureDir ensures a directory exists
func ensureDir(path string) error {
	return os.MkdirAll(path, 0755)
}

// getWorkspaceReportPath returns the report path for a target
func getWorkspaceReportPath(target, format string) string {
	workspacePath := core.GetWorkspacePath(target)
	reportsDir := filepath.Join(workspacePath, "reports")
	os.MkdirAll(reportsDir, 0755)
	return filepath.Join(reportsDir, "latest."+format)
}  
