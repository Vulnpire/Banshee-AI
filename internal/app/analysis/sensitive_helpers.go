package analysis

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// saveSensitiveDocument saves a sensitive document to the tracking file.
// File location: ~/.config/banshee/sensitive-pdfs.txt
func saveSensitiveDocument(url, summary, details string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %v", err)
	}

	configDir := filepath.Join(home, ".config", "banshee")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	trackingFile := filepath.Join(configDir, "sensitive-pdfs.txt")
	f, err := os.OpenFile(trackingFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open tracking file: %v", err)
	}
	defer f.Close()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	entry := fmt.Sprintf("[%s] %s\n  Summary: %s\n  Details: %s\n\n", timestamp, url, summary, details)

	if _, err := f.WriteString(entry); err != nil {
		return fmt.Errorf("failed to write to tracking file: %v", err)
	}

	if err := f.Sync(); err != nil {
		return fmt.Errorf("failed to sync tracking file: %v", err)
	}

	return nil
}

// saveSuccessfulURL saves a successful URL with finding context to successful.txt.
// File location: ~/.config/banshee/successful.txt
// Format: URL (Finding type: description)
func saveSuccessfulURL(url, findingType, description string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %v", err)
	}

	configDir := filepath.Join(home, ".config", "banshee")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	successFile := filepath.Join(configDir, "successful.txt")
	f, err := os.OpenFile(successFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open successful file: %v", err)
	}
	defer f.Close()

	// Format: URL | findingType: description
	entry := fmt.Sprintf("%s | %s: %s\n", url, findingType, description)

	if _, err := f.WriteString(entry); err != nil {
		return fmt.Errorf("failed to write to successful file: %v", err)
	}

	if err := f.Sync(); err != nil {
		return fmt.Errorf("failed to sync successful file: %v", err)
	}

	return nil
}
