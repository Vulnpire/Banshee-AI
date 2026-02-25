package monitor

import (
	"bufio"
	"os"
	"strings"
)

// appendDorksToIgnoreFile appends new dorks to the ignore file.
func appendDorksToIgnoreFile(filename string, dorks []string) error {
	// Read existing dorks.
	existing := make(map[string]struct{})
	if fileExists(filename) {
		lines, err := readLines(filename)
		if err != nil {
			return err
		}
		for _, line := range lines {
			existing[strings.TrimSpace(line)] = struct{}{}
		}
	}

	// Open file for appending.
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := bufio.NewWriter(f)
	defer writer.Flush()

	// Append only new dorks.
	for _, dork := range dorks {
		dork = strings.TrimSpace(dork)
		if _, exists := existing[dork]; !exists {
			writer.WriteString(dork + "\n")
		}
	}

	return nil
}
