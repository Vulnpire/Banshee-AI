package ai

import "strings"

// shellescape escapes a string for safe use in shell commands.
func shellescape(s string) string {
	// Replace single quotes with '\'' (end quote, escaped quote, start quote).
	s = strings.ReplaceAll(s, "'", "'\\''")
	return "'" + s + "'"
}
