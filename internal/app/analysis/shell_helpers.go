package analysis

import "strings"

// shellescape escapes a string for safe use in shell commands.
func shellescape(s string) string {
	s = strings.ReplaceAll(s, "'", "'\\''")
	return "'" + s + "'"
}
