package search

import "regexp"

// convertToBraveDork converts Google dork syntax to Brave Search compatible format.
func convertToBraveDork(googleDork string) string {
	braveDork := googleDork

	// Convert -ext: to -filetype: (exclusion).
	braveDork = regexp.MustCompile(`-ext:(\w+)`).ReplaceAllString(braveDork, `-filetype:$1`)

	// Convert ext: to filetype: (inclusion).
	braveDork = regexp.MustCompile(`\bext:(\w+)`).ReplaceAllString(braveDork, `filetype:$1`)

	return braveDork
}
