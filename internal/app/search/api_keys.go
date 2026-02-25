package search

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// --- API Keys ---

func (c *Config) loadGoogleAPIKeysDefault() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(home, ".config", "banshee", "keys.txt")
	return c.readGoogleApiKeysFromFile(path)
}

func (c *Config) readGoogleApiKeysFromFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var keys []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		keys = append(keys, line)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("no API keys in file")
	}
	c.ApiKeys = keys
	return nil
}

func (c *Config) loadBraveAPIKeysDefault() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(home, ".config", "banshee", "brave-keys.txt")
	return c.readBraveApiKeysFromFile(path)
}

func (c *Config) readBraveApiKeysFromFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var keys []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		keys = append(keys, line)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("no Brave API keys in file")
	}
	c.BraveAPIKeys = keys
	return nil
}

func (c *Config) getRandomBraveApiKey() (string, error) {
	available := make([]string, 0, len(c.BraveAPIKeys))
	now := time.Now()

	for _, k := range c.BraveAPIKeys {
		if _, ex := c.ExhaustedBraveKeys[k]; ex {
			continue
		}
		// Check rate limit: 1 req/sec per key
		if lastUsed, ok := c.BraveKeyLastUsed[k]; ok {
			// Add small buffer to be safe (1.1 seconds)
			if now.Sub(lastUsed) < 1100*time.Millisecond {
				continue
			}
		}
		available = append(available, k)
	}

	if len(available) == 0 {
		return "", errors.New("no available Brave API keys (rate limited or exhausted)")
	}

	// Rotate pseudo-randomly by time
	idx := int(time.Now().UnixNano()) % len(available)
	selectedKey := available[idx]
	c.BraveKeyLastUsed[selectedKey] = now

	return selectedKey, nil
}

