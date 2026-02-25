package cve

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func (c *Config) callGeminiCLI(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	timeout := time.Duration(c.SmartTimeout) * time.Second
	if timeout == 0 {
		timeout = 150 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var args []string
	if c.AiModel != "" {
		args = []string{"--model", c.AiModel, "-p", userPrompt}
	} else {
		args = []string{"-p", userPrompt}
	}

	cmd := exec.CommandContext(ctx, "gemini-cli", args...)
	cmd.Stdin = strings.NewReader(systemPrompt)

	env := os.Environ()
	env = append(env, "NODE_NO_WARNINGS=1")
	cmd.Env = env

	if home, err := os.UserHomeDir(); err == nil {
		cmd.Dir = home
	}

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = nil

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("AI optimization timeout after %ds (configurable via ~/.config/banshee/.config: smart-timeout=%d)", c.SmartTimeout, c.SmartTimeout)
		}
		return "", fmt.Errorf("AI error: %v", err)
	}

	return stdout.String(), nil
}
