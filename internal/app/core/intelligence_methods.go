package core

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Vulnpire/Banshee-AI/internal/app/console"
)

// isDataFresh checks if a specific data type is still fresh based on TTL.
func (f *IntelligenceFreshness) isDataFresh(dataType string) bool {
	if f == nil {
		return false
	}

	now := time.Now()
	switch dataType {
	case "subdomains":
		return now.Sub(f.SubdomainsUpdated).Hours() < float64(f.SubdomainsTTL*24)
	case "techstack":
		return now.Sub(f.TechStackUpdated).Hours() < float64(f.TechStackTTL*24)
	case "dorks":
		return now.Sub(f.DorksUpdated).Hours() < float64(f.DorksTTL*24)
	case "patterns":
		return now.Sub(f.PatternsUpdated).Hours() < float64(f.PatternsTTL*24)
	default:
		return false
	}
}

// calculateFreshnessScore returns a score 0-100 based on data age.
func (f *IntelligenceFreshness) calculateFreshnessScore(dataType string) float64 {
	if f == nil {
		return 0
	}

	var age time.Duration
	var ttl int

	now := time.Now()
	switch dataType {
	case "subdomains":
		age = now.Sub(f.SubdomainsUpdated)
		ttl = f.SubdomainsTTL
	case "techstack":
		age = now.Sub(f.TechStackUpdated)
		ttl = f.TechStackTTL
	case "dorks":
		age = now.Sub(f.DorksUpdated)
		ttl = f.DorksTTL
	case "patterns":
		age = now.Sub(f.PatternsUpdated)
		ttl = f.PatternsTTL
	default:
		return 0
	}

	ageInDays := age.Hours() / 24
	ttlDays := float64(ttl)

	// Score decreases linearly from 100 to 0 as data ages from 0 to TTL.
	score := 100 * (1 - (ageInDays / ttlDays))
	if score < 0 {
		score = 0
	}
	return score
}

// updateFreshness marks a data type as freshly updated.
func (f *IntelligenceFreshness) updateFreshness(dataType string) {
	if f == nil {
		return
	}

	now := time.Now()
	switch dataType {
	case "subdomains":
		f.SubdomainsUpdated = now
	case "techstack":
		f.TechStackUpdated = now
	case "dorks":
		f.DorksUpdated = now
	case "patterns":
		f.PatternsUpdated = now
	}
}

// validatePattern tests a pattern and updates confidence scoring.
func (vm *ValidationMetrics) validatePattern(pattern string, success bool) {
	if vm == nil {
		return
	}

	if vm.PatternConfidence == nil {
		vm.PatternConfidence = make(map[string]float64)
	}

	// Initialize confidence if this is first validation.
	currentConfidence, exists := vm.PatternConfidence[pattern]
	if !exists {
		currentConfidence = 50.0
		vm.TotalPatterns++
	}

	alpha := 0.3
	if success {
		currentConfidence = currentConfidence + alpha*(100.0-currentConfidence)
	} else {
		currentConfidence = currentConfidence - alpha*currentConfidence
	}

	vm.PatternConfidence[pattern] = currentConfidence
	vm.ValidatedPatterns++
	vm.LastValidation = time.Now()

	vm.updateConfidenceCounts()
}

// updateConfidenceCounts recalculates high and low confidence pattern counts.
func (vm *ValidationMetrics) updateConfidenceCounts() {
	if vm == nil || vm.PatternConfidence == nil {
		return
	}

	high, low := 0, 0
	for _, conf := range vm.PatternConfidence {
		if conf > 70.0 {
			high++
		} else if conf < 30.0 {
			low++
		}
	}

	vm.HighConfidence = high
	vm.LowConfidence = low
}

// pruneLowPerformingPatterns removes patterns with confidence < threshold.
func (vm *ValidationMetrics) pruneLowPerformingPatterns(threshold float64) []string {
	if vm == nil || vm.PatternConfidence == nil {
		return nil
	}

	pruned := []string{}
	for pattern, confidence := range vm.PatternConfidence {
		if confidence < threshold {
			pruned = append(pruned, pattern)
			delete(vm.PatternConfidence, pattern)
			vm.PrunedPatterns++
			vm.TotalPatterns--
		}
	}

	vm.updateConfidenceCounts()
	return pruned
}

// cleanupExpiredIntelligence removes stale data based on TTL.
func (intel *TargetIntelligence) cleanupExpiredIntelligence() (cleaned int) {
	if intel == nil || intel.DataFreshness == nil {
		return 0
	}

	if !intel.DataFreshness.isDataFresh("subdomains") {
		originalCount := len(intel.DiscoveredSubdomains)
		intel.DiscoveredSubdomains = []string{}
		intel.SubdomainFirstSeen = make(map[string]time.Time)
		cleaned += originalCount
		console.Logv(false, "[Cleanup] Removed %d expired subdomains (>%d days old)", originalCount, intel.DataFreshness.SubdomainsTTL)
	}

	if !intel.DataFreshness.isDataFresh("techstack") {
		originalCount := len(intel.TechStack)
		intel.TechStack = []string{}
		cleaned += originalCount
		console.Logv(false, "[Cleanup] Removed %d expired tech stack entries (>%d days old)", originalCount, intel.DataFreshness.TechStackTTL)
	}

	if !intel.DataFreshness.isDataFresh("dorks") {
		originalCount := len(intel.SuccessfulDorks)
		newDorks := []DorkIntelligence{}
		for _, dork := range intel.SuccessfulDorks {
			age := time.Since(dork.LastUsed).Hours() / 24
			if age < float64(intel.DataFreshness.DorksTTL) {
				newDorks = append(newDorks, dork)
			}
		}
		intel.SuccessfulDorks = newDorks
		cleaned += originalCount - len(newDorks)
		console.Logv(false, "[Cleanup] Removed %d expired dorks (>%d days old)", originalCount-len(newDorks), intel.DataFreshness.DorksTTL)
	}

	if !intel.DataFreshness.isDataFresh("patterns") && intel.PatternStatistics != nil {
		originalCount := len(intel.PatternStatistics)
		for pattern, stats := range intel.PatternStatistics {
			age := time.Since(stats.LastSuccess).Hours() / 24
			if age > float64(intel.DataFreshness.PatternsTTL) {
				delete(intel.PatternStatistics, pattern)
			}
		}
		cleaned += originalCount - len(intel.PatternStatistics)
		console.Logv(false, "[Cleanup] Removed %d expired patterns (>%d days old)", originalCount-len(intel.PatternStatistics), intel.DataFreshness.PatternsTTL)
	}

	return cleaned
}

// archiveOldIntelligence moves old intelligence to archive directory.
func (intel *TargetIntelligence) archiveOldIntelligence(configDir string) error {
	if intel == nil {
		return nil
	}

	archiveDir := filepath.Join(configDir, ".intel", "archive")
	if err := os.MkdirAll(archiveDir, 0755); err != nil {
		return err
	}

	timestamp := time.Now().Format("2006-01-02")
	targetHash := fmt.Sprintf("%x", md5.Sum([]byte(intel.Target)))
	archiveFile := filepath.Join(archiveDir, fmt.Sprintf("%s_%s.json", targetHash, timestamp))

	data, err := json.MarshalIndent(intel, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(archiveFile, data, 0644)
}

// CleanupExpiredIntelligence wraps the internal cleanup for external callers.
func CleanupExpiredIntelligence(intel *TargetIntelligence) int {
	if intel == nil {
		return 0
	}
	return intel.cleanupExpiredIntelligence()
}

// ArchiveOldIntelligence wraps archive behavior for external callers.
func ArchiveOldIntelligence(intel *TargetIntelligence, configDir string) error {
	if intel == nil {
		return nil
	}
	return intel.archiveOldIntelligence(configDir)
}
