package pipeline

import (
	"github.com/Vulnpire/Banshee-AI/internal/app/ai"
	"github.com/Vulnpire/Banshee-AI/internal/app/analysis"
	"github.com/Vulnpire/Banshee-AI/internal/app/core"
)

// Aliases for AI package types used in the pipeline.
type CompanyTimeline = ai.CompanyTimeline
type DorkPrediction = ai.DorkPrediction
type InlineCodeAnalysisStats = analysis.InlineCodeAnalysisStats
type GoogleResponse = core.GoogleResponse
