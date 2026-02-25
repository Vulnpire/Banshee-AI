package pipeline

import (
	"banshee/internal/app/ai"
	"banshee/internal/app/analysis"
	"banshee/internal/app/core"
)

// Aliases for AI package types used in the pipeline.
type CompanyTimeline = ai.CompanyTimeline
type DorkPrediction = ai.DorkPrediction
type InlineCodeAnalysisStats = analysis.InlineCodeAnalysisStats
type GoogleResponse = core.GoogleResponse
