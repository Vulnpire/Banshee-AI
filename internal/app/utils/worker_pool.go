package utils

import (
	"context"
	"sync"
)

// =============================================================================
// WORKER POOL INFRASTRUCTURE
// =============================================================================

// WorkerJob represents a single job to be processed by a worker
type WorkerJob struct {
	Index int
	Data  interface{}
}

// WorkerResult represents the result of a worker job
type WorkerResult struct {
	Index  int
	Result interface{}
	Error  error
}

// processWithWorkerPool processes items in parallel using a worker pool
// items: slice of items to process
// workerCount: number of parallel workers
// processor: function to process each item (receives item, returns result and error)
// Returns: slice of results in the same order as input items
func processWithWorkerPool(ctx context.Context, items []interface{}, workerCount int, processor func(context.Context, interface{}) (interface{}, error)) ([]interface{}, []error) {
	if len(items) == 0 {
		return nil, nil
	}

	// Ensure at least 1 worker
	if workerCount < 1 {
		workerCount = 1
	}

	// Don't use more workers than items
	if workerCount > len(items) {
		workerCount = len(items)
	}

	jobs := make(chan WorkerJob, len(items))
	results := make(chan WorkerResult, len(items))

	// Start workers
	var wg sync.WaitGroup
	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				// Check context cancellation
				if ctx.Err() != nil {
					results <- WorkerResult{Index: job.Index, Error: ctx.Err()}
					continue
				}

				result, err := processor(ctx, job.Data)
				results <- WorkerResult{
					Index:  job.Index,
					Result: result,
					Error:  err,
				}
			}
		}()
	}

	// Send jobs
	go func() {
		for i, item := range items {
			jobs <- WorkerJob{Index: i, Data: item}
		}
		close(jobs)
	}()

	// Wait for workers to finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	resultSlice := make([]interface{}, len(items))
	errorSlice := make([]error, len(items))

	for result := range results {
		resultSlice[result.Index] = result.Result
		errorSlice[result.Index] = result.Error
	}

	return resultSlice, errorSlice
}

func ProcessWithWorkerPool(ctx context.Context, items []interface{}, workerCount int, processor func(context.Context, interface{}) (interface{}, error)) ([]interface{}, []error) {
	return processWithWorkerPool(ctx, items, workerCount, processor)
}

// processURLsWithWorkerPool is a specialized worker pool for URL processing
// urls: slice of URLs to process
// workerCount: number of parallel workers
// processor: function to process each URL (receives URL string, returns result string and error)
// Returns: slice of result strings
func processURLsWithWorkerPool(ctx context.Context, urls []string, workerCount int, processor func(context.Context, string) (string, error)) []string {
	if len(urls) == 0 {
		return nil
	}

	// Convert URLs to interface{} for generic worker pool
	items := make([]interface{}, len(urls))
	for i, url := range urls {
		items[i] = url
	}

	// Wrapper processor to handle type conversion
	wrapperProcessor := func(ctx context.Context, item interface{}) (interface{}, error) {
		url := item.(string)
		return processor(ctx, url)
	}

	results, errors := processWithWorkerPool(ctx, items, workerCount, wrapperProcessor)

	// Collect successful results
	var successfulResults []string
	for i, result := range results {
		if errors[i] == nil && result != nil {
			if str, ok := result.(string); ok && str != "" {
				successfulResults = append(successfulResults, str)
			}
		}
	}

	return successfulResults
}

// processBatchWithWorkerPool processes items in batches using a worker pool
// batches: slice of batches to process
// workerCount: number of parallel workers
// processor: function to process each batch (receives batch, returns error)
func processBatchWithWorkerPool(ctx context.Context, batches []interface{}, workerCount int, processor func(context.Context, interface{}) error) []error {
	if len(batches) == 0 {
		return nil
	}

	// Wrapper processor that returns nil as result
	wrapperProcessor := func(ctx context.Context, item interface{}) (interface{}, error) {
		err := processor(ctx, item)
		return nil, err
	}

	_, errors := processWithWorkerPool(ctx, batches, workerCount, wrapperProcessor)
	return errors
}
