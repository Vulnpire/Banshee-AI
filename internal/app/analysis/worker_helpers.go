package analysis

import (
	"context"

	"github.com/Vulnpire/Banshee-AI/internal/app/utils"
)

func processWithWorkerPool(ctx context.Context, items []interface{}, workerCount int, processor func(context.Context, interface{}) (interface{}, error)) ([]interface{}, []error) {
	return utils.ProcessWithWorkerPool(ctx, items, workerCount, processor)
}
