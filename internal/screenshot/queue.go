package screenshot

import (
	"context"
	"errors"
	"sync"
)

var (
	ErrQueueFull    = errors.New("screenshot queue is full")
	ErrQueueTimeout = errors.New("queue wait timeout")
)

// QueuedScreenshotter wraps Screenshotter with a request queue
type QueuedScreenshotter struct {
	*Screenshotter
	queue     chan *queueRequest
	waitGroup sync.WaitGroup
}

type queueRequest struct {
	ctx    context.Context
	opts   *Options
	result chan *captureResult
}

type captureResult struct {
	result *Result
	err    error
}

// NewQueuedScreenshotter creates a screenshotter with request queuing
func NewQueuedScreenshotter(poolSize int, queueSize int, storageDir string) (*QueuedScreenshotter, error) {
	base, err := New(poolSize, storageDir)
	if err != nil {
		return nil, err
	}

	qs := &QueuedScreenshotter{
		Screenshotter: base,
		queue:        make(chan *queueRequest, queueSize),
	}

	// Start worker goroutines (one per browser in pool)
	for i := 0; i < poolSize; i++ {
		qs.waitGroup.Add(1)
		go qs.worker()
	}

	return qs, nil
}

// CaptureQueued adds the request to queue and waits for result
func (qs *QueuedScreenshotter) CaptureQueued(ctx context.Context, opts *Options) (*Result, error) {
	req := &queueRequest{
		ctx:    ctx,
		opts:   opts,
		result: make(chan *captureResult, 1),
	}

	// Try to add to queue
	select {
	case qs.queue <- req:
		// Successfully queued
	case <-ctx.Done():
		return &Result{
			Success: false,
			URL:     opts.URL,
			Error:   "request cancelled",
		}, ctx.Err()
	default:
		// Queue is full
		return &Result{
			Success: false,
			URL:     opts.URL,
			Error:   ErrQueueFull.Error(),
		}, ErrQueueFull
	}

	// Wait for result
	select {
	case res := <-req.result:
		return res.result, res.err
	case <-ctx.Done():
		return &Result{
			Success: false,
			URL:     opts.URL,
			Error:   "request timeout while queued",
		}, ErrQueueTimeout
	}
}

// worker processes requests from the queue
func (qs *QueuedScreenshotter) worker() {
	defer qs.waitGroup.Done()

	for req := range qs.queue {
		// Check if request is still valid
		select {
		case <-req.ctx.Done():
			// Request was cancelled while in queue
			req.result <- &captureResult{
				result: &Result{
					Success: false,
					URL:     req.opts.URL,
					Error:   "cancelled while queued",
				},
				err: req.ctx.Err(),
			}
			continue
		default:
		}

		// Process the screenshot
		result, err := qs.Capture(req.ctx, req.opts)
		req.result <- &captureResult{
			result: result,
			err:    err,
		}
	}
}

// Close shuts down the queued screenshotter
func (qs *QueuedScreenshotter) Close() error {
	// Close the queue
	close(qs.queue)

	// Wait for workers to finish
	qs.waitGroup.Wait()

	// Close the underlying screenshotter
	return qs.Screenshotter.Close()
}

// QueueStats returns current queue statistics
func (qs *QueuedScreenshotter) QueueStats() (queued, capacity int) {
	return len(qs.queue), cap(qs.queue)
}