package screenshot

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
)

// BrowserInstance represents a single browser instance in the pool
type BrowserInstance struct {
	ctx        context.Context
	cancel     context.CancelFunc
	inUse      bool
	healthy    bool
	lastUsed   time.Time
	errorCount int
}

// BrowserPool manages a pool of pre-warmed browser instances for speed
type BrowserPool struct {
	instances []*BrowserInstance
	mu        sync.Mutex
	size      int
	opts      []chromedp.ExecAllocatorOption
}

// NewBrowserPool creates a new browser pool with pre-warmed instances
func NewBrowserPool(size int) (*BrowserPool, error) {
	if size <= 0 {
		size = 10 // Default to 10 for speed
	}

	// Speed-optimized Chrome flags
	opts := []chromedp.ExecAllocatorOption{
		chromedp.NoDefaultBrowserCheck,
		chromedp.NoFirstRun,
		chromedp.Headless,
		chromedp.DisableGPU,
		chromedp.NoSandbox,
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-web-security", true),
		chromedp.Flag("disable-features", "VizDisplayCompositor,TranslateUI"),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-background-timer-throttling", true),
		chromedp.Flag("disable-renderer-backgrounding", true),
		chromedp.Flag("disable-backgrounding-occluded-windows", true),
		chromedp.Flag("disable-ipc-flooding-protection", true),
		chromedp.Flag("disable-hang-monitor", true),
		chromedp.Flag("hide-scrollbars", true),
		chromedp.Flag("mute-audio", true),
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("disable-plugins", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("disable-breakpad", true),
		chromedp.Flag("disable-cloud-import", true),
		chromedp.Flag("disable-gesture-typing", true),
		chromedp.Flag("metrics-recording-only", true),
		chromedp.Flag("no-default-browser-check", true),
		chromedp.Flag("no-pings", true),
		chromedp.Flag("password-store", "basic"),
		chromedp.Flag("use-mock-keychain", true),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("allow-insecure-localhost", true),
		// Performance flags
		chromedp.Flag("enable-features", "NetworkService,NetworkServiceInProcess"),
		chromedp.Flag("force-color-profile", "srgb"),
		chromedp.Flag("disable-domain-reliability", true),
		chromedp.Flag("disable-component-update", true),
		chromedp.Flag("disable-features", "CalculateNativeWinOcclusion,BackForwardCache"),
		// Set window size for consistency
		chromedp.WindowSize(1280, 720),
	}

	pool := &BrowserPool{
		instances: make([]*BrowserInstance, 0, size),
		size:      size,
		opts:      opts,
	}

	// Pre-warm browser instances
	for i := 0; i < size; i++ {
		instance, err := pool.createInstance()
		if err != nil {
			// Clean up any created instances on failure
			pool.Close()
			return nil, fmt.Errorf("failed to create browser instance %d: %w", i, err)
		}
		pool.instances = append(pool.instances, instance)
	}

	return pool, nil
}

// createInstance creates a new browser instance
func (p *BrowserPool) createInstance() (*BrowserInstance, error) {
	// Create allocator context
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), p.opts...)

	// Create browser context
	ctx, cancel := chromedp.NewContext(allocCtx)

	// Start browser (pre-warm)
	if err := chromedp.Run(ctx); err != nil {
		cancel()
		allocCancel()
		return nil, err
	}

	return &BrowserInstance{
		ctx: ctx,
		cancel: func() {
			cancel()
			allocCancel()
		},
		inUse:      false,
		healthy:    true,
		lastUsed:   time.Now(),
		errorCount: 0,
	}, nil
}

// Acquire gets an available browser instance from the pool
func (p *BrowserPool) Acquire(ctx context.Context) (*BrowserInstance, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Find first available and healthy instance
	for _, instance := range p.instances {
		if !instance.inUse && instance.healthy {
			instance.inUse = true
			instance.lastUsed = time.Now()
			return instance, nil
		}
	}

	// Try to recycle an unhealthy instance
	for i, instance := range p.instances {
		if !instance.inUse && !instance.healthy {
			// Close the unhealthy instance
			if instance.cancel != nil {
				instance.cancel()
			}

			// Create a new instance
			newInstance, err := p.createInstance()
			if err != nil {
				continue // Try next unhealthy instance
			}

			// Replace the unhealthy instance
			p.instances[i] = newInstance
			newInstance.inUse = true
			newInstance.lastUsed = time.Now()
			return newInstance, nil
		}
	}

	// No available instance (fail fast for speed)
	return nil, ErrBrowserUnavailable
}

// Release returns a browser instance to the pool
func (p *BrowserPool) Release(instance *BrowserInstance) {
	if instance == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	instance.inUse = false
	instance.lastUsed = time.Now()

	// Optional: Clear browser state for next use
	// This is skipped for maximum speed, but can be enabled if needed
	// chromedp.Run(instance.ctx, chromedp.Navigate("about:blank"))
}

// MarkUnhealthy marks a browser instance as unhealthy due to an error
func (p *BrowserPool) MarkUnhealthy(instance *BrowserInstance) {
	if instance == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	instance.errorCount++
	// Mark as unhealthy after 3 errors
	if instance.errorCount >= 3 {
		instance.healthy = false
	}
}

// Close shuts down all browser instances in the pool
func (p *BrowserPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, instance := range p.instances {
		if instance.cancel != nil {
			instance.cancel()
		}
	}

	p.instances = nil
	return nil
}

// Health checks the health of the pool
func (p *BrowserPool) Health() (available, total int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	total = len(p.instances)
	for _, instance := range p.instances {
		if !instance.inUse {
			available++
		}
	}
	return
}

// Size returns the size of the browser pool
func (p *BrowserPool) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.instances)
}

// Context returns the context for a browser instance
func (b *BrowserInstance) Context() context.Context {
	return b.ctx
}