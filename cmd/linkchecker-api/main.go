package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/olegrjumin/blink/internal/checker"
	"github.com/olegrjumin/blink/internal/config"
	"github.com/olegrjumin/blink/internal/httpapi"
	"github.com/olegrjumin/blink/internal/httpclient"
	"github.com/olegrjumin/blink/internal/logging"
	"github.com/olegrjumin/blink/internal/mwbapi"
	"github.com/olegrjumin/blink/internal/screenshot"
	"github.com/olegrjumin/blink/internal/service"
)

func main() {
	// Load configuration from environment variables
	cfg := config.Load()

	// Initialize logger
	logger := logging.New()

	// Initialize HTTP client for making URL checks
	httpClient := httpclient.NewClient()

	// Initialize MWB API client
	mwbClient := mwbapi.New()

	// Initialize checker with the HTTP client and MWB API client
	chk := checker.New(httpClient, mwbClient)

	// Create service options from config
	opts := checker.CheckOptions{
		Timeout:         cfg.RequestTimeout,
		FollowRedirects: true,
		MaxRedirects:    cfg.MaxRedirects,
		Method:          cfg.DefaultMethod,
		UserAgent:       cfg.DefaultUserAgent,
	}

	// Initialize service with checker, logger, and options
	svc := service.New(chk, logger, opts)

	// Initialize screenshot service with queue
	var queuedScreenshotter *screenshot.QueuedScreenshotter
	var cleanupService *screenshot.CleanupService

	qs, err := screenshot.NewQueuedScreenshotter(cfg.BrowserPoolSize, cfg.ScreenshotQueueSize, cfg.ScreenshotDir)
	if err != nil {
		logger.Error("Failed to initialize screenshot service", "error", err)
		// Continue without screenshot service - it's optional
	} else {
		queuedScreenshotter = qs

		// Start cleanup service
		cleanupService = screenshot.NewCleanupService(cfg.ScreenshotDir, cfg.ScreenshotMaxAge, cfg.CleanupInterval)
		cleanupService.Start()
		logger.Info("Screenshot cleanup service started", "maxAge", cfg.ScreenshotMaxAge, "interval", cfg.CleanupInterval)
	}

	// Create server address from config
	addr := fmt.Sprintf(":%d", cfg.Port)

	// Create a new HTTP server (pass queued screenshotter if available)
	var screenshotService interface{}
	if queuedScreenshotter != nil {
		screenshotService = queuedScreenshotter
	}
	server := httpapi.NewServer(addr, logger, svc, screenshotService)

	// Channel to listen for OS signals (Ctrl+C, kill, etc.)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Start the server in a goroutine so it doesn't block
	go func() {
		logger.Info("Starting server", "port", cfg.Port)
		if err := server.ListenAndServe(); err != nil {
			logger.Error("Server error", "error", err)
		}
	}()

	// Wait for interrupt signal
	<-quit
	logger.Info("Shutting down server...")

	// Create a context with timeout for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := server.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown", "error", err)
		os.Exit(1)
	}

	// Cleanup screenshot service
	if cleanupService != nil {
		cleanupService.Stop()
		logger.Info("Screenshot cleanup service stopped")
	}
	if queuedScreenshotter != nil {
		if err := queuedScreenshotter.Close(); err != nil {
			logger.Error("Failed to close screenshot service", "error", err)
		}
	}

	logger.Info("Server stopped gracefully")
}
