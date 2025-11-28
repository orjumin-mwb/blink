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
	"github.com/olegrjumin/blink/internal/service"
)

func main() {
	// Load configuration from environment variables
	cfg := config.Load()

	// Initialize logger
	logger := logging.New()

	// Initialize HTTP client for making URL checks
	httpClient := httpclient.NewClient()

	// Initialize checker with the HTTP client
	chk := checker.New(httpClient)

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

	// Create server address from config
	addr := fmt.Sprintf(":%d", cfg.Port)

	// Create a new HTTP server
	server := httpapi.NewServer(addr, logger, svc)

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

	logger.Info("Server stopped gracefully")
}
