// Package main provides the entry point for vc-jump bastion host server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/auth"
	"github.com/Veritas-Calculus/vc-jump/internal/config"
	"github.com/Veritas-Calculus/vc-jump/internal/dashboard"
	"github.com/Veritas-Calculus/vc-jump/internal/server"
	"github.com/Veritas-Calculus/vc-jump/internal/storage"
)

// Build information set by ldflags.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	showVersion := flag.Bool("version", false, "show version information")
	flag.Parse()

	if *showVersion {
		fmt.Printf("vc-jump %s\n", version)
		fmt.Printf("  commit: %s\n", commit)
		fmt.Printf("  built:  %s\n", date)
		os.Exit(0)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// Initialize storage.
	var store *storage.SQLiteStore
	if cfg.Storage.Type == "sqlite" {
		store, err = storage.NewSQLiteStore(cfg.Storage)
		if err != nil {
			log.Fatalf("failed to create SQLite store: %v", err)
		}
		defer func() { _ = store.Close() }()
		log.Printf("using SQLite storage at %s", cfg.Storage.DBPath)

		// Cleanup stale sessions from previous runs (sessions that were not properly closed).
		ctx := context.Background()
		if cleaned, err := store.CleanupStaleSessions(ctx); err != nil {
			log.Printf("warning: failed to cleanup stale sessions: %v", err)
		} else if cleaned > 0 {
			log.Printf("cleaned up %d stale sessions from previous run", cleaned)
		}

		// Create default admin user if Dashboard is enabled and no users exist.
		if cfg.Dashboard.Enabled && cfg.Dashboard.Username != "" {
			users, _ := store.ListUsers(ctx)
			if len(users) == 0 {
				hashedPwd, err := auth.HashPassword(cfg.Dashboard.Password)
				if err != nil {
					log.Printf("warning: failed to hash admin password: %v", err)
				} else {
					adminUser := &storage.User{
						Username:     cfg.Dashboard.Username,
						PasswordHash: hashedPwd,
						Groups:       []string{"admin"},
						IsActive:     true,
					}
					if err := store.CreateUser(ctx, adminUser); err != nil {
						log.Printf("warning: failed to create admin user: %v", err)
					} else {
						log.Printf("created default admin user: %s", cfg.Dashboard.Username)
					}
				}
			}
		}
	}

	srv, err := server.New(cfg)
	if err != nil {
		if store != nil {
			_ = store.Close()
		}
		log.Fatalf("failed to create server: %v", err) //nolint:gocritic // store is explicitly closed above
	}

	// Set SQLite store for server if available.
	if store != nil {
		srv.SetSQLiteStore(store)
	}

	// Start dashboard if enabled.
	var dashboardServer *dashboard.Server
	if cfg.Dashboard.Enabled && store != nil {
		sessionTimeout := 24 * time.Hour
		if cfg.Dashboard.SessionTimeout != "" {
			if d, err := time.ParseDuration(cfg.Dashboard.SessionTimeout); err == nil {
				sessionTimeout = d
			}
		}

		dashboardCfg := dashboard.DashboardConfig{
			ListenAddr:     cfg.Dashboard.ListenAddr,
			SessionTimeout: sessionTimeout,
			EnableHTTPS:    cfg.Dashboard.EnableHTTPS,
			CertFile:       cfg.Dashboard.CertFile,
			KeyFile:        cfg.Dashboard.KeyFile,
		}

		dashboardServer, err = dashboard.NewWithRecording(dashboardCfg, store, cfg.Auth, cfg.Recording)
		if err != nil {
			log.Printf("failed to create dashboard: %v", err)
		} else {
			go func() {
				log.Printf("starting dashboard on %s", cfg.Dashboard.ListenAddr)
				if err := dashboardServer.Start(); err != nil {
					log.Printf("dashboard error: %v", err)
				}
			}()
		}
	}

	// Handle graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("shutting down server...")

		// Shutdown dashboard.
		if dashboardServer != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := dashboardServer.Stop(ctx); err != nil {
				log.Printf("error stopping dashboard: %v", err)
			}
		}

		if err := srv.Stop(); err != nil {
			log.Printf("error stopping server: %v", err)
		}
	}()

	log.Printf("starting vc-jump server on %s", cfg.Server.ListenAddr)
	if err := srv.Start(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
