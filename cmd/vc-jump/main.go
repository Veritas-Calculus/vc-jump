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
	"github.com/Veritas-Calculus/vc-jump/internal/recording"
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
		printVersion()
		os.Exit(0)
	}

	// Check for CLI subcommands (user, host, apikey, migrate).
	if handleCLI(flag.Args(), *configPath) {
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// Initialize storage.
	store := initStorage(cfg)
	if store != nil {
		defer func() { _ = store.Close() }()
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
	dashboardServer := startDashboard(cfg, store, srv)

	// Handle graceful shutdown.
	setupGracefulShutdown(srv, dashboardServer)

	// Handle config hot reload on SIGHUP.
	setupConfigReload(*configPath, srv, cfg)

	log.Printf("starting vc-jump server on %s", cfg.Server.ListenAddr)
	if err := srv.Start(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func printVersion() {
	fmt.Printf("vc-jump %s\n", version)
	fmt.Printf("  commit: %s\n", commit)
	fmt.Printf("  built:  %s\n", date)
}

func initStorage(cfg *config.Config) *storage.SQLiteStore {
	if cfg.Storage.Type != "sqlite" {
		return nil
	}

	store, err := storage.NewSQLiteStore(cfg.Storage)
	if err != nil {
		log.Fatalf("failed to create SQLite store: %v", err)
	}
	log.Printf("using SQLite storage at %s", cfg.Storage.DBPath)

	ctx := context.Background()
	cleanupStaleSessions(ctx, store)
	createDefaultAdminUser(ctx, cfg, store)

	return store
}

func cleanupStaleSessions(ctx context.Context, store *storage.SQLiteStore) {
	if cleaned, err := store.CleanupStaleSessions(ctx); err != nil {
		log.Printf("warning: failed to cleanup stale sessions: %v", err)
	} else if cleaned > 0 {
		log.Printf("cleaned up %d stale sessions from previous run", cleaned)
	}
}

func createDefaultAdminUser(ctx context.Context, cfg *config.Config, store *storage.SQLiteStore) {
	if !cfg.Dashboard.Enabled || cfg.Dashboard.Username == "" {
		return
	}

	users, _ := store.ListUsers(ctx)
	if len(users) > 0 {
		// Check if admin user already has admin role assigned.
		assignAdminRoleIfNeeded(ctx, store, cfg.Dashboard.Username)
		return
	}

	hashedPwd, err := auth.HashPassword(cfg.Dashboard.Password)
	if err != nil {
		log.Printf("warning: failed to hash admin password: %v", err)
		return
	}

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
		// Assign admin role to the new user.
		assignAdminRoleIfNeeded(ctx, store, cfg.Dashboard.Username)
	}
}

// assignAdminRoleIfNeeded assigns the admin role to a user if not already assigned.
func assignAdminRoleIfNeeded(ctx context.Context, store *storage.SQLiteStore, username string) {
	// Get user by username.
	user, err := store.GetUserByUsername(ctx, username)
	if err != nil {
		return
	}

	// Get admin role.
	adminRole, err := store.GetRoleByName(ctx, "admin")
	if err != nil {
		return
	}

	// Check if user already has admin role.
	userRoles, _ := store.GetUserRoles(ctx, user.ID)
	for _, r := range userRoles {
		if r.Name == "admin" {
			return // Already has admin role.
		}
	}

	// Assign admin role.
	if err := store.AssignRole(ctx, user.ID, adminRole.ID); err != nil {
		log.Printf("warning: failed to assign admin role to %s: %v", username, err)
	} else {
		log.Printf("assigned admin role to user: %s", username)
	}
}

func startDashboard(cfg *config.Config, store *storage.SQLiteStore, srv *server.Server) *dashboard.Server {
	if !cfg.Dashboard.Enabled || store == nil {
		return nil
	}

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

	var recorderAdapter dashboard.RecorderInterface
	if recorder := srv.GetRecorder(); recorder != nil {
		recorderAdapter = &recorderAdapterImpl{recorder: recorder}
	}

	dashboardServer, err := dashboard.NewWithRecorder(dashboardCfg, store, cfg.Auth, cfg.Recording, recorderAdapter)
	if err != nil {
		log.Printf("failed to create dashboard: %v", err)
		return nil
	}

	go func() {
		log.Printf("starting dashboard on %s", cfg.Dashboard.ListenAddr)
		if err := dashboardServer.Start(); err != nil {
			log.Printf("dashboard error: %v", err)
		}
	}()

	return dashboardServer
}

func setupGracefulShutdown(srv *server.Server, dashboardServer *dashboard.Server) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Printf("received %s, initiating graceful shutdown...", sig)

		// Phase 1: Stop accepting new HTTP requests.
		if dashboardServer != nil {
			log.Println("  → stopping dashboard HTTP server...")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := dashboardServer.Stop(ctx); err != nil {
				log.Printf("  ✗ error stopping dashboard: %v", err)
			} else {
				log.Println("  ✓ dashboard stopped")
			}
			cancel()
		}

		// Phase 2: Stop SSH server (waits for active sessions up to 30s).
		log.Println("  → stopping SSH server (waiting for active sessions)...")
		if err := srv.Stop(); err != nil {
			log.Printf("  ✗ error stopping SSH server: %v", err)
		} else {
			log.Println("  ✓ SSH server stopped")
		}

		log.Println("shutdown complete")
		os.Exit(0)
	}()

	// Second signal = force exit.
	go func() {
		sigCh2 := make(chan os.Signal, 1)
		signal.Notify(sigCh2, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh2 // first signal handled above
		<-sigCh2 // second signal = force
		log.Println("forced shutdown (second signal received)")
		os.Exit(1)
	}()
}

func setupConfigReload(configPath string, srv *server.Server, currentCfg *config.Config) {
	sigHup := make(chan os.Signal, 1)
	signal.Notify(sigHup, syscall.SIGHUP)

	go func() {
		for range sigHup {
			log.Println("SIGHUP received, reloading configuration...")

			newCfg, err := config.Load(configPath)
			if err != nil {
				log.Printf("  ✗ config reload failed: %v (keeping current config)", err)
				continue
			}

			// Validate that non-reloadable fields haven't changed.
			if newCfg.Server.ListenAddr != currentCfg.Server.ListenAddr {
				log.Println("  ⚠ server.listen_addr changed — requires restart")
			}
			if newCfg.Storage.DBPath != currentCfg.Storage.DBPath {
				log.Println("  ⚠ storage.db_path changed — requires restart")
			}

			// Reload hosts into SSH server.
			srv.ReloadHosts(newCfg.Hosts)
			log.Printf("  ✓ reloaded %d hosts", len(newCfg.Hosts))

			// Update session config.
			if newCfg.Session.IdleTimeout != currentCfg.Session.IdleTimeout {
				log.Printf("  ✓ session idle timeout: %v → %v",
					currentCfg.Session.IdleTimeout, newCfg.Session.IdleTimeout)
			}
			if newCfg.Session.MaxDuration != currentCfg.Session.MaxDuration {
				log.Printf("  ✓ session max duration: %v → %v",
					currentCfg.Session.MaxDuration, newCfg.Session.MaxDuration)
			}

			// Update current config reference (safe fields only).
			currentCfg.Hosts = newCfg.Hosts
			currentCfg.Session = newCfg.Session
			currentCfg.Logging = newCfg.Logging

			log.Println("  ✓ configuration reloaded successfully")
		}
	}()
}

// recorderAdapterImpl adapts recording.Recorder to dashboard.RecorderInterface.
type recorderAdapterImpl struct {
	recorder *recording.Recorder
}

func (a *recorderAdapterImpl) ListActiveSessions() []dashboard.ActiveSessionInfo {
	sessions := a.recorder.ListActiveSessions()
	result := make([]dashboard.ActiveSessionInfo, len(sessions))
	for i, s := range sessions {
		result[i] = dashboard.ActiveSessionInfo{
			ID:        s.ID,
			Username:  s.Username,
			HostName:  s.HostName,
			StartTime: s.StartTime,
		}
	}
	return result
}

func (a *recorderAdapterImpl) GetSession(id string) (dashboard.SessionInterface, bool) {
	session, ok := a.recorder.GetSession(id)
	if !ok {
		return nil, false
	}
	return session, true
}
