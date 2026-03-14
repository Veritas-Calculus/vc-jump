package dashboard

import (
	"context"
	"time"
)

// startCleanupScheduler starts background cleanup goroutines for maintenance tasks.
func (s *Server) startCleanupScheduler(auditRetentionDays int) {
	if s.store == nil {
		return
	}

	stopCh := make(chan struct{})
	s.cleanupStop = stopCh

	// Token cleanup: every 1 hour.
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				if err := s.store.DeleteExpiredTokens(ctx); err != nil {
					s.logger.Warnf("token cleanup failed: %v", err)
				}
				cancel()
			case <-stopCh:
				return
			}
		}
	}()

	// Audit log cleanup: every 24 hours (if retention configured).
	if auditRetentionDays > 0 {
		go func() {
			ticker := time.NewTicker(24 * time.Hour)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
					before := time.Now().AddDate(0, 0, -auditRetentionDays)
					count, err := s.store.CleanupAuditLogs(ctx, before)
					if err != nil {
						s.logger.Warnf("audit log cleanup failed: %v", err)
					} else if count > 0 {
						s.logger.Infof("cleaned up %d audit logs older than %d days", count, auditRetentionDays)
					}
					cancel()
				case <-stopCh:
					return
				}
			}
		}()
	}

	// Stale session cleanup: once on startup + every 6 hours.
	go func() {
		// Run once immediately on startup.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		count, err := s.store.CleanupStaleSessions(ctx)
		if err != nil {
			s.logger.Warnf("stale session cleanup failed on startup: %v", err)
		} else if count > 0 {
			s.logger.Infof("cleaned up %d stale sessions on startup", count)
		}
		cancel()

		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				count, err := s.store.CleanupStaleSessions(ctx)
				if err != nil {
					s.logger.Warnf("stale session cleanup failed: %v", err)
				} else if count > 0 {
					s.logger.Infof("cleaned up %d stale sessions", count)
				}
				cancel()
			case <-stopCh:
				return
			}
		}
	}()
}
