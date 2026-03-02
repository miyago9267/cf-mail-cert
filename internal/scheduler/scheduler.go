package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/miyago/cf-mail-cert/internal/cert"
	"github.com/miyago/cf-mail-cert/internal/deploy"
)

// Scheduler periodically checks certificate status and renews as needed.
type Scheduler struct {
	manager  *cert.Manager
	deployer *deploy.Deployer
	interval time.Duration
	logger   *slog.Logger
}

func New(manager *cert.Manager, deployer *deploy.Deployer, interval time.Duration, logger *slog.Logger) *Scheduler {
	return &Scheduler{
		manager:  manager,
		deployer: deployer,
		interval: interval,
		logger:   logger,
	}
}

// Run starts the scheduler loop. It runs an immediate check on start,
// then periodically thereafter. Blocks until ctx is cancelled.
func (s *Scheduler) Run(ctx context.Context) error {
	s.logger.Info("scheduler started", "interval", s.interval)

	// Run immediately on start
	if err := s.RunOnce(ctx); err != nil {
		s.logger.Error("initial certificate check failed", "error", err)
	}

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("scheduler stopped")
			return ctx.Err()
		case <-ticker.C:
			if err := s.RunOnce(ctx); err != nil {
				s.logger.Error("certificate renewal check failed", "error", err)
			}
		}
	}
}

// RunOnce performs a single check-and-renew cycle.
func (s *Scheduler) RunOnce(ctx context.Context) error {
	s.logger.Info("checking certificate status")

	resource, changed, err := s.manager.ObtainOrRenew()
	if err != nil {
		return fmt.Errorf("obtain/renew: %w", err)
	}

	if !changed {
		s.logger.Info("certificate is valid, no action needed")
		return nil
	}

	s.logger.Info("certificate updated, deploying")

	if err := s.deployer.Deploy(resource.Certificate, resource.PrivateKey); err != nil {
		return fmt.Errorf("deploy: %w", err)
	}

	s.logger.Info("certificate deployed and service reloaded")
	return nil
}
