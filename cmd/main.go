package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/miyago/cf-mail-cert/internal/cert"
	"github.com/miyago/cf-mail-cert/internal/config"
	"github.com/miyago/cf-mail-cert/internal/deploy"
	"github.com/miyago/cf-mail-cert/internal/dns"
	"github.com/miyago/cf-mail-cert/internal/scheduler"
)

const usage = `cf-mail-cert - Multi-zone Cloudflare ACME certificate manager for docker-mailserver

Usage:
  cf-mail-cert <command> [flags]

Commands:
  issue    Obtain a new certificate (force, even if one exists)
  renew    Check and renew certificate if needed
  serve    Run as daemon, periodically checking and renewing

Flags:
  -config string   Path to config file (default "/etc/cf-mail-cert/config.yaml")
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	cmd := os.Args[1]
	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		fmt.Print(usage)
		return
	}

	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	configPath := fs.String("config", "/etc/cf-mail-cert/config.yaml", "path to config file")
	fs.Parse(os.Args[2:])

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	provider, err := buildDNSProvider(cfg, logger)
	if err != nil {
		logger.Error("failed to initialize DNS provider", "error", err)
		os.Exit(1)
	}

	manager := cert.NewManager(cfg, provider, logger)

	deployer, err := deploy.NewDeployer(&cfg.Deploy, logger)
	if err != nil {
		logger.Error("failed to initialize deployer", "error", err)
		os.Exit(1)
	}

	switch cmd {
	case "issue":
		runIssue(manager, deployer, logger)
	case "renew":
		runRenew(manager, deployer, logger)
	case "serve":
		runServe(cfg, manager, deployer, logger)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}
}

func buildDNSProvider(cfg *config.Config, logger *slog.Logger) (*dns.MultiCloudflareProvider, error) {
	var accounts []dns.AccountConfig

	if cfg.Cloudflare.APIToken != "" {
		accounts = []dns.AccountConfig{
			{Name: "default", APIToken: cfg.Cloudflare.APIToken},
		}
	} else {
		for _, a := range cfg.Cloudflare.Accounts {
			accounts = append(accounts, dns.AccountConfig{
				Name:     a.Name,
				APIToken: a.APIToken,
			})
		}
	}

	return dns.NewMultiCloudflareProvider(accounts, logger)
}

func runIssue(manager *cert.Manager, deployer *deploy.Deployer, logger *slog.Logger) {
	logger.Info("issuing new certificate")

	resource, err := manager.ForceObtain()
	if err != nil {
		logger.Error("failed to obtain certificate", "error", err)
		os.Exit(1)
	}

	if err := deployer.Deploy(resource.Certificate, resource.PrivateKey); err != nil {
		logger.Error("failed to deploy certificate", "error", err)
		os.Exit(1)
	}

	logger.Info("certificate issued and deployed successfully")
}

func runRenew(manager *cert.Manager, deployer *deploy.Deployer, logger *slog.Logger) {
	logger.Info("checking certificate for renewal")

	resource, changed, err := manager.ObtainOrRenew()
	if err != nil {
		logger.Error("failed to obtain/renew certificate", "error", err)
		os.Exit(1)
	}

	if !changed {
		logger.Info("certificate is still valid, no renewal needed")
		return
	}

	if err := deployer.Deploy(resource.Certificate, resource.PrivateKey); err != nil {
		logger.Error("failed to deploy certificate", "error", err)
		os.Exit(1)
	}

	logger.Info("certificate renewed and deployed successfully")
}

func runServe(cfg *config.Config, manager *cert.Manager, deployer *deploy.Deployer, logger *slog.Logger) {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	s := scheduler.New(manager, deployer, cfg.Scheduler.CheckInterval, logger)

	logger.Info("starting cf-mail-cert daemon",
		"check_interval", cfg.Scheduler.CheckInterval,
		"renew_before_expiry", cfg.Scheduler.RenewBeforeExpiry,
		"domains", cfg.Domains,
	)

	if err := s.Run(ctx); err != nil && err != context.Canceled {
		logger.Error("scheduler error", "error", err)
		os.Exit(1)
	}

	logger.Info("cf-mail-cert daemon stopped")
}
