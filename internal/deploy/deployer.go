package deploy

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/miyago/cf-mail-cert/internal/config"
)

// Reloader is the interface for triggering a mail server reload.
type Reloader interface {
	Reload(ctx context.Context) error
}

// Deployer writes certificate files and triggers a reload.
type Deployer struct {
	certPath string
	keyPath  string
	reloader Reloader
	logger   *slog.Logger
}

// NewDeployer creates a deployer based on the deploy configuration.
func NewDeployer(cfg *config.DeployConfig, logger *slog.Logger) (*Deployer, error) {
	var reloader Reloader

	switch cfg.Reload.Method {
	case "docker":
		reloader = NewDockerReloader(cfg.Reload.Docker.ContainerName, logger)
	case "hook":
		reloader = NewHookReloader(cfg.Reload.Hook.Command, logger)
	default:
		return nil, fmt.Errorf("unknown reload method: %s", cfg.Reload.Method)
	}

	return &Deployer{
		certPath: cfg.CertPath,
		keyPath:  cfg.KeyPath,
		reloader: reloader,
		logger:   logger,
	}, nil
}

// Deploy writes the certificate and key to configured paths, then triggers a reload.
func (d *Deployer) Deploy(certPEM, keyPEM []byte) error {
	if err := atomicWrite(d.certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("writing certificate: %w", err)
	}

	if err := atomicWrite(d.keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("writing private key: %w", err)
	}

	d.logger.Info("certificate files written",
		"cert", d.certPath,
		"key", d.keyPath,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := d.reloader.Reload(ctx); err != nil {
		return fmt.Errorf("reloading mail server: %w", err)
	}

	return nil
}

// atomicWrite writes data to a file atomically by writing to a temp file
// and renaming it to the target path.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating directory %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()

	defer func() {
		// Clean up temp file on error
		if err != nil {
			os.Remove(tmpPath)
		}
	}()

	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("writing temp file: %w", err)
	}

	if err = tmp.Chmod(perm); err != nil {
		tmp.Close()
		return fmt.Errorf("setting file permissions: %w", err)
	}

	if err = tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}

	if err = os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("renaming temp file to %s: %w", path, err)
	}

	return nil
}
