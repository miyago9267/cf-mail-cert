package deploy

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
)

// HookReloader executes a shell command to reload the mail server.
type HookReloader struct {
	command string
	logger  *slog.Logger
}

func NewHookReloader(command string, logger *slog.Logger) *HookReloader {
	return &HookReloader{
		command: command,
		logger:  logger,
	}
}

func (r *HookReloader) Reload(ctx context.Context) error {
	r.logger.Info("executing reload hook", "command", r.command)

	cmd := exec.CommandContext(ctx, "sh", "-c", r.command)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("hook command failed: %w", err)
	}

	r.logger.Info("reload hook completed")
	return nil
}
