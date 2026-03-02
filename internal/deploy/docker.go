package deploy

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

// DockerReloader restarts a Docker container to reload certificates.
type DockerReloader struct {
	containerName string
	logger        *slog.Logger
}

func NewDockerReloader(containerName string, logger *slog.Logger) *DockerReloader {
	return &DockerReloader{
		containerName: containerName,
		logger:        logger,
	}
}

func (r *DockerReloader) Reload(ctx context.Context) error {
	r.logger.Info("restarting Docker container", "container", r.containerName)

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("creating Docker client: %w", err)
	}
	defer cli.Close()

	timeout := 30
	if err := cli.ContainerRestart(ctx, r.containerName, container.StopOptions{Timeout: &timeout}); err != nil {
		return fmt.Errorf("restarting container %s: %w", r.containerName, err)
	}

	r.logger.Info("Docker container restarted", "container", r.containerName)
	return nil
}
