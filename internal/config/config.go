package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ACME       ACMEConfig       `yaml:"acme"`
	Cloudflare CloudflareConfig `yaml:"cloudflare"`
	Domains    []string         `yaml:"domains"`
	Deploy     DeployConfig     `yaml:"deploy"`
	Scheduler  SchedulerConfig  `yaml:"scheduler"`
}

type ACMEConfig struct {
	Email   string `yaml:"email"`
	CAUrl   string `yaml:"ca_url"`
	Storage string `yaml:"storage"`
}

type CloudflareConfig struct {
	APIToken string              `yaml:"api_token"`
	Accounts []CloudflareAccount `yaml:"accounts"`
}

type CloudflareAccount struct {
	Name     string `yaml:"name"`
	APIToken string `yaml:"api_token"`
}

type DeployConfig struct {
	CertPath string       `yaml:"cert_path"`
	KeyPath  string       `yaml:"key_path"`
	Reload   ReloadConfig `yaml:"reload"`
}

type ReloadConfig struct {
	Method string       `yaml:"method"`
	Docker DockerConfig `yaml:"docker"`
	Hook   HookConfig   `yaml:"hook"`
}

type DockerConfig struct {
	ContainerName string `yaml:"container_name"`
}

type HookConfig struct {
	Command string `yaml:"command"`
}

type SchedulerConfig struct {
	CheckInterval    time.Duration `yaml:"-"`
	RenewBeforeExpiry time.Duration `yaml:"-"`
	RawCheckInterval    string `yaml:"check_interval"`
	RawRenewBeforeExpiry string `yaml:"renew_before_expiry"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	cfg.applyDefaults()
	cfg.applyEnvOverrides()

	if err := cfg.parseDurations(); err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.ACME.CAUrl == "" {
		c.ACME.CAUrl = "https://acme-v02.api.letsencrypt.org/directory"
	}
	if c.ACME.Storage == "" {
		c.ACME.Storage = "/data/certs"
	}
	if c.Scheduler.RawCheckInterval == "" {
		c.Scheduler.RawCheckInterval = "24h"
	}
	if c.Scheduler.RawRenewBeforeExpiry == "" {
		c.Scheduler.RawRenewBeforeExpiry = "720h"
	}
}

func (c *Config) applyEnvOverrides() {
	if v := os.Getenv("CF_API_TOKEN"); v != "" && c.Cloudflare.APIToken == "" {
		c.Cloudflare.APIToken = v
	}

	for i := range c.Cloudflare.Accounts {
		envKey := "CF_ACCOUNT_" + strings.ToUpper(strings.ReplaceAll(c.Cloudflare.Accounts[i].Name, "-", "_")) + "_TOKEN"
		if v := os.Getenv(envKey); v != "" {
			c.Cloudflare.Accounts[i].APIToken = v
		}
	}
}

func (c *Config) parseDurations() error {
	var err error
	c.Scheduler.CheckInterval, err = time.ParseDuration(c.Scheduler.RawCheckInterval)
	if err != nil {
		return fmt.Errorf("parsing check_interval %q: %w", c.Scheduler.RawCheckInterval, err)
	}
	c.Scheduler.RenewBeforeExpiry, err = time.ParseDuration(c.Scheduler.RawRenewBeforeExpiry)
	if err != nil {
		return fmt.Errorf("parsing renew_before_expiry %q: %w", c.Scheduler.RawRenewBeforeExpiry, err)
	}
	return nil
}

func (c *Config) Validate() error {
	if c.ACME.Email == "" {
		return fmt.Errorf("acme.email is required")
	}

	hasToken := c.Cloudflare.APIToken != ""
	hasAccounts := len(c.Cloudflare.Accounts) > 0
	if !hasToken && !hasAccounts {
		return fmt.Errorf("cloudflare: either api_token or accounts must be configured")
	}
	if hasToken && hasAccounts {
		return fmt.Errorf("cloudflare: api_token and accounts are mutually exclusive")
	}
	if hasAccounts {
		for i, a := range c.Cloudflare.Accounts {
			if a.Name == "" {
				return fmt.Errorf("cloudflare.accounts[%d].name is required", i)
			}
			if a.APIToken == "" {
				return fmt.Errorf("cloudflare.accounts[%d].api_token is required (or set CF_ACCOUNT_%s_TOKEN)", i, strings.ToUpper(strings.ReplaceAll(a.Name, "-", "_")))
			}
		}
	}

	if len(c.Domains) == 0 {
		return fmt.Errorf("at least one domain is required")
	}

	if c.Deploy.CertPath == "" {
		return fmt.Errorf("deploy.cert_path is required")
	}
	if c.Deploy.KeyPath == "" {
		return fmt.Errorf("deploy.key_path is required")
	}

	switch c.Deploy.Reload.Method {
	case "docker":
		if c.Deploy.Reload.Docker.ContainerName == "" {
			return fmt.Errorf("deploy.reload.docker.container_name is required when method=docker")
		}
	case "hook":
		if c.Deploy.Reload.Hook.Command == "" {
			return fmt.Errorf("deploy.reload.hook.command is required when method=hook")
		}
	default:
		return fmt.Errorf("deploy.reload.method must be 'docker' or 'hook', got %q", c.Deploy.Reload.Method)
	}

	return nil
}
