package dns

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	cf "github.com/cloudflare/cloudflare-go"
	"github.com/go-acme/lego/v4/challenge/dns01"
)

// AccountConfig holds credentials for a single Cloudflare account.
type AccountConfig struct {
	Name     string
	APIToken string
}

type accountClient struct {
	name    string
	api     *cf.API
	zoneMap map[string]string // zone apex (e.g. "example.com") -> zone ID
}

// MultiCloudflareProvider implements lego's challenge.Provider interface,
// routing DNS-01 challenges to the correct Cloudflare account/zone.
type MultiCloudflareProvider struct {
	clients   []*accountClient
	domainMap map[string]*accountClient // zone apex -> account client
	recordIDs map[string]string         // FQDN -> DNS record ID (for cleanup)
	mu        sync.Mutex
	logger    *slog.Logger
}

// NewMultiCloudflareProvider creates a provider that can manage DNS records
// across multiple Cloudflare accounts. It queries each token's zones upfront
// to build a domain-to-account routing table.
func NewMultiCloudflareProvider(accounts []AccountConfig, logger *slog.Logger) (*MultiCloudflareProvider, error) {
	if len(accounts) == 0 {
		return nil, fmt.Errorf("at least one Cloudflare account is required")
	}

	p := &MultiCloudflareProvider{
		domainMap: make(map[string]*accountClient),
		recordIDs: make(map[string]string),
		logger:    logger,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, acct := range accounts {
		api, err := cf.NewWithAPIToken(acct.APIToken)
		if err != nil {
			return nil, fmt.Errorf("creating Cloudflare client for account %q: %w", acct.Name, err)
		}

		zones, err := api.ListZones(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing zones for account %q: %w", acct.Name, err)
		}

		client := &accountClient{
			name:    acct.Name,
			api:     api,
			zoneMap: make(map[string]string),
		}

		for _, z := range zones {
			client.zoneMap[z.Name] = z.ID
			if existing, ok := p.domainMap[z.Name]; ok {
				logger.Warn("zone found in multiple accounts, using first",
					"zone", z.Name,
					"using", existing.name,
					"duplicate", acct.Name,
				)
				continue
			}
			p.domainMap[z.Name] = client
		}

		logger.Info("loaded Cloudflare account",
			"account", acct.Name,
			"zones", len(client.zoneMap),
		)

		p.clients = append(p.clients, client)
	}

	if len(p.domainMap) == 0 {
		return nil, fmt.Errorf("no zones found across all Cloudflare accounts")
	}

	return p, nil
}

// Present creates the DNS TXT record for the ACME challenge.
func (p *MultiCloudflareProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	client, zoneID, err := p.findAccountForDomain(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("finding Cloudflare account for %s: %w", domain, err)
	}

	p.logger.Info("creating DNS challenge record",
		"domain", domain,
		"fqdn", info.EffectiveFQDN,
		"account", client.name,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	record, err := client.api.CreateDNSRecord(ctx, cf.ZoneIdentifier(zoneID), cf.CreateDNSRecordParams{
		Type:    "TXT",
		Name:    dns01.UnFqdn(info.EffectiveFQDN),
		Content: info.Value,
		TTL:     120,
	})
	if err != nil {
		return fmt.Errorf("creating TXT record for %s: %w", domain, err)
	}

	p.mu.Lock()
	p.recordIDs[info.EffectiveFQDN] = record.ID
	p.mu.Unlock()

	return nil
}

// CleanUp removes the DNS TXT record created for the ACME challenge.
func (p *MultiCloudflareProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	p.mu.Lock()
	recordID, ok := p.recordIDs[info.EffectiveFQDN]
	if ok {
		delete(p.recordIDs, info.EffectiveFQDN)
	}
	p.mu.Unlock()

	if !ok {
		return fmt.Errorf("no record ID found for %s, cannot clean up", info.EffectiveFQDN)
	}

	client, zoneID, err := p.findAccountForDomain(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("finding Cloudflare account for cleanup of %s: %w", domain, err)
	}

	p.logger.Info("cleaning up DNS challenge record",
		"domain", domain,
		"fqdn", info.EffectiveFQDN,
		"account", client.name,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return client.api.DeleteDNSRecord(ctx, cf.ZoneIdentifier(zoneID), recordID)
}

// Timeout returns the timeout and polling interval for DNS propagation checks.
func (p *MultiCloudflareProvider) Timeout() (timeout, interval time.Duration) {
	return 5 * time.Minute, 10 * time.Second
}

// findAccountForDomain walks up the domain hierarchy to find the Cloudflare
// account that manages the zone containing the given FQDN.
func (p *MultiCloudflareProvider) findAccountForDomain(fqdn string) (*accountClient, string, error) {
	// Strip trailing dot
	name := dns01.UnFqdn(fqdn)

	// Walk up: _acme-challenge.mail.example.com -> mail.example.com -> example.com
	for {
		if client, ok := p.domainMap[name]; ok {
			zoneID := client.zoneMap[name]
			return client, zoneID, nil
		}

		idx := strings.IndexByte(name, '.')
		if idx == -1 {
			break
		}
		name = name[idx+1:]
	}

	return nil, "", fmt.Errorf("no Cloudflare zone found for %s in any configured account", fqdn)
}
