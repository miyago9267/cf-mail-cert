package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"github.com/miyago/cf-mail-cert/internal/config"
)

// Manager handles the ACME certificate lifecycle: account registration,
// certificate obtainment, renewal, and persistent storage.
type Manager struct {
	config   *config.Config
	provider challenge.Provider
	logger   *slog.Logger
}

func NewManager(cfg *config.Config, provider challenge.Provider, logger *slog.Logger) *Manager {
	return &Manager{
		config:   cfg,
		provider: provider,
		logger:   logger,
	}
}

// ObtainOrRenew checks existing certificate state and either obtains a new
// certificate or renews an existing one as needed. Returns the certificate
// resource, whether any action was taken, and any error.
func (m *Manager) ObtainOrRenew() (*certificate.Resource, bool, error) {
	user, err := m.loadOrCreateAccount()
	if err != nil {
		return nil, false, fmt.Errorf("loading ACME account: %w", err)
	}

	client, err := m.buildClient(user)
	if err != nil {
		return nil, false, fmt.Errorf("building ACME client: %w", err)
	}

	existing, err := m.loadCertificate()
	if err != nil {
		m.logger.Info("no existing certificate found, will obtain new one", "reason", err)
	}

	// Check if domains changed
	if existing != nil && m.domainsChanged(existing) {
		m.logger.Info("configured domains changed, will obtain new certificate")
		existing = nil
	}

	if existing == nil {
		return m.obtain(client)
	}

	needsRenewal, err := m.checkExpiry(existing)
	if err != nil {
		return nil, false, fmt.Errorf("checking certificate expiry: %w", err)
	}

	if !needsRenewal {
		return existing, false, nil
	}

	return m.renew(client, existing)
}

// ForceObtain obtains a new certificate regardless of existing state.
func (m *Manager) ForceObtain() (*certificate.Resource, error) {
	user, err := m.loadOrCreateAccount()
	if err != nil {
		return nil, fmt.Errorf("loading ACME account: %w", err)
	}

	client, err := m.buildClient(user)
	if err != nil {
		return nil, fmt.Errorf("building ACME client: %w", err)
	}

	res, _, err := m.obtain(client)
	return res, err
}

func (m *Manager) obtain(client *lego.Client) (*certificate.Resource, bool, error) {
	m.logger.Info("obtaining new certificate", "domains", m.config.Domains)

	request := certificate.ObtainRequest{
		Domains: m.config.Domains,
		Bundle:  true,
	}

	res, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, false, fmt.Errorf("obtaining certificate: %w", err)
	}

	if err := m.saveCertificate(res); err != nil {
		return nil, false, fmt.Errorf("saving certificate: %w", err)
	}

	m.logger.Info("certificate obtained successfully", "domains", m.config.Domains)
	return res, true, nil
}

func (m *Manager) renew(client *lego.Client, existing *certificate.Resource) (*certificate.Resource, bool, error) {
	m.logger.Info("renewing certificate", "domains", m.config.Domains)

	res, err := client.Certificate.RenewWithOptions(*existing, &certificate.RenewOptions{Bundle: true})
	if err != nil {
		return nil, false, fmt.Errorf("renewing certificate: %w", err)
	}

	if err := m.saveCertificate(res); err != nil {
		return nil, false, fmt.Errorf("saving renewed certificate: %w", err)
	}

	m.logger.Info("certificate renewed successfully", "domains", m.config.Domains)
	return res, true, nil
}

func (m *Manager) checkExpiry(res *certificate.Resource) (bool, error) {
	block, _ := pem.Decode(res.Certificate)
	if block == nil {
		return false, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("parsing certificate: %w", err)
	}

	remaining := time.Until(cert.NotAfter)
	m.logger.Info("certificate expiry check",
		"expires", cert.NotAfter,
		"remaining", remaining.Round(time.Hour),
		"threshold", m.config.Scheduler.RenewBeforeExpiry,
	)

	return remaining < m.config.Scheduler.RenewBeforeExpiry, nil
}

func (m *Manager) domainsChanged(res *certificate.Resource) bool {
	block, _ := pem.Decode(res.Certificate)
	if block == nil {
		return true
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}

	// Compare SANs with configured domains
	certDomains := make([]string, len(cert.DNSNames))
	copy(certDomains, cert.DNSNames)
	sort.Strings(certDomains)

	configDomains := make([]string, len(m.config.Domains))
	copy(configDomains, m.config.Domains)
	sort.Strings(configDomains)

	return !slices.Equal(certDomains, configDomains)
}

func (m *Manager) buildClient(user *acmeUser) (*lego.Client, error) {
	cfg := lego.NewConfig(user)
	cfg.CADirURL = m.config.ACME.CAUrl
	cfg.Certificate.KeyType = certcrypto.EC256

	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating ACME client: %w", err)
	}

	if err := client.Challenge.SetDNS01Provider(m.provider); err != nil {
		return nil, fmt.Errorf("setting DNS-01 provider: %w", err)
	}

	// Register if not already registered
	if user.registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{
			TermsOfServiceAgreed: true,
		})
		if err != nil {
			return nil, fmt.Errorf("registering ACME account: %w", err)
		}
		user.registration = reg
		if err := m.saveAccount(user); err != nil {
			return nil, fmt.Errorf("saving ACME account: %w", err)
		}
		m.logger.Info("ACME account registered", "email", user.email)
	}

	return client, nil
}

// Storage paths

func (m *Manager) storagePath(name string) string {
	return filepath.Join(m.config.ACME.Storage, name)
}

// Account management

type acmeUser struct {
	email        string
	registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

func (m *Manager) loadOrCreateAccount() (*acmeUser, error) {
	if err := os.MkdirAll(m.config.ACME.Storage, 0700); err != nil {
		return nil, fmt.Errorf("creating storage directory: %w", err)
	}

	keyPath := m.storagePath("account.key")
	regPath := m.storagePath("account.json")

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		// Create new account
		m.logger.Info("creating new ACME account key")
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating account key: %w", err)
		}
		return &acmeUser{
			email: m.config.ACME.Email,
			key:   privateKey,
		}, nil
	}

	// Load existing account
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode account key PEM")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing account key: %w", err)
	}

	user := &acmeUser{
		email: m.config.ACME.Email,
		key:   privateKey,
	}

	// Load registration if exists
	regData, err := os.ReadFile(regPath)
	if err == nil {
		var reg registration.Resource
		if err := json.Unmarshal(regData, &reg); err != nil {
			return nil, fmt.Errorf("parsing account registration: %w", err)
		}
		user.registration = &reg
	}

	m.logger.Info("loaded existing ACME account")
	return user, nil
}

func (m *Manager) saveAccount(user *acmeUser) error {
	// Save private key
	ecKey, ok := user.key.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("account key is not ECDSA")
	}

	keyBytes, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		return fmt.Errorf("marshaling account key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	if err := os.WriteFile(m.storagePath("account.key"), keyPEM, 0600); err != nil {
		return fmt.Errorf("writing account key: %w", err)
	}

	// Save registration
	if user.registration != nil {
		regData, err := json.MarshalIndent(user.registration, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling account registration: %w", err)
		}
		if err := os.WriteFile(m.storagePath("account.json"), regData, 0600); err != nil {
			return fmt.Errorf("writing account registration: %w", err)
		}
	}

	return nil
}

// Certificate persistence

func (m *Manager) loadCertificate() (*certificate.Resource, error) {
	metaPath := m.storagePath("certificate.json")

	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, fmt.Errorf("reading certificate metadata: %w", err)
	}

	var res certificate.Resource
	if err := json.Unmarshal(metaData, &res); err != nil {
		return nil, fmt.Errorf("parsing certificate metadata: %w", err)
	}

	certData, err := os.ReadFile(m.storagePath("certificate.pem"))
	if err != nil {
		return nil, fmt.Errorf("reading certificate: %w", err)
	}
	res.Certificate = certData

	keyData, err := os.ReadFile(m.storagePath("certificate.key"))
	if err != nil {
		return nil, fmt.Errorf("reading certificate key: %w", err)
	}
	res.PrivateKey = keyData

	return &res, nil
}

func (m *Manager) saveCertificate(res *certificate.Resource) error {
	// Save certificate PEM
	if err := os.WriteFile(m.storagePath("certificate.pem"), res.Certificate, 0644); err != nil {
		return fmt.Errorf("writing certificate: %w", err)
	}

	// Save private key PEM
	if err := os.WriteFile(m.storagePath("certificate.key"), res.PrivateKey, 0600); err != nil {
		return fmt.Errorf("writing certificate key: %w", err)
	}

	// Save metadata (without cert/key data to avoid duplication)
	meta := *res
	meta.Certificate = nil
	meta.PrivateKey = nil

	metaData, err := json.MarshalIndent(&meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling certificate metadata: %w", err)
	}

	if err := os.WriteFile(m.storagePath("certificate.json"), metaData, 0644); err != nil {
		return fmt.Errorf("writing certificate metadata: %w", err)
	}

	return nil
}
