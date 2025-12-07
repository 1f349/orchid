package joint

import (
	"context"
	"errors"
	"github.com/1f349/cache"
	"github.com/1f349/orchid/database"
	"github.com/1f349/orchid/logger"
	"github.com/1f349/orchid/providers/verbena"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/providers/dns/duckdns"
	"github.com/go-acme/lego/v4/providers/dns/namesilo"
	"strings"
	"time"
)

var errDomainNotFound = errors.New("domain not found")
var errUnsupportedDNSProvider = errors.New("unsupported DNS provider")

// One day of cache should be plenty
var domainCacheDuration = 24 * time.Hour

var _ challenge.ProviderTimeout = (*DNSProvider)(nil)

type domainQuery interface {
	FindDomainAcmeToken(ctx context.Context, domain string) ([]database.DnsApiToken, error)
}

type domainCacheItem struct {
	id       int64
	source   string
	token    string
	provider challenge.Provider
}

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	DomainQuery        domainQuery
	PropagationTimeout time.Duration
	PollingInterval    time.Duration
}

func NewDefaultConfig(query domainQuery) *Config {
	return &Config{
		DomainQuery:        query,
		PropagationTimeout: dns01.DefaultPropagationTimeout,
		PollingInterval:    dns01.DefaultPollingInterval,
	}
}

// NewDNSProviderConfig returns a default configuration for the DNSProvider.
func NewDNSProviderConfig(config *Config) challenge.Provider {
	return &DNSProvider{
		config:      config,
		domainCache: cache.New[string, domainCacheItem](),
	}
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config      *Config
	domainCache *cache.Cache[string, domainCacheItem]
}

// makeProvider constructs a DNS challenge provider using the provided source and token
func (d *DNSProvider) makeProvider(source string, token string) (challenge.Provider, error) {
	switch source {
	case "duckdns":
		return duckdns.NewDNSProviderConfig(&duckdns.Config{
			Token:              token,
			PropagationTimeout: 20 * time.Minute,
			PollingInterval:    5 * time.Minute,
		})
	case "namesilo":
		return namesilo.NewDNSProviderConfig(&namesilo.Config{
			APIKey:             token,
			PropagationTimeout: 2 * time.Hour,
			PollingInterval:    15 * time.Minute,
			TTL:                3600,
		})
	case "1f349":
		return verbena.NewDNSProviderConfig(&verbena.Config{
			Host:               "https://api.1f349.com/v1/verbena",
			APIKey:             token,
			PropagationTimeout: 20 * time.Minute,
			PollingInterval:    5 * time.Minute,
			TTL:                3600,
		})
	default:
		return nil, errUnsupportedDNSProvider
	}
}

func (d *DNSProvider) fetchProviderFromDatabase(domain string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Try fetching new rows for the domain cache
	rows, err := d.config.DomainQuery.FindDomainAcmeToken(ctx, domain)
	cancel()
	if err != nil {
		return err
	}
	for _, i := range rows {
		dnsProvider, err := d.makeProvider(i.Source, i.Token)
		if err != nil {
			logger.Logger.Error("Failed to make DNS provider", "id", i.ID, "source", i.Source, "err", err)
		} else {
			d.domainCache.Set(i.Domain, domainCacheItem{
				id:       i.ID,
				source:   i.Source,
				token:    i.Token,
				provider: dnsProvider,
			}, domainCacheDuration)
		}
	}

	return nil
}

func (d *DNSProvider) ResolveProvider(domain string) (challenge.Provider, error) {
	var provider challenge.Provider
	for {
		err := d.fetchProviderFromDatabase(domain)
		if err == nil {
			logger.Logger.Warn("Failed to fetch providers from the database", "domain", domain, "err", err)
		}

		// Resolve the provider from the cache
		item, ok := d.domainCache.Get(domain)
		if ok {
			logger.Logger.Info("Loading DNS provider", "domain", domain, "id", item.id, "source", item.source)
			provider = item.provider
			break
		}

		// Split by the next subdomain separator
		n := strings.IndexByte(domain, '.')
		if n == -1 {
			return nil, errDomainNotFound
		}
		domain = domain[n+1:]
	}
	return provider, nil
}

// Present creations a TXT record to fulfill the dns-01 challenge.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	provider, err := d.ResolveProvider(domain)
	if err != nil {
		return err
	}
	return provider.Present(domain, token, keyAuth)
}

// CleanUp removes the TXT record to fulfill the dns-01 challenge.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	provider, err := d.ResolveProvider(domain)
	if err != nil {
		return err
	}
	return provider.CleanUp(domain, token, keyAuth)
}

func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}
