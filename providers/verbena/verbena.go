// Package verbena implements a DNS provider for solving the DNS-01 challenge using verbena DNS.
package verbena

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/1f349/verbena/rest"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/gobuffalo/nulls"
)

const (
	defaultTTL = 3600
	maxTTL     = 2592000
)

var _ challenge.ProviderTimeout = (*DNSProvider)(nil)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	Host               string
	APIKey             string
	PropagationTimeout time.Duration
	PollingInterval    time.Duration
	TTL                int32
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		TTL:                defaultTTL,
		PropagationTimeout: dns01.DefaultPropagationTimeout,
		PollingInterval:    dns01.DefaultPollingInterval,
	}
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	client *rest.Client
	config *Config
}

// NewDNSProviderConfig return a DNSProvider instance configured for verbena.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("verbena: the configuration of the DNS provider is nil")
	}

	if config.TTL < defaultTTL || config.TTL > maxTTL {
		return nil, fmt.Errorf("verbena: TTL should be in [%d, %d]", defaultTTL, maxTTL)
	}

	hostUrl, err := url.Parse(config.Host)
	if err != nil {
		return nil, fmt.Errorf("verbena: invalid host address: %w", err)
	}
	if hostUrl.Scheme != "https" {
		return nil, fmt.Errorf("verbena: invalid host address: host must be absolute and use HTTPS")
	}

	client, err := rest.NewClient(hostUrl.String(), config.APIKey)
	if err != nil {
		return nil, err
	}

	return &DNSProvider{client: client, config: config}, nil
}

// Present creates a TXT record to fulfill the dns-01 challenge.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	zone, err := dns01.FindZoneByFqdn(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("verbena: could not find zone for domain %q: %w", domain, err)
	}

	zoneName := dns01.UnFqdn(zone)

	subdomain, err := dns01.ExtractSubDomain(info.EffectiveFQDN, zoneName)
	if err != nil {
		return fmt.Errorf("verbena: %w", err)
	}

	zoneId, err := d.client.LookupZone(zoneName)
	if err != nil {
		return err
	}

	err = d.client.CreateZoneRecord(zoneId, rest.CreateRecord{
		Name: subdomain,
		Ttl:  nulls.NewInt32(d.config.TTL),
		Type: "TXT",
		Value: rest.RecordValue{
			Text: info.Value,
		},
		Active: true,
	})
	if err != nil {
		return fmt.Errorf("verbena: failed to add record %w", err)
	}
	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	zone, err := dns01.FindZoneByFqdn(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("verbena: could not find zone for domain %q: %w", domain, err)
	}

	zoneName := dns01.UnFqdn(zone)

	zoneId, err := d.client.LookupZone(zoneName)
	if err != nil {
		return err
	}

	resp, err := d.client.GetZoneRecords(zoneId)
	if err != nil {
		return fmt.Errorf("verbena: %w", err)
	}

	subdomain, err := dns01.ExtractSubDomain(info.EffectiveFQDN, zoneName)
	if err != nil {
		return fmt.Errorf("verbena: %w", err)
	}

	for _, r := range resp {
		if r.Type == "TXT" && r.Value.Text == info.Value && (r.Name == subdomain || r.Name == dns01.UnFqdn(info.EffectiveFQDN)) {
			err := d.client.DeleteZoneRecord(zoneId, r.ID)
			if err != nil {
				return fmt.Errorf("verbena: %w", err)
			}

			return nil
		}
	}

	return fmt.Errorf("verbena: no TXT record to delete for %s (%s)", info.EffectiveFQDN, info.Value)
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}
