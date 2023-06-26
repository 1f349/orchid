package renewal

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"github.com/MrMelon54/orchid/http-acme"
	"github.com/MrMelon54/orchid/pebble-dev"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/namesilo"
	"github.com/go-acme/lego/v4/registration"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	ErrUnsupportedDNSProvider = errors.New("unsupported DNS provider")
	//go:embed find-next-cert.sql
	findNextCertSql string
	//go:embed create-tables.sql
	createTableCertificates string
)

type Service struct {
	db         *sql.DB
	httpAcme   *http_acme.HttpAcmeProvider
	certTicker *time.Ticker
	certDone   chan struct{}
	caAddr     string
	caCert     []byte
	transport  *http.Transport
	renewLock  *sync.Mutex
	leAccount  *Account
	certDir    string
	keyDir     string

	//notify
}

func NewRenewalService(wg *sync.WaitGroup, db *sql.DB, httpAcme *http_acme.HttpAcmeProvider, leConfig LetsEncryptConfig) (*Service, error) {
	r := &Service{
		db:         db,
		httpAcme:   httpAcme,
		certTicker: time.NewTicker(time.Minute * 10),
		certDone:   make(chan struct{}),
		renewLock:  &sync.Mutex{},
		leAccount: &Account{
			email: leConfig.Account.Email,
			key:   leConfig.Account.PrivateKey,
		},
	}

	// init domains table
	_, err := r.db.Exec(createTableCertificates)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificates table: %w", err)
	}

	// resolve CA information
	r.resolveCADirectory(leConfig)
	err = r.resolveCACertificate(leConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve CA certificate: %w", err)
	}

	wg.Add(1)
	go r.renewalRoutine(wg)
	return r, nil
}

func (s *Service) Shutdown() {
	log.Println("[Renewal] Shutting down certificate renewal service")
	close(s.certDone)
}

func (s *Service) resolveCADirectory(conf LetsEncryptConfig) {
	switch conf.Directory {
	case "production", "prod":
		s.caAddr = lego.LEDirectoryProduction
	case "staging":
		s.caAddr = lego.LEDirectoryStaging
	default:
		s.caAddr = conf.Directory
	}
}

func (s *Service) resolveCACertificate(conf LetsEncryptConfig) error {
	switch conf.Certificate {
	case "default":
		// no nothing
	case "pebble":
		s.caCert = pebble_dev.GetPebbleCert()
	default:
		caGet, err := http.Get(conf.Certificate)
		if err != nil {
			return fmt.Errorf("failed to download CA certificate: %w", err)
		}
		s.caCert, err = io.ReadAll(caGet.Body)
		if err != nil {
			return fmt.Errorf("failed to read CA certificate: %w", err)
		}
	}
	if s.caCert != nil {
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(s.caCert) {
			return fmt.Errorf("failed to add certificate to CA cert pool")
		}
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.TLSClientConfig = &tls.Config{RootCAs: caPool}
		s.transport = t
	}
	return nil
}

var ErrAlreadyRenewing = errors.New("already renewing")

func (s *Service) renewalRoutine(wg *sync.WaitGroup) {
	defer func() {
		s.certTicker.Stop()
		log.Println("[Renewal] Stopped certificate renewal service")
		wg.Done()
	}()

	log.Println("[Renewal] Doing quick certificate check before starting...")
	err := s.renewalCheck()
	if err != nil {
		log.Println("[Renewal] Certificate check, should not error first try: ", err)
		return
	}
	log.Println("[Renewal] Initial check complete, continually checking every 4 hours...")

	for {
		select {
		case <-s.certDone:
			return
		case <-s.certTicker.C:
			go func() {
				err := s.renewalCheck()
				if err != nil && err != ErrAlreadyRenewing {
					log.Println("[Renewal] Certificate check, an error occurred: ", err)
				}
			}()
		}
	}
}

func (s *Service) renewalCheck() error {
	if !s.renewLock.TryLock() {
		return ErrAlreadyRenewing
	}
	defer s.renewLock.Unlock()

	localData, err := s.findNextCertificateToRenew()
	if err != nil {
		return fmt.Errorf("failed to find a certificate to renew: %w", err)
	}

	// no certificates to update
	if localData == nil {
		return nil
	}

	s.renewCert(localData)
}

func (s *Service) findNextCertificateToRenew() (*localCertData, error) {
	d := &localCertData{}

	row := s.db.QueryRow(findNextCertSql)
	err := row.Scan(&d.id, &d.cert.current, &d.cert.notAfter, &d.dns.name, &d.dns.token)
	switch err {
	case nil:
		// no nothing
		break
	case io.EOF:
		// no certificate to update
		return nil, nil
	default:
		return nil, fmt.Errorf("failed to scan table row: %w", err)
	}

	return d, nil
}

func (s *Service) fetchDomains(localData *localCertData) ([]string, error) {
	query, err := s.db.Query(`SELECT domain FROM certificate_domains WHERE cert_id = ?`, localData.id)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch domains for certificate: %d: %w", localData.id, err)
	}

	domains := make([]string, 0)
	for query.Next() {
		var domain string
		err := query.Scan(&domain)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row from domains table: %d: %w", localData.id, err)
		}
		domains = append(domains, domain)
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("no domains registered for certificate: %d", localData.id)
	}
	return domains, nil
}

func (s *Service) setupLegoClient(localData *localCertData) (*lego.Client, error) {
	config := lego.NewConfig(s.leAccount)
	config.CADirURL = s.caAddr
	if s.transport != nil {
		config.HTTPClient.Transport = s.transport
	}
	dnsProv, err := s.getDnsProvider(localData.dns.name, localData.dns.token)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve dns provider: %w", err)
	}

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client: %w", err)
	}

	// set providers - always returns nil so ignore the error
	_ = client.Challenge.SetHTTP01Provider(s.httpAcme)
	_ = client.Challenge.SetDNS01Provider(dnsProv)

	register, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("failed to update account registration: %w", err)
	}

	s.leAccount.reg = register
	return client, nil
}

func (s *Service) getDnsProvider(name, token string) (challenge.Provider, error) {
	switch name {
	case "namesilo":
		return namesilo.NewDNSProviderConfig(&namesilo.Config{APIKey: token})
	default:
		return nil, ErrUnsupportedDNSProvider
	}
}

func (s *Service) getPrivateKey(id uint64) (*rsa.PrivateKey, error) {
	privKeyBytes, err := os.ReadFile(filepath.Join(s.keyDir, fmt.Sprintf("%d.key.pem", id)))
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PrivateKey(privKeyBytes)
}

func (s *Service) renewCert(localData *localCertData) {
	s.setRenewing(localData.id, true, false)

	cert, certBytes, err := s.renewCertInternal(localData)
	if err != nil {
		log.Printf("[Renewal Failed to renew cert %d: %s\n", localData.id, err)
		s.setRenewing(localData.id, false, true)
		return
	}

	_, err = s.db.Exec(`UPDATE certificates SET renewing = 0, renew_failed = 0, not_after = ?, updated_at = ? WHERE id = ?`, cert.NotAfter, cert.NotBefore, localData.id)
	if err != nil {
		log.Printf("[Renewal] Failed to update certificate %d in database: %s\n", localData.id, err)
		return
	}

	oldPath := filepath.Join(s.certDir, fmt.Sprintf("%d-old.cert.pem", localData.id))
	newPath := filepath.Join(s.certDir, fmt.Sprintf("%d.cert.pem", localData.id))

	err = os.Rename(newPath, oldPath)
	if err != nil {
		log.Printf("[Renewal] Failed to rename certificate file '%s' => '%s': %s\n", newPath, oldPath, err)
		return
	}

	openCertFile, err := os.Create(newPath)
	if err != nil {
		log.Printf("[Renewal] Failed to create certificate file '%s': %s\n", newPath, err)
		return
	}
	defer openCertFile.Close()

	_, err = openCertFile.Write(certBytes)
	if err != nil {
		log.Printf("[Renewal] Failed to write certificate file '%s': %s\n", newPath, err)
		return
	}

	log.Printf("[Renewal] Updated certificate %d successfully\n", localData.id)
}

func (s *Service) renewCertInternal(localData *localCertData) (*x509.Certificate, []byte, error) {
	// read private key file
	privKey, err := s.getPrivateKey(localData.id)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open private key: %w", err)
	}

	// fetch domains for this certificate
	domains, err := s.fetchDomains(localData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to update cert: %w", err)
	}

	// setup client for requesting a new certificate
	client, err := s.setupLegoClient(localData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate a client: %w", err)
	}

	obtain, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains:    domains,
		PrivateKey: privKey,
		Bundle:     true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to obtain replacement certificate: %w", err)
	}

	parseCert, err := x509.ParseCertificate(obtain.Certificate)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse new certificate: %w", err)
	}

	return parseCert, obtain.Certificate, nil
}

func (s *Service) setRenewing(id uint64, renewing, failed bool) {
	_, err := s.db.Exec("UPDATE certificates SET renewing = ?, renew_failed = ? WHERE id = ?", renewing, failed, id)
	if err != nil {
		log.Printf("[Renewal] Failed to set renewing/failed mode in database %d: %s\n", id, err)
	}
}
