package renewal

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/MrMelon54/orchid/pebble"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/duckdns"
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

var testDnsOptions interface {
	challenge.Provider
	GetDnsAddrs() []string
}

type Service struct {
	db         *sql.DB
	httpAcme   challenge.Provider
	certTicker *time.Ticker
	certDone   chan struct{}
	caAddr     string
	caCert     []byte
	transport  http.RoundTripper
	renewLock  *sync.Mutex
	leAccount  *Account
	certDir    string
	keyDir     string
	insecure   bool
}

func NewRenewalService(wg *sync.WaitGroup, db *sql.DB, httpAcme challenge.Provider, leConfig LetsEncryptConfig, certDir, keyDir string) (*Service, error) {
	r := &Service{
		db:         db,
		httpAcme:   httpAcme,
		certTicker: time.NewTicker(time.Minute * 10),
		certDone:   make(chan struct{}),
		renewLock:  &sync.Mutex{},
		leAccount: &Account{
			email: leConfig.Account.Email,
		},
		certDir:  certDir,
		keyDir:   keyDir,
		insecure: leConfig.insecure,
	}

	// make certDir and keyDir
	err := os.MkdirAll(certDir, os.ModePerm)
	if err != nil {
		return nil, fmt.Errorf("failed to create certDir '%s': %w", certDir, err)
	}
	err = os.MkdirAll(keyDir, os.ModePerm)
	if err != nil {
		return nil, fmt.Errorf("failed to create certDir '%s': %w", certDir, err)
	}

	// load lets encrypt private key
	err = r.resolveLEPrivKey(leConfig.Account.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve LetsEncrypt account private key: %w", err)
	}

	// init domains table
	_, err = r.db.Exec(createTableCertificates)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificates table: %w", err)
	}

	// resolve CA information
	r.resolveCADirectory(leConfig.Directory)
	err = r.resolveCACertificate(leConfig.Certificate)
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

func (s *Service) resolveLEPrivKey(a string) error {
	key, err := x509.ParsePKCS1PrivateKey([]byte(a))
	if err != nil {
		bytes, err := os.ReadFile(a)
		if err != nil {
			return err
		}
		key, err = x509.ParsePKCS1PrivateKey(bytes)
	}
	s.leAccount.key = key
	return err
}

func (s *Service) resolveCADirectory(dir string) {
	switch dir {
	case "production", "prod":
		s.caAddr = lego.LEDirectoryProduction
	case "staging":
		s.caAddr = lego.LEDirectoryStaging
	default:
		s.caAddr = dir
	}
}

func (s *Service) resolveCACertificate(cert string) error {
	switch cert {
	case "default":
		// no nothing
	case "pebble":
		s.caCert = pebble.RawCert
	case "insecure":
		s.caCert = []byte{0x00}
	default:
		s.caCert = []byte(cert)
	}
	if s.caCert != nil {
		if bytes.Compare([]byte{0x00}, s.caCert) == 0 {
			t := http.DefaultTransport.(*http.Transport).Clone()
			t.TLSClientConfig.InsecureSkipVerify = true
			s.transport = t
		} else {
			caPool := x509.NewCertPool()
			if !caPool.AppendCertsFromPEM(s.caCert) {
				return fmt.Errorf("failed to add certificate to CA cert pool")
			}
			t := http.DefaultTransport.(*http.Transport).Clone()
			t.TLSClientConfig = &tls.Config{RootCAs: caPool}
			s.transport = t
		}
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

	err = s.renewCert(localData)
	if err != nil {
		return err
	}
	log.Printf("[Renewal] Updated certificate %d successfully\n", localData.id)
	return nil
}

func (s *Service) findNextCertificateToRenew() (*localCertData, error) {
	d := &localCertData{}

	row := s.db.QueryRow(findNextCertSql)
	err := row.Scan(&d.id, &d.notAfter, &d.dns.name, &d.dns.token)
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

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client: %w", err)
	}

	// set http challenge provider
	_ = client.Challenge.SetHTTP01Provider(s.httpAcme)

	// if testDnsOptions is defined then set up the test provider
	if testDnsOptions != nil {
		dnsAddrs := testDnsOptions.GetDnsAddrs()
		log.Printf("Using testDnsOptions with DNS server: %v\n", dnsAddrs)
		_ = client.Challenge.SetDNS01Provider(testDnsOptions, dns01.AddRecursiveNameservers(dnsAddrs), dns01.DisableCompletePropagationRequirement())
	} else if localData.dns.name.Valid && localData.dns.token.Valid {
		// if the dns name and token are "valid" meaning non-null in this case
		// set up the specific dns provider requested
		dnsProv, err := s.getDnsProvider(localData.dns.name.String, localData.dns.token.String)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve dns provider: %w", err)
		}
		_ = client.Challenge.SetDNS01Provider(dnsProv)
	}

	register, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("failed to update account registration: %w", err)
	}

	s.leAccount.reg = register
	return client, nil
}

func (s *Service) getDnsProvider(name, token string) (challenge.Provider, error) {
	switch name {
	case "duckdns":
		config := duckdns.NewDefaultConfig()
		config.Token = token
		return duckdns.NewDNSProviderConfig(config)
	case "namesilo":
		config := namesilo.NewDefaultConfig()
		config.APIKey = token
		return namesilo.NewDNSProviderConfig(config)
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

func (s *Service) renewCert(localData *localCertData) error {
	s.setRenewing(localData.id, true, false)

	cert, certBytes, err := s.renewCertInternal(localData)
	if err != nil {
		s.setRenewing(localData.id, false, true)
		return fmt.Errorf("failed to renew cert %d: %w", localData.id, err)
	}

	_, err = s.db.Exec(`UPDATE certificates SET renewing = 0, renew_failed = 0, not_after = ?, updated_at = ? WHERE id = ?`, cert.NotAfter, cert.NotBefore, localData.id)
	if err != nil {
		return fmt.Errorf("failed to update cert %d in database: %w", localData.id, err)
	}

	err = s.writeCertFile(localData.id, certBytes)
	if err != nil {
		return fmt.Errorf("failed to write cert file: %w", err)
	}

	return nil
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

	// obtain new certificate - this call will hang until a certificate is ready
	obtain, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains:    domains,
		PrivateKey: privKey,
		Bundle:     true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to obtain replacement certificate: %w", err)
	}

	// extract the certificate data from pem encoding
	p, _ := pem.Decode(obtain.Certificate)
	if p.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("invalid certificate type '%s'", p.Type)
	}

	// parse the obtained certificate
	parseCert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse new certificate: %w", err)
	}

	// return the parsed and raw bytes
	return parseCert, obtain.Certificate, nil
}

func (s *Service) setRenewing(id uint64, renewing, failed bool) {
	_, err := s.db.Exec("UPDATE certificates SET renewing = ?, renew_failed = ? WHERE id = ?", renewing, failed, id)
	if err != nil {
		log.Printf("[Renewal] Failed to set renewing/failed mode in database %d: %s\n", id, err)
	}
}

func (s *Service) writeCertFile(id uint64, certBytes []byte) error {
	oldPath := filepath.Join(s.certDir, fmt.Sprintf("%d-old.cert.pem", id))
	newPath := filepath.Join(s.certDir, fmt.Sprintf("%d.cert.pem", id))

	// move certificate file to old name
	err := os.Rename(newPath, oldPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to rename cert file '%s' => '%s': %w", newPath, oldPath, err)
	}

	// create new certificate file
	openCertFile, err := os.Create(newPath)
	if err != nil {
		return fmt.Errorf("failed to create cert file '%s': %s", newPath, err)
	}
	defer openCertFile.Close()

	// write certificate bytes
	_, err = openCertFile.Write(certBytes)
	if err != nil {
		return fmt.Errorf("failed to write cert file '%s': %s", newPath, err)
	}

	return nil
}
