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
	"github.com/1f349/orchid/pebble"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/duckdns"
	"github.com/go-acme/lego/v4/providers/dns/namesilo"
	"github.com/go-acme/lego/v4/registration"
	"io"
	"log"
	"math/rand"
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

const (
	DomainStateNormal  = 0
	DomainStateAdded   = 1
	DomainStateRemoved = 2
)

// overrides only used in testing
var testDnsOptions interface {
	challenge.Provider
	GetDnsAddrs() []string
}

// Service manages the scheduled renewal of certificates stored in the database
// and outputs the latest certificates to the certDir folder. If the certificate
// does not have a key already defined in keyDir then a new key is generated.
//
// The service makes use of an HTTP ACME challenge provider, and a DNS ACME
// challenge provider. These ensure the `.wellknown/acme-challenges` files and
// `_acme-challenges` TXT records are updated to validate the ownership of the
// specified domains.
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
	client     *lego.Client
}

// NewService creates a new certificate renewal service.
func NewService(wg *sync.WaitGroup, db *sql.DB, httpAcme challenge.Provider, leConfig LetsEncryptConfig, certDir, keyDir string) (*Service, error) {
	s := &Service{
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
	err = s.resolveLEPrivKey(leConfig.Account.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve LetsEncrypt account private key: %w", err)
	}

	// init domains table
	_, err = s.db.Exec(createTableCertificates)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificates table: %w", err)
	}

	// resolve CA information
	s.resolveCADirectory(leConfig.Directory)
	err = s.resolveCACertificate(leConfig.Certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve CA certificate: %w", err)
	}

	// setup client for requesting a new certificate
	client, err := s.setupLegoClient()
	if err != nil {
		return nil, fmt.Errorf("failed to generate a client: %w", err)
	}
	s.client = client

	// start the background routine
	wg.Add(1)
	go s.renewalRoutine(wg)
	return s, nil
}

// Shutdown the renewal service.
func (s *Service) Shutdown() {
	log.Println("[Renewal] Shutting down certificate renewal service")
	close(s.certDone)
}

// resolveLEPrivKey resolves the private key for the LetsEncrypt account.
// If the string is a path to a file then the contents of the file is read.
func (s *Service) resolveLEPrivKey(a string) error {
	p, _ := pem.Decode([]byte(a))
	if p == nil {
		return fmt.Errorf("failed to parse pem encoding")
	}
	if p.Type != "RSA PRIVATE KEY" {
		return fmt.Errorf("invalid key types: %s", p.Type)
	}
	key, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse key: %w", err)
	}
	s.leAccount.key = key
	return err
}

// resolveCADirectory resolves the certificate authority directory URL.
//
// If "production" or "prod" then the LetsEncrypt production directory is used.
//
// If "staging" then the LetsEncrypt staging directory is used.
//
// Otherwise, the string is assumed to be a value directory URL (used for testing
// with pebble).
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

// resolveCACertificate resolves the certificate authority root certificate.
//
// If "default" is used then the internal library lego defaults to the
// LetsEncrypt production root certificate.
//
// If "pebble" is used then the pebble certificate is used.
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

// renewalRoutine is the main loop which makes used of certTicker to constantly
// check if the existing certificates are up-to-date.
func (s *Service) renewalRoutine(wg *sync.WaitGroup) {
	// Upon leaving the function stop the ticker and clear the WaitGroup.
	defer func() {
		s.certTicker.Stop()
		log.Println("[Renewal] Stopped certificate renewal service")
		wg.Done()
	}()

	// Do an initial check and refuse to start if any errors occur.
	log.Println("[Renewal] Doing quick certificate check before starting...")
	err := s.renewalCheck()
	if err != nil {
		log.Println("[Renewal] Certificate check, should not error first try: ", err)
		return
	}

	// Logging or something
	log.Println("[Renewal] Initial check complete, continually checking every 10 minutes...")

	// Main loop
	for {
		select {
		case <-s.certDone:
			// Exit if certDone has closed
			return
		case <-s.certTicker.C:
			// Start a new check in a separate routine
			go func() {
				// run a renewal check and log errors, but ignore ErrAlreadyRenewing
				err := s.renewalCheck()
				if err != nil && !errors.Is(err, ErrAlreadyRenewing) {
					log.Println("[Renewal] Certificate check, an error occurred: ", err)
				}
			}()
		}
	}
}

// renewalCheck runs a locked renewal check, this only returns and unlocks once a
// renewal finishes or if no certificate needs to renew.
func (s *Service) renewalCheck() error {
	if !s.renewLock.TryLock() {
		return ErrAlreadyRenewing
	}
	defer s.renewLock.Unlock()

	// check for running out certificates in the database
	localData, err := s.findNextCertificateToRenew()
	if err != nil {
		return fmt.Errorf("failed to find a certificate to renew: %w", err)
	}

	// no certificates to update
	if localData == nil {
		return nil
	}

	// renew the certificate from the collected data
	err = s.renewCert(localData)
	if err != nil {
		return err
	}

	// renew succeeded
	log.Printf("[Renewal] Updated certificate %d successfully\n", localData.id)

	return nil
}

// findNextCertificateToRenew finds a certificate to update
func (s *Service) findNextCertificateToRenew() (*localCertData, error) {
	d := &localCertData{}

	// sql or something, the query is in `find-next-cert.sql`
	row, err := s.db.Query(findNextCertSql)
	if err != nil {
		return nil, fmt.Errorf("failed to run query: %w", err)
	}
	defer row.Close()

	// if next fails no rows were found
	if !row.Next() {
		return nil, nil
	}

	// scan the first row
	err = row.Scan(&d.id, &d.notAfter, &d.dns.name, &d.dns.token, &d.tempParent)
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
	// more sql: this one just grabs all the domains for a certificate
	query, err := s.db.Query(`SELECT domain FROM certificate_domains WHERE cert_id = ?`, resolveTempParent(localData))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch domains for certificate: %d: %w", localData.id, err)
	}

	// convert query responses to a string slice
	domains := make([]string, 0)
	for query.Next() {
		var domain string
		err := query.Scan(&domain)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row from domains table: %d: %w", localData.id, err)
		}
		domains = append(domains, domain)
	}
	// if no domains were found then the renewal will fail
	if len(domains) == 0 {
		return nil, fmt.Errorf("no domains registered for certificate: %d", localData.id)
	}
	return domains, nil
}

func (s *Service) setupLegoClient() (*lego.Client, error) {
	// create lego config and change the certificate authority directory URL and the
	// http.Client transport if an alternative is provided
	config := lego.NewConfig(s.leAccount)
	config.CADirURL = s.caAddr
	if s.transport != nil {
		config.HTTPClient.Transport = s.transport
	}

	// create lego client from the config
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client: %w", err)
	}

	// set http challenge provider
	_ = client.Challenge.SetHTTP01Provider(s.httpAcme)

	// make sure the LetsEncrypt account is registered
	register, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("failed to update account registration: %w", err)
	}

	// return and use the client
	s.leAccount.reg = register
	return client, nil
}

// getDnsProvider loads a DNS challenge provider using the provided name and
// token
func (s *Service) getDnsProvider(name, token string) (challenge.Provider, error) {
	log.Printf("[Renewal] Loading dns provider: %s with token %s*****\n", name, token[:3])
	switch name {
	case "duckdns":
		return duckdns.NewDNSProviderConfig(&duckdns.Config{
			Token:              token,
			PropagationTimeout: 15 * time.Minute,
			PollingInterval:    2 * time.Minute,
		})
	case "namesilo":
		return namesilo.NewDNSProviderConfig(&namesilo.Config{
			APIKey:             token,
			PropagationTimeout: 2 * time.Hour,
			PollingInterval:    15 * time.Minute,
			TTL:                3600,
		})
	default:
		return nil, ErrUnsupportedDNSProvider
	}
}

// getPrivateKey reads the private key for the specified certificate id, or
// generates one is the file doesn't exist
func (s *Service) getPrivateKey(id uint64) (*rsa.PrivateKey, error) {
	fPath := filepath.Join(s.keyDir, fmt.Sprintf("%d.key.pem", id))
	pemBytes, err := os.ReadFile(fPath)
	if err != nil {
		if os.IsNotExist(err) {
			key, err := rsa.GenerateKey(rand.New(rand.NewSource(time.Now().UnixNano())), 4096)
			if err != nil {
				return nil, fmt.Errorf("generate rsa key error: %w", err)
			}
			err = os.WriteFile(fPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), os.ModePerm)
			if err != nil {
				return nil, fmt.Errorf("failed to save rsa key: %w", err)
			}
			return key, nil
		}
		return nil, err
	}
	keyBlock, _ := pem.Decode(pemBytes)
	if keyBlock == nil {
		return nil, fmt.Errorf("invalid pem block: failed to parse")
	}
	if keyBlock.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("invalid pem block type")
	}
	return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
}

// renewCert sets the renewing state in the database, calls renewCertInternal,
// updates the NotAfter/NotBefore columns in the database and writes the
// certificate to the certDir directory.
func (s *Service) renewCert(localData *localCertData) error {
	// database synchronous state
	s.setRenewing(localData.id, true, false)

	// run internal renewal code and log errors
	cert, certBytes, err := s.renewCertInternal(localData)
	if err != nil {
		s.setRenewing(localData.id, false, true)
		return fmt.Errorf("failed to renew cert %d: %w", localData.id, err)
	}

	// set the NotAfter/NotBefore in the database
	_, err = s.db.Exec(`UPDATE certificates SET renewing = 0, renew_failed = 0, not_after = ?, updated_at = ? WHERE id = ?`, cert.NotAfter, cert.NotBefore, localData.id)
	if err != nil {
		return fmt.Errorf("failed to update cert %d in database: %w", localData.id, err)
	}

	// set domains to normal state
	_, err = s.db.Exec(`UPDATE certificate_domains SET state = ? WHERE cert_id = ?`, DomainStateNormal, localData.id)
	if err != nil {
		return fmt.Errorf("failed to update domains for %d in database: %w", localData.id, err)
	}

	// write out the certificate file
	err = s.writeCertFile(localData.id, certBytes)
	if err != nil {
		return fmt.Errorf("failed to write cert file: %w", err)
	}

	return nil
}

// renewCertInternal handles each stage of fetching the certificate private key,
// fetching the domains slice, setting up the lego client, obtaining a renewed
// certificate, decoding and parsing the certificate.
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

	// remove old dns challenge
	s.client.Challenge.Remove(challenge.DNS01)

	// if testDnsOptions is defined then set up the test provider
	if testDnsOptions != nil {
		// set up the dns provider used during tests and disable propagation as no dns
		// will validate these tests
		dnsAddr := testDnsOptions.GetDnsAddrs()
		log.Printf("Using testDnsOptions with DNS server: %v\n", dnsAddr)
		_ = s.client.Challenge.SetDNS01Provider(testDnsOptions, dns01.AddRecursiveNameservers(dnsAddr), dns01.DisableCompletePropagationRequirement())
	} else if localData.dns.name.Valid && localData.dns.token.Valid {
		// if the dns name and token are "valid" meaning non-null in this case
		// set up the specific dns provider requested
		dnsProv, err := s.getDnsProvider(localData.dns.name.String, localData.dns.token.String)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to resolve dns provider: %w", err)
		}
		_ = s.client.Challenge.SetDNS01Provider(dnsProv)
	}

	// obtain new certificate - this call will hang until a certificate is ready
	obtain, err := s.client.Certificate.Obtain(certificate.ObtainRequest{
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

// setRenewing sets the renewing and failed states in the database for a
// specified certificate id.
func (s *Service) setRenewing(id uint64, renewing, failed bool) {
	_, err := s.db.Exec("UPDATE certificates SET renewing = ?, renew_failed = ? WHERE id = ?", renewing, failed, id)
	if err != nil {
		log.Printf("[Renewal] Failed to set renewing/failed mode in database %d: %s\n", id, err)
	}
}

// writeCertFile writes the output certificate file and renames the current one
// to include `-old` in the name.
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

func resolveTempParent(local *localCertData) uint64 {
	if local.tempParent > 0 {
		return local.tempParent
	}
	return local.id
}
