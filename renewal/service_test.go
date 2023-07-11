package renewal

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"github.com/MrMelon54/certgen"
	"github.com/MrMelon54/orchid/pebble"
	"github.com/MrMelon54/orchid/test"
	"github.com/go-acme/lego/v4/lego"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"go/build"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"
)

const pebbleUrl = "https://localhost:5000"

func TestService_resolveCADirectory(t *testing.T) {
	s := &Service{}
	s.resolveCADirectory("production")
	assert.Equal(t, lego.LEDirectoryProduction, s.caAddr)
	s.resolveCADirectory("prod")
	assert.Equal(t, lego.LEDirectoryProduction, s.caAddr)
	s.resolveCADirectory("staging")
	assert.Equal(t, lego.LEDirectoryStaging, s.caAddr)
	s.resolveCADirectory(pebbleUrl)
	assert.Equal(t, pebbleUrl, s.caAddr)
}

func TestService_resolveCACertificate(t *testing.T) {
	s := &Service{}
	assert.NoError(t, s.resolveCACertificate("default"))
	assert.Nil(t, s.caCert)
	assert.NoError(t, s.resolveCACertificate("pebble"))
	assert.Equal(t, 0, bytes.Compare(pebble.RawCert, s.caCert))
}

func setupPebbleSuite(tb testing.TB) (*certgen.CertGen, func()) {
	log.Println("Running pebble")
	pebbleTmp, err := os.MkdirTemp("", "pebble")
	assert.NoError(tb, err)
	assert.NoError(tb, os.WriteFile(filepath.Join(pebbleTmp, "pebble-config.json"), pebble.RawConfig, os.ModePerm))

	serverTls, err := certgen.MakeServerTls(nil, 2048, pkix.Name{
		Country:            []string{"GB"},
		Organization:       []string{"Orchid"},
		OrganizationalUnit: []string{"Test"},
		SerialNumber:       "0",
		CommonName:         "localhost",
	}, big.NewInt(1), func(now time.Time) time.Time {
		return now.AddDate(10, 0, 0)
	}, []string{"localhost", "pebble"}, []net.IP{net.IPv4(127, 0, 0, 1)})
	assert.NoError(tb, err)
	assert.NoError(tb, os.MkdirAll(filepath.Join(pebbleTmp, "certs", "localhost"), os.ModePerm))
	assert.NoError(tb, os.WriteFile(filepath.Join(pebbleTmp, "certs", "localhost", "cert.pem"), serverTls.GetCertPem(), os.ModePerm))
	assert.NoError(tb, os.WriteFile(filepath.Join(pebbleTmp, "certs", "localhost", "key.pem"), serverTls.GetKeyPem(), os.ModePerm))

	dnsServer := test.MakeFakeDnsProv("127.0.0.34:5053") // 127.0.0.34:53
	dnsServer.AddRecursiveSOA("example.test.")
	go dnsServer.Start()
	testDnsOptions = dnsServer

	pebbleFile := filepath.Join(build.Default.GOPATH, "bin", "pebble")
	command := exec.Command(pebbleFile, "-config", filepath.Join(pebbleTmp, "pebble-config.json"), "-dnsserver", "127.0.0.34:5053")
	command.Env = append(command.Env, "PEBBLE_VA_ALWAYS_VALID=1")
	command.Dir = pebbleTmp

	if command.Start() != nil {
		log.Println("Installing pebble")
		instCmd := exec.Command("go", "install", "github.com/letsencrypt/pebble/cmd/pebble@latest")
		assert.NoError(tb, instCmd.Run(), "Failed to start pebble make sure it is installed... go install github.com/letsencrypt/pebble/cmd/pebble@latest")
		assert.NoError(tb, command.Start(), "failed to start pebble again")
	}

	return serverTls, func() {
		fmt.Println("Killing pebble")
		if command != nil && command.Process != nil {
			assert.NoError(tb, command.Process.Kill())
		}
		dnsServer.Shutdown()
	}
}

func setupPebbleTest(t *testing.T, serverTls *certgen.CertGen) *Service {
	wg := &sync.WaitGroup{}
	dbFile := fmt.Sprintf("file:%s?mode=memory&cache=shared", uuid.NewString())
	db, err := sql.Open("sqlite3", dbFile)
	assert.NoError(t, err)
	log.Println("DB File:", dbFile)

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig.InsecureSkipVerify = true
	req, err := http.NewRequest(http.MethodGet, "https://localhost:14000/root", nil)
	assert.NoError(t, err)
	res, err := tr.RoundTrip(req)
	assert.NoError(t, err)
	certRaw, err := io.ReadAll(res.Body)
	assert.NoError(t, err)

	certDir, err := os.MkdirTemp("", "orchid-certs")
	keyDir, err := os.MkdirTemp("", "orchid-keys")

	lePrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	acmeProv := test.MakeFakeAcmeProv(serverTls.GetCertPem())
	service, err := NewService(wg, db, acmeProv, LetsEncryptConfig{
		Account: LetsEncryptAccount{
			Email:      "webmaster@example.test",
			PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(lePrivKey)})),
		},
		Directory:   "https://localhost:14000/dir",
		Certificate: string(certRaw),
		insecure:    true,
	}, certDir, keyDir)
	assert.NoError(t, err)
	service.transport = acmeProv

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	assert.NoError(t, os.WriteFile(filepath.Join(keyDir, "1.key.pem"), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)}), os.ModePerm))

	return service
}

func TestPebbleRenewal(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping renewal tests in short mode")
	}
	serverTls, cancel := setupPebbleSuite(t)
	t.Cleanup(cancel)

	time.Sleep(5 * time.Second)

	tests := []struct {
		name    string
		domains []string
	}{
		{"Test", []string{"hello.example.test"}},
		{"Test with multiple certificates", []string{"example.test", "world.example.test"}},
		{"Test with wildcard certificate", []string{"example.test", "*.example.test"}},
	}

	for _, i := range tests {
		t.Run(i.name, func(t *testing.T) {
			//t.Parallel()
			service := setupPebbleTest(t, serverTls)
			//goland:noinspection SqlWithoutWhere
			_, err := service.db.Exec("DELETE FROM certificate_domains")
			assert.NoError(t, err)

			_, err = service.db.Exec(`INSERT INTO certificates (owner, dns, auto_renew, active, renewing, renew_failed, not_after, updated_at) VALUES (1, 1, 1, 1, 0, 0, NULL, NULL)`)
			assert.NoError(t, err)
			for _, j := range i.domains {
				_, err = service.db.Exec(`INSERT INTO certificate_domains (cert_id, domain) VALUES (1, ?)`, j)
				assert.NoError(t, err)
			}

			query, err := service.db.Query("SELECT cert_id, domain from certificate_domains")
			assert.NoError(t, err)
			for query.Next() {
				var a uint64
				var b string
				assert.NoError(t, query.Scan(&a, &b))
			}

			assert.NoError(t, service.renewalCheck())
			certFilePath := filepath.Join(service.certDir, "1.cert.pem")
			certFileRaw, err := os.ReadFile(certFilePath)
			assert.NoError(t, err)

			p, _ := pem.Decode(certFileRaw)
			assert.NotNil(t, p)
			if p == nil {
				t.FailNow()
			}
			assert.Equal(t, "CERTIFICATE", p.Type)
			outCert, err := x509.ParseCertificate(p.Bytes)
			assert.NoError(t, err)
			sort.Strings(i.domains)
			sort.Strings(outCert.DNSNames)
			assert.Equal(t, i.domains, outCert.DNSNames)
		})
	}
}
