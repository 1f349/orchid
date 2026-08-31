package renewal

import (
	"bytes"
	"charm.land/log/v2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"github.com/1f349/orchid"
	"github.com/1f349/orchid/logger"
	"github.com/1f349/orchid/pebble"
	"github.com/1f349/orchid/test"
	"github.com/go-acme/lego/v5/lego"
	"github.com/gobuffalo/nulls"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/mrmelon54/certgen"
	"github.com/stretchr/testify/assert"
	"go/build"
	"math/big"
	"net"
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
	assert.Equal(t, lego.DirectoryURLLetsEncrypt, s.caAddr)
	s.resolveCADirectory("prod")
	assert.Equal(t, lego.DirectoryURLLetsEncrypt, s.caAddr)
	s.resolveCADirectory("staging")
	assert.Equal(t, lego.DirectoryURLLetsEncryptStaging, s.caAddr)
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
	Logger.Info("Running pebble")
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

	dnsServer := test.MakeFakeDnsProv("127.243.243.34:5053") // 127.243.243.34:53
	dnsServer.AddRecursiveSOA("example.test.")
	go dnsServer.Start()
	testDnsOptions = dnsServer

	pebbleFile := filepath.Join(build.Default.GOPATH, "bin", "pebble")
	command := exec.Command(pebbleFile, "-config", filepath.Join(pebbleTmp, "pebble-config.json"), "-dnsserver", "127.0.0.34:5053")
	command.Env = append(command.Env, "PEBBLE_VA_ALWAYS_VALID=1")
	command.Dir = pebbleTmp

	if command.Start() != nil {
		_ = command.Wait()

		Logger.Info("Installing pebble")
		instCmd := exec.Command("go", "install", "github.com/letsencrypt/pebble/v2/cmd/pebble@latest")
		assert.NoError(tb, instCmd.Run(), "Failed to start pebble make sure it is installed... go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest")

		command = exec.Command(pebbleFile, "-config", filepath.Join(pebbleTmp, "pebble-config.json"), "-dnsserver", "127.0.0.34:5053")
		command.Env = append(command.Env, "PEBBLE_VA_ALWAYS_VALID=1")
		command.Dir = pebbleTmp
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		assert.NoError(tb, command.Start(), "failed to start pebble again")
	}

	return serverTls, func() {
		fmt.Println("Killing pebble")
		if command != nil && command.Process != nil {
			assert.NoError(tb, command.Process.Kill())
			_ = command.Wait()
		}
		dnsServer.Shutdown()
		assert.NoError(tb, os.RemoveAll(pebbleTmp))
	}
}

func setupPebbleTest(t *testing.T, serverTls *certgen.CertGen) (*Service, *sql.DB) {
	wg := &sync.WaitGroup{}
	dbFile := fmt.Sprintf("file:%s?mode=memory&cache=shared", uuid.NewString())
	db, err := orchid.InitDB(dbFile)
	assert.NoError(t, err)
	db2, err := sql.Open("sqlite3", dbFile)
	assert.NoError(t, err)

	Logger.Info("DB File:", "db", dbFile)

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
		Certificate: "insecure",
		insecure:    true,
	}, certDir, keyDir)
	fmt.Println(err)
	assert.NoError(t, err)

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	assert.NoError(t, os.WriteFile(filepath.Join(keyDir, "1.key.pem"), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)}), os.ModePerm))

	return service, db2
}

func deconstructPebbleTest(t *testing.T, service *Service) {
	assert.NoError(t, os.RemoveAll(service.certDir))
	assert.NoError(t, os.RemoveAll(service.keyDir))
}

func TestPebbleRenewal(t *testing.T) {
	logger.Logger.SetLevel(log.DebugLevel)

	if testing.Short() {
		t.Skip("Skipping renewal tests in short mode")
	}
	serverTls, cancel := setupPebbleSuite(t)
	t.Cleanup(cancel)

	time.Sleep(5 * time.Second)

	const oneDay = 24 * time.Hour

	tests := []struct {
		name    string
		domains []string
		dur     time.Duration
		short   bool
	}{
		{"Test", []string{"hello.example.test"}, 90 * oneDay, false},
		{"Test with multiple certificates", []string{"example.test", "world.example.test"}, 90 * oneDay, false},
		{"Test with wildcard certificate", []string{"example.test", "*.example.test"}, 90 * oneDay, false},
		{"Test with wildcard certificate and short validity", []string{"example2.test", "*.example2.test"}, 15 * oneDay, true},
	}

	n := time.Now()

	for _, i := range tests {
		t.Run(i.name, func(t *testing.T) {
			service, db2 := setupPebbleTest(t, serverTls)
			defer deconstructPebbleTest(t, service)
			//goland:noinspection SqlWithoutWhere
			_, err := db2.Exec("DELETE FROM certificate_domains")
			assert.NoError(t, err)

			if i.short {
				service.certProfile = "short"
			} else {
				service.certProfile = "default"
			}

			_, err = db2.Exec(`INSERT INTO certificates (dns, auto_renew, active, renewing, renew_retry, not_after, updated_at, common_name, renew_at) VALUES (1, 1, 1, 0, '2000-01-01 00:00:00+00:00', '2000-01-01 00:00:00+00:00', '2000-01-01 00:00:00+00:00', ?, ?);`, i.domains[0], n.Add(-time.Hour))
			assert.NoError(t, err)
			for _, j := range i.domains {
				_, err = db2.Exec(`INSERT INTO certificate_domains (cert_id, domain) VALUES (1, ?)`, j)
				assert.NoError(t, err)
			}

			query, err := db2.Query("SELECT cert_id, domain from certificate_domains")
			assert.NoError(t, err)
			for query.Next() {
				var a uint64
				var b string
				assert.NoError(t, query.Scan(&a, &b))
			}

			assert.NoError(t, service.renewalCheck())
			certFilePath := filepath.Join(service.certDir, fmt.Sprintf("1-%s.crt", i.domains[0]))
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

			fmt.Println("not before:", outCert.NotBefore)
			fmt.Println("not after:", outCert.NotAfter)

			// Validate the cert duration is within an hour of the expected duration
			dur := outCert.NotAfter.Sub(outCert.NotBefore)
			fmt.Printf("cert duration: %v (%v days)\n", dur, dur.Hours()/24)
			assert.True(t, dur > (i.dur-time.Hour) && dur < (i.dur+time.Hour))

			query2, err := db2.Query("SELECT id, renew_at from certificates")
			assert.NoError(t, err)
			for query2.Next() {
				var a uint64
				var b nulls.Time
				assert.NoError(t, query2.Scan(&a, &b))

				assert.True(t, b.Valid, "time must be valid")

				renewStart := outCert.NotAfter.Add(-(dur / 3)).Add(-(dur / 15))
				renewEnd := outCert.NotAfter
				assert.True(t, b.Time.After(renewStart), "renew time %v should be after %v", b.Time, renewStart)
				assert.True(t, b.Time.Before(renewEnd), "renew time %v should be before %v", b.Time, renewEnd)

				fmt.Println("renew:", b.Time)
				fmt.Println("start:", renewStart)
				fmt.Println("end:", renewEnd)
			}
		})
	}
}
