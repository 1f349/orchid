package test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/go-acme/lego/v4/challenge"
	"net/http"
)

// fakeAcmeProv an acme provider to emulate
type fakeAcmeProv struct {
	t http.RoundTripper
}

func MakeFakeAcmeProv(cert []byte) interface {
	challenge.Provider
	http.RoundTripper
} {
	cp := x509.NewCertPool()
	cp.AppendCertsFromPEM(cert)
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{RootCAs: cp}
	return &fakeAcmeProv{t: t}
}

func (f *fakeAcmeProv) Present(string, string, string) error { return nil }
func (f *fakeAcmeProv) CleanUp(string, string, string) error { return nil }
func (f *fakeAcmeProv) RoundTrip(req *http.Request) (*http.Response, error) {
	// use transport with custom CertPool for pebble requests
	if req.URL.Host == "localhost:14000" {
		return f.t.RoundTrip(req)
	}
	return nil, fmt.Errorf("invalid fakeAcmeProv.RoundTrip call to '%s'", req.URL.String())
}
