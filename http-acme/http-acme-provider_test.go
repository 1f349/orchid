package http_acme

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/MrMelon54/mjwt"
	"github.com/MrMelon54/mjwt/auth"
	"github.com/MrMelon54/mjwt/claims"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type fakeTransport struct {
	verify mjwt.Verifier
	req    *http.Request
	clean  bool
}

func (f *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	bearer := req.Header.Get("Authorization")
	if !strings.HasPrefix(bearer, "Bearer ") {
		return nil, fmt.Errorf("invalid bearer token")
	}
	_, b, err := mjwt.ExtractClaims[auth.AccessTokenClaims](f.verify, bearer[7:])
	if err != nil {
		return nil, err
	}

	// check perms
	if !f.clean && !b.Claims.Perms.Has("test:acme:present") {
		return nil, fmt.Errorf("missing perm 'test:acme:present'")
	}
	if f.clean && !b.Claims.Perms.Has("test:acme:clean") {
		return nil, fmt.Errorf("missing perm 'test:acme:clean'")
	}
	rec := httptest.NewRecorder()
	rec.WriteHeader(http.StatusOK)
	f.req = req
	return rec.Result(), nil
}

func TestHttpAcmeProvider_Present(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	// perms
	ps := claims.NewPermStorage()
	ps.Set("test:acme:present")

	// signer
	signer := mjwt.NewMJwtSigner("Test", privateKey)
	accessToken, err := signer.GenerateJwt("", "", nil, 5*time.Minute, auth.AccessTokenClaims{Perms: ps})
	assert.NoError(t, err)

	ft := &fakeTransport{verify: signer}
	prov := &HttpAcmeProvider{
		accessToken,
		"",
		"https://api.example.com/acme/present/%domain%/%token%/%content%",
		"https://api.example.com/acme/clean/%domain%/%token%",
		ft,
	}
	assert.NoError(t, prov.Present("example.com", "1234", "1234abcd"))
	assert.Equal(t, *ft.req.URL, url.URL{
		Scheme: "https",
		Host:   "api.example.com",
		Path:   "/acme/present/example.com/1234/1234abcd",
	})
}

func TestHttpAcmeProvider_CleanUp(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	// perms
	ps := claims.NewPermStorage()
	ps.Set("test:acme:clean")

	// signer
	signer := mjwt.NewMJwtSigner("Test", privateKey)
	accessToken, err := signer.GenerateJwt("", "", nil, 5*time.Minute, auth.AccessTokenClaims{Perms: ps})
	assert.NoError(t, err)

	ft := &fakeTransport{verify: signer, clean: true}
	prov := &HttpAcmeProvider{
		accessToken,
		"",
		"https://api.example.com/acme/present/%domain%/%token%/%content%",
		"https://api.example.com/acme/clean/%domain%/%token%",
		ft,
	}
	assert.NoError(t, prov.CleanUp("example.com", "1234", "1234abcd"))
	assert.Equal(t, *ft.req.URL, url.URL{
		Scheme: "https",
		Host:   "api.example.com",
		Path:   "/acme/clean/example.com/1234",
	})
}
