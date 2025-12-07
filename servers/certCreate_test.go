package servers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/1f349/mjwt/auth"
	"github.com/1f349/orchid/database"
	"github.com/1f349/orchid/database/types"
	"github.com/golang-jwt/jwt/v4"
	"github.com/julienschmidt/httprouter"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestSubject(t *testing.T) {
	assert.Equal(t, "invalid common name .., expected a valid fully qualified domain name", Subject{CommonName: ".."}.Validate().Error())
	assert.Equal(t, "invalid country USA, expected 2 characters", Subject{CommonName: ".", Country: "USA"}.Validate().Error())
	assert.NoError(t, Subject{CommonName: ".", Country: "US"}.Validate())
}

type testCertCreateQueries struct{}

func (t *testCertCreateQueries) AddCertificate(ctx context.Context, opts database.AddCertificateParams) (int64, error) {
	if opts.CommonName != "example.com" {
		return 0, fmt.Errorf("database insert failed")
	}
	return 1, nil
}

func (t *testCertCreateQueries) AddCertificateOwner(ctx context.Context, opts database.AddCertificateOwnerParams) error {
	if opts.Owner != "user1234" || opts.CertID != 1 {
		return fmt.Errorf("database insert failed")
	}
	return nil
}

func (t *testCertCreateQueries) AddDomains(ctx context.Context, arg database.AddDomainsParams) error {
	if arg.Domain != "example.com" && arg.CertID != 1 && arg.State != 0 {
		return fmt.Errorf("database insert failed")
	}
	return nil
}

func (t *testCertCreateQueries) UseTx(ctx context.Context, cb func(tx *database.Queries) error) error {
	// TODO: Implement this UseTx call properly
	return nil
}

func TestCertCreate(t *testing.T) {
	t.Run("Empty body", func(t *testing.T) {
		rec := httptest.NewRecorder()
		s := strings.Repeat("1234", 1024*1024/4) + "1"
		req := httptest.NewRequest(http.MethodPost, "/cert", strings.NewReader(s))
		certCreate(rec, req, httprouter.Params{}, AuthClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: "user1234",
			},
		}, &testCertCreateQueries{})
		res := rec.Result()
		assert.Equal(t, http.StatusRequestEntityTooLarge, res.StatusCode)
		assert.Equal(t, "Request Entity Too Large\n", rec.Body.String())
	})
	t.Run("Empty body", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/cert", nil)
		certCreate(rec, req, httprouter.Params{}, AuthClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: "user1234",
			},
		}, &testCertCreateQueries{})
		res := rec.Result()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		assert.Equal(t, "Failed to parse body\n", rec.Body.String())
	})
	t.Run("Valid JSON but invalid values", func(t *testing.T) {
		rec := httptest.NewRecorder()
		var buf bytes.Buffer
		assert.NoError(t, json.NewEncoder(&buf).Encode(PostCertOptions{
			Name:      "1f349.com Certificate",
			Authority: types.AuthorityLetsEncrypt,
			AutoRenew: true,
			Subject: Subject{
				CommonName: "example.com",
				Country:    "USA",
				Org:        "Internet Corporation for Assigned Names and Numbers",
				Locality:   "Los Angeles",
				Province:   "California",
			},
			Domains: []string{
				"example.com",
				"*.example.com",
			},
			Addresses: []netip.Addr{
				netip.MustParseAddr("192.0.2.1"),
				netip.MustParseAddr("2001:db8::1"),
			},
		}))
		req := httptest.NewRequest(http.MethodPost, "/cert", bytes.NewReader(buf.Bytes()))
		certCreate(rec, req, httprouter.Params{}, AuthClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: "user1234",
			},
		}, &testCertCreateQueries{})
		res := rec.Result()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		assert.Equal(t, "Failed to validate subject: invalid country USA, expected 2 characters\n", rec.Body.String())
	})
	t.Run("Valid request", func(t *testing.T) {
		rec := httptest.NewRecorder()
		var buf bytes.Buffer
		assert.NoError(t, json.NewEncoder(&buf).Encode(PostCertOptions{
			Name:      "Example.com Certificate",
			Authority: types.AuthorityLetsEncrypt,
			AutoRenew: true,
			Subject: Subject{
				CommonName: "example.com",
				Country:    "US",
				Org:        "Internet Corporation for Assigned Names and Numbers",
				Locality:   "Los Angeles",
				Province:   "California",
			},
			Domains: []string{
				"example.com",
				"*.example.com",
			},
			Addresses: []netip.Addr{
				netip.MustParseAddr("192.0.2.1"),
				netip.MustParseAddr("2001:db8::1"),
			},
		}))
		req := httptest.NewRequest(http.MethodPost, "/cert", bytes.NewReader(buf.Bytes()))
		certCreate(rec, req, httprouter.Params{}, AuthClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: "user1234",
			},
			Claims: auth.AccessTokenClaims{Perms: auth.ParsePermStorage("domain:owns=example.com domain:owns=2.0.192.in-addr.arpa domain:owns=8.B.D.0.1.0.0.2.ip6.arpa")},
		}, &testCertCreateQueries{})
		res := rec.Result()
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, "{\"result\":\"Added certificate\"}\n", rec.Body.String())
	})
	t.Run("Database error", func(t *testing.T) {
		rec := httptest.NewRecorder()
		var buf bytes.Buffer
		assert.NoError(t, json.NewEncoder(&buf).Encode(PostCertOptions{
			Name:      "Example.com Certificate",
			Authority: types.Authority(255),
			AutoRenew: true,
			Subject: Subject{
				CommonName: "example.com",
				Country:    "US",
			},
			Domains: []string{
				"example.com",
				"*.example.com",
			},
			Addresses: []netip.Addr{
				netip.MustParseAddr("192.0.2.1"),
				netip.MustParseAddr("2001:db8::1"),
			},
		}))
		req := httptest.NewRequest(http.MethodPost, "/cert", bytes.NewReader(buf.Bytes()))
		certCreate(rec, req, httprouter.Params{}, AuthClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: "user1234",
			},
			Claims: auth.AccessTokenClaims{Perms: auth.ParsePermStorage("domain:owns=example.com domain:owns=2.0.192.in-addr.arpa domain:owns=8.b.d.0.1.0.0.2.ip6.arpa")},
		}, &testCertCreateQueries{})
		res := rec.Result()
		assert.Equal(t, http.StatusInternalServerError, res.StatusCode)
		assert.Equal(t, "Failed to add certificate to the database\n", rec.Body.String())
	})
}
