package http_acme

import (
	"encoding/json"
	"fmt"
	"github.com/go-acme/lego/v4/challenge"
	"gopkg.in/yaml.v3"
	"log"
	"net/http"
	"os"
	"strings"
)

var _ challenge.Provider = &HttpAcmeProvider{}

// HttpAcmeProvider sends HTTP requests to an API updating the outputted
// `.wellknown/acme-challenges` data
type HttpAcmeProvider struct {
	tokenFile                    string
	accessToken, refreshToken    string
	apiUrlPresent, apiUrlCleanUp string
	apiUrlRefreshToken           string
	trip                         http.RoundTripper
}

type AcmeLogin struct {
	Access  string `yaml:"access"`
	Refresh string `yaml:"refresh"`
}

// NewHttpAcmeProvider creates a new HttpAcmeProvider using http.DefaultTransport
// as the transport
func NewHttpAcmeProvider(tokenFile, apiUrlPresent, apiUrlCleanUp, apiUrlRefreshToken string) (*HttpAcmeProvider, error) {
	// acme login token
	openTokens, err := os.Open(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load acme tokens: %w", err)
	}

	var acmeLogins AcmeLogin
	err = yaml.NewDecoder(openTokens).Decode(&acmeLogins)
	if err != nil {
		return nil, fmt.Errorf("failed to load acme tokens: %w", err)
	}

	return &HttpAcmeProvider{tokenFile, acmeLogins.Access, acmeLogins.Refresh, apiUrlPresent, apiUrlCleanUp, apiUrlRefreshToken, http.DefaultTransport}, nil
}

// Present implements challenge.Provider and sends a put request to the specified
// path along with a bearer token to authenticate
func (h *HttpAcmeProvider) Present(domain, token, keyAuth string) error {
	// round trip
	trip, err := h.authCheckRequest(http.MethodPut, h.apiUrlPresent, domain, token, keyAuth)
	if err != nil {
		return err
	}
	if trip.StatusCode != http.StatusOK {
		return fmt.Errorf("Trip response status code was not 200")
	}
	return nil
}

// CleanUp implements challenge.Provider and sends a delete request to the
// specified path along with a bearer token to authenticate
func (h *HttpAcmeProvider) CleanUp(domain, token, keyAuth string) error {
	// round trip
	trip, err := h.authCheckRequest(http.MethodDelete, h.apiUrlCleanUp, domain, token, keyAuth)
	if err != nil {
		return err
	}
	if trip.StatusCode != http.StatusOK {
		return fmt.Errorf("Trip response status code was not 200")
	}
	return nil
}

// authCheckRequest call internalRequest and renews the access token if it is
// outdated and calls internalRequest again
func (h *HttpAcmeProvider) authCheckRequest(method, url, domain, token, keyAuth string) (*http.Response, error) {
	// call internal request and check the status code
	resp, err := h.internalRequest(method, url, domain, token, keyAuth)
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		// just return
		return resp, nil
	case http.StatusForbidden:
		// send request to get renewed access and refresh tokens
		req, err := http.NewRequest(http.MethodPost, h.apiUrlRefreshToken, nil)
		if err != nil {
			return nil, fmt.Errorf("refresh token request failed: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+h.refreshToken)

		// round trip and status check
		trip, err := h.trip.RoundTrip(req)
		if err != nil {
			return nil, fmt.Errorf("refresh token request failed: %w", err)
		}
		if trip.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("refresh token request failed: due to invalid status code, expected 200 got %d", trip.StatusCode)
		}

		// parse tokens from response body
		var tokens struct {
			Access  string `json:"access"`
			Refresh string `json:"refresh"`
		}
		if json.NewDecoder(trip.Body).Decode(&tokens) != nil {
			return nil, fmt.Errorf("refresh token parsing failed: %w", err)
		}
		h.accessToken = tokens.Access
		h.refreshToken = tokens.Refresh

		go h.saveLoginTokens()

		// call internal request again
		resp, err = h.internalRequest(method, url, domain, token, keyAuth)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusOK {
			// just return
			return resp, nil
		}
		return nil, fmt.Errorf("invalid status code, expected 200 got %d", resp.StatusCode)
	}
	// first request had an invalid status code
	return nil, fmt.Errorf("invalid status code, expected 200/403 got %d", resp.StatusCode)
}

// internalRequest sends a request to the acme challenge hosting api
func (h *HttpAcmeProvider) internalRequest(method, url, domain, token, keyAuth string) (*http.Response, error) {
	v := strings.NewReplacer("$domain", domain, "$token", token, "$content", keyAuth).Replace(url)
	req, err := http.NewRequest(method, v, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+h.accessToken)
	return h.trip.RoundTrip(req)
}

func (h *HttpAcmeProvider) saveLoginTokens() {
	// acme login token
	openTokens, err := os.Create(h.tokenFile)
	if err != nil {
		log.Println("[Orchid] Failed to open token file:", err)
	}
	defer openTokens.Close()

	err = yaml.NewEncoder(openTokens).Encode(AcmeLogin{Access: h.accessToken, Refresh: h.refreshToken})
	if err != nil {
		log.Println("[Orchid] Failed to write tokens file:", err)
	}
}
