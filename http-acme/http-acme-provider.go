package http_acme

import (
	"encoding/json"
	"fmt"
	"github.com/go-acme/lego/v4/challenge"
	"net/http"
	"strings"
)

var _ challenge.Provider = &HttpAcmeProvider{}

// HttpAcmeProvider sends HTTP requests to an API updating the outputted
// `.wellknown/acme-challenges` data
type HttpAcmeProvider struct {
	accessToken, refreshToken    string
	apiUrlPresent, apiUrlCleanUp string
	apiUrlRefreshToken           string
	trip                         http.RoundTripper
}

// NewHttpAcmeProvider creates a new HttpAcmeProvider using http.DefaultTransport
// as the transport
func NewHttpAcmeProvider(accessToken, refreshToken, apiUrlPresent, apiUrlCleanUp, apiUrlRefreshToken string) *HttpAcmeProvider {
	return &HttpAcmeProvider{accessToken, refreshToken, apiUrlPresent, apiUrlCleanUp, apiUrlRefreshToken, http.DefaultTransport}
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
	v := strings.NewReplacer("%domain%", domain, "%token%", token, "%content%", keyAuth).Replace(url)
	req, err := http.NewRequest(method, v, nil)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("Authorization", "Bearer "+h.accessToken)
	return h.trip.RoundTrip(req)
}
