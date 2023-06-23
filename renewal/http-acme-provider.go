package renewal

import (
	"fmt"
	"github.com/go-acme/lego/v4/challenge"
	"net/http"
	"strings"
)

var _ challenge.Provider = &HttpAcmeProvider{}

type HttpAcmeProvider struct {
	accessToken, refreshToken    string
	apiUrlPresent, apiUrlCleanUp string
	trip                         http.RoundTripper
}

func NewCustomHTTPProvider(accessToken, refreshToken, apiUrlPresent, apiUrlCleanUp string) *HttpAcmeProvider {
	return &HttpAcmeProvider{accessToken, refreshToken, apiUrlPresent, apiUrlCleanUp, http.DefaultTransport}
}

func (h *HttpAcmeProvider) Present(domain, token, keyAuth string) error {
	v := strings.NewReplacer("%domain%", domain, "%token%", token, "%content%", keyAuth).Replace(h.apiUrlPresent)
	req, err := http.NewRequest(http.MethodPut, v, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+h.accessToken)

	// round trip
	trip, err := h.trip.RoundTrip(req)
	if err != nil {
		return err
	}
	if trip.StatusCode != http.StatusOK {
		return fmt.Errorf("Trip response status code was not 200")
	}
	return nil
}

func (h *HttpAcmeProvider) CleanUp(domain, token, keyAuth string) error {
	v := strings.NewReplacer("%domain%", domain, "%token%", token, "%content%", keyAuth).Replace(h.apiUrlCleanUp)
	req, err := http.NewRequest(http.MethodPut, v, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+h.accessToken)

	// round trip
	trip, err := h.trip.RoundTrip(req)
	if err != nil {
		return err
	}
	if trip.StatusCode != http.StatusOK {
		return fmt.Errorf("Trip response status code was not 200")
	}
	return nil
}
