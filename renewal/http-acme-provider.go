package renewal

import (
	"github.com/go-acme/lego/v4/challenge"
)

var _ challenge.Provider = &HttpAcmeProvider{}

type HttpAcmeProvider struct {
	accessToken, refreshToken    string
	apiUrlPresent, apiUrlCleanUp string
}

func NewCustomHTTPProvider(accessToken, refreshToken, apiUrlPresent, apiUrlCleanUp string) *HttpAcmeProvider {
	return &HttpAcmeProvider{accessToken, refreshToken, apiUrlPresent, apiUrlCleanUp}
}

func (h *HttpAcmeProvider) Present(domain, token, keyAuth string) error {
	//TODO implement me
	panic("implement me")
}

func (h *HttpAcmeProvider) CleanUp(domain, token, keyAuth string) error {
	//TODO implement me
	panic("implement me")
}
