package renewal

import (
	"crypto"
	"github.com/go-acme/lego/v4/registration"
)

// Account stores the information required for the lego library to use the
// LetsEncrypt account details.
type Account struct {
	email string
	reg   *registration.Resource
	key   crypto.PrivateKey
}

func (a *Account) GetEmail() string                        { return a.email }
func (a *Account) GetRegistration() *registration.Resource { return a.reg }
func (a *Account) GetPrivateKey() crypto.PrivateKey        { return a.key }
