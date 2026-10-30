package renewal

import (
	"crypto"
	"github.com/go-acme/lego/v5/acme"
)

// Account stores the information required for the lego library to use the
// LetsEncrypt account details.
type Account struct {
	email string
	reg   *acme.ExtendedAccount
	key   crypto.Signer
}

func (a *Account) GetEmail() string                       { return a.email }
func (a *Account) GetRegistration() *acme.ExtendedAccount { return a.reg }
func (a *Account) GetPrivateKey() crypto.Signer           { return a.key }
