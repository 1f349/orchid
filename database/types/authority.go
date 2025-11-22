package types

type Authority uint8

const (
	AuthorityLetsEncrypt Authority = 1
	AuthorityCustom      Authority = 2
	AuthorityDN42        Authority = 3
)

func (a Authority) String() string {
	switch a {
	case AuthorityLetsEncrypt:
		return "Lets Encrypt"
	case AuthorityCustom:
		return "Custom"
	case AuthorityDN42:
		return "DN42"
	default:
		return "<Unknown Authority>"
	}
}
