package utils

import "github.com/MrMelon54/violet/utils"

type DomainChecker []string

func (d DomainChecker) ValidateDomain(a string) bool {
	if fqdn, ok := utils.GetTopFqdn(a); ok {
		for _, i := range d {
			if i == fqdn {
				return true
			}
		}
	}
	return false
}
