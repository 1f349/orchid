package utils

import (
	"github.com/1f349/violet/utils"
	"slices"
)

type DomainChecker []string

func (d DomainChecker) ValidateDomain(a string) bool {
	if fqdn, ok := utils.GetTopFqdn(a); ok {
		if slices.Contains(d, fqdn) {
			return true
		}
	}
	return false
}
