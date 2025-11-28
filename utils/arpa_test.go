package utils

import (
	"github.com/stretchr/testify/assert"
	"net/netip"
	"testing"
)

func TestConvertAddrToArpa(t *testing.T) {
	assert.Equal(t, "28.2.0.192.in-addr.arpa", ConvertAddrToArpa(netip.MustParseAddr("192.0.2.28")))
	assert.Equal(t, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", ConvertAddrToArpa(netip.MustParseAddr("2001:db8::1")))
}

func TestParseArpaToAddr(t *testing.T) {
	prefix, err := ParseArpaToPrefix("2.0.192.in-addr.arpa")
	assert.NoError(t, err)
	assert.Equal(t, netip.MustParsePrefix("192.0.2.0/24"), prefix)
	prefix, err = ParseArpaToPrefix("0.0.0.0.8.B.D.0.1.0.0.2.ip6.arpa")
	assert.NoError(t, err)
	prefix, err = ParseArpaToPrefix("0_27.2.0.192.in-addr.arpa")
	assert.NoError(t, err)
	assert.Equal(t, netip.MustParsePrefix("192.0.2.0/27"), prefix)
	prefix, err = ParseArpaToPrefix("0_33.8.B.D.0.1.0.0.2.ip6.arpa")
	assert.NoError(t, err)
	assert.Equal(t, netip.MustParsePrefix("2001:db8::/33"), prefix)
}
