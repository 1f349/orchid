//go:build !DEBUG

package pebble

import _ "embed"

var (
	//go:embed asset/pebble-cert.pem
	RawCert []byte
	//go:embed asset/pebble-config.json
	RawConfig []byte
)
