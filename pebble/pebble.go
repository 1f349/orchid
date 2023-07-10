//go:build !DEBUG

package pebble

import _ "embed"

var (
	//go:embed pebble-cert.pem
	RawCert []byte
	//go:embed pebble-config.json
	RawConfig []byte
)
