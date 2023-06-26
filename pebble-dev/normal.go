//go:build !DEBUG

package pebble_dev

import "log"

func GetPebbleCert() []byte {
	log.Fatalln("[Renewal] Pebble is selected as the certificate source but this binary was not compiled in debug mode")
	return nil
}
