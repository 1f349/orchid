package renewal

import "time"

// Contains local types for the renewal service
type localCertData struct {
	id  uint64
	dns struct {
		name  string
		token string
	}
	cert struct {
		current  uint64
		notAfter time.Time
	}
	domains []string
}
