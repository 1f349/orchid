package renewal

import (
	"time"
)

// Contains local types for the renewal service
type localCertData struct {
	id       int64
	notAfter time.Time
	domains  []string
}
