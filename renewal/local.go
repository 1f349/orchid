package renewal

import (
	"database/sql"
	"time"
)

// Contains local types for the renewal service
type localCertData struct {
	id  int64
	dns struct {
		name  sql.NullString
		token sql.NullString
	}
	notAfter   time.Time
	domains    []string
	tempParent sql.NullInt64
}
