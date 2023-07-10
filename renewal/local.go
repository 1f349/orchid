package renewal

import (
	"database/sql"
)

// Contains local types for the renewal service
type localCertData struct {
	id  uint64
	dns struct {
		name  sql.NullString
		token sql.NullString
	}
	notAfter   sql.NullTime
	domains    []string
	tempParent uint64
}
