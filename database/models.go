// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0

package database

import (
	"database/sql"
	"time"
)

type Certificate struct {
	ID         int64         `json:"id"`
	Owner      string        `json:"owner"`
	Dns        sql.NullInt64 `json:"dns"`
	AutoRenew  bool          `json:"auto_renew"`
	Active     bool          `json:"active"`
	Renewing   bool          `json:"renewing"`
	NotAfter   time.Time     `json:"not_after"`
	UpdatedAt  time.Time     `json:"updated_at"`
	TempParent sql.NullInt64 `json:"temp_parent"`
	RenewRetry time.Time     `json:"renew_retry"`
}

type CertificateDomain struct {
	DomainID int64  `json:"domain_id"`
	CertID   int64  `json:"cert_id"`
	Domain   string `json:"domain"`
	State    int64  `json:"state"`
}

type DnsAcme struct {
	ID    int64  `json:"id"`
	Type  string `json:"type"`
	Email string `json:"email"`
	Token string `json:"token"`
}
