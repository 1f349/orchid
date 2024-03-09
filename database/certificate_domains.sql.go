// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0
// source: certificate_domains.sql

package database

import (
	"context"
	"strings"
)

const addDomains = `-- name: AddDomains :exec
INSERT INTO certificate_domains (cert_id, domain, state)
VALUES (?, ?, ?)
`

type AddDomainsParams struct {
	CertID int64  `json:"cert_id"`
	Domain string `json:"domain"`
	State  int64  `json:"state"`
}

func (q *Queries) AddDomains(ctx context.Context, arg AddDomainsParams) error {
	_, err := q.db.ExecContext(ctx, addDomains, arg.CertID, arg.Domain, arg.State)
	return err
}

const getDomainStatesForCert = `-- name: GetDomainStatesForCert :many
SELECT domain, state
FROM certificate_domains
WHERE cert_id = ?
`

type GetDomainStatesForCertRow struct {
	Domain string `json:"domain"`
	State  int64  `json:"state"`
}

func (q *Queries) GetDomainStatesForCert(ctx context.Context, certID int64) ([]GetDomainStatesForCertRow, error) {
	rows, err := q.db.QueryContext(ctx, getDomainStatesForCert, certID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []GetDomainStatesForCertRow
	for rows.Next() {
		var i GetDomainStatesForCertRow
		if err := rows.Scan(&i.Domain, &i.State); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getDomainsForCertificate = `-- name: GetDomainsForCertificate :many
SELECT domain
FROM certificate_domains
WHERE cert_id = ?
`

func (q *Queries) GetDomainsForCertificate(ctx context.Context, certID int64) ([]string, error) {
	rows, err := q.db.QueryContext(ctx, getDomainsForCertificate, certID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		items = append(items, domain)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const setDomainStateForCert = `-- name: SetDomainStateForCert :exec
UPDATE certificate_domains
SET state = ?
WHERE cert_id = ?
`

type SetDomainStateForCertParams struct {
	State  int64 `json:"state"`
	CertID int64 `json:"cert_id"`
}

func (q *Queries) SetDomainStateForCert(ctx context.Context, arg SetDomainStateForCertParams) error {
	_, err := q.db.ExecContext(ctx, setDomainStateForCert, arg.State, arg.CertID)
	return err
}

const updateDomains = `-- name: UpdateDomains :exec
UPDATE certificate_domains
SET state = ?
WHERE domain IN (/*SLICE:domains*/?)
`

type UpdateDomainsParams struct {
	State   int64    `json:"state"`
	Domains []string `json:"domains"`
}

func (q *Queries) UpdateDomains(ctx context.Context, arg UpdateDomainsParams) error {
	query := updateDomains
	var queryParams []interface{}
	queryParams = append(queryParams, arg.State)
	if len(arg.Domains) > 0 {
		for _, v := range arg.Domains {
			queryParams = append(queryParams, v)
		}
		query = strings.Replace(query, "/*SLICE:domains*/?", strings.Repeat(",?", len(arg.Domains))[1:], 1)
	} else {
		query = strings.Replace(query, "/*SLICE:domains*/?", "NULL", 1)
	}
	_, err := q.db.ExecContext(ctx, query, queryParams...)
	return err
}
