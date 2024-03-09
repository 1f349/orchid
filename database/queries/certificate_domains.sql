-- name: GetDomainsForCertificate :many
SELECT domain
FROM certificate_domains
WHERE cert_id = ?;

-- name: GetDomainStatesForCert :many
SELECT domain, state
FROM certificate_domains
WHERE cert_id = ?;

-- name: SetDomainStateForCert :exec
UPDATE certificate_domains
SET state = ?
WHERE cert_id = ?;

-- name: AddDomains :exec
INSERT INTO certificate_domains (cert_id, domain, state)
VALUES (?, ?, ?);

-- name: UpdateDomains :exec
UPDATE certificate_domains
SET state = ?
WHERE domain IN (sqlc.slice(domains));
