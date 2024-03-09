-- name: FindNextCert :one
SELECT cert.id, cert.not_after, dns_acme.type, dns_acme.token, cert.temp_parent
FROM certificates AS cert
         LEFT OUTER JOIN dns_acme ON cert.dns = dns_acme.id
WHERE cert.active = 1
  AND (cert.auto_renew = 1 OR cert.not_after IS NULL)
  AND cert.renewing = 0
  AND cert.renew_failed = 0
  AND (cert.not_after IS NULL OR DATETIME(cert.not_after, 'utc', '-30 days') < DATETIME())
ORDER BY cert.temp_parent, cert.not_after DESC NULLS FIRST
LIMIT 1;

-- name: FindOwnedCerts :many
SELECT cert.id,
       cert.auto_renew,
       cert.active,
       cert.renewing,
       cert.renew_failed,
       cert.not_after,
       cert.updated_at,
       certificate_domains.domain
FROM certificates AS cert
         INNER JOIN certificate_domains ON cert.id = certificate_domains.cert_id;

-- name: UpdateRenewingState :exec
UPDATE certificates
SET renewing     = ?,
    renew_failed = ?
WHERE id = ?;

-- name: UpdateCertAfterRenewal :exec
UPDATE certificates
SET renewing    = 0,
    renew_failed=0,
    not_after=?,
    updated_at=?
WHERE id = ?;

-- name: AddCertificate :exec
INSERT INTO certificates (owner, dns, not_after, updated_at)
VALUES (?, ?, ?, ?);

-- name: RemoveCertificate :exec
UPDATE certificates
SET active = 0
WHERE id = ?;

-- name: CheckCertOwner :one
SELECT id, owner
FROM certificates
WHERE active = 1
  and id = ?;
