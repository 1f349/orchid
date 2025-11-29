-- name: FindNextCert :one
SELECT cert.id, cert.not_after, dns_acme.type, dns_acme.token
FROM certificates AS cert
         LEFT OUTER JOIN dns_acme ON cert.dns = dns_acme.id
WHERE cert.active = 1
  AND (cert.auto_renew = 1 OR cert.not_after IS NULL)
  AND cert.renewing = 0
  AND (cert.renew_retry IS NULL OR DATETIME() > DATETIME(cert.renew_retry))
  AND (cert.not_after IS NULL OR DATETIME(cert.not_after, 'utc', '-30 days') < DATETIME())
ORDER BY cert.not_after DESC NULLS FIRST
LIMIT 1;

-- name: FindOwnedCerts :many
SELECT cert.id,
       cert.name,
       cert.authority,
       cert.auto_renew,
       cert.active,
       cert.renewing,
       cert.renew_retry,
       cert.not_after,
       cert.updated_at,
       cert.common_name,
       cert.country,
       cert.org,
       cert.org_unit,
       cert.locality,
       cert.province,
       certificate_domains.domain
FROM certificates AS cert
         LEFT JOIN certificate_domains ON cert.id = certificate_domains.cert_id
         INNER JOIN owners ON owners.cert_id = cert.id
WHERE owners.owner = ?;

-- name: UpdateRenewingState :exec
UPDATE certificates
SET renewing    = ?,
    renew_retry = ?
WHERE id = ?;

-- name: TriggerManualRenew :exec
UPDATE certificates
SET renew_retry = DATETIME('now'),
    not_after   = NULL
WHERE id = ?;

-- name: SetRetryFlag :exec
UPDATE certificates
SET renew_retry = DATETIME('now', '+1 day')
WHERE id = ?;

-- name: UpdateCertAfterRenewal :exec
UPDATE certificates
SET renewing    = 0,
    renew_retry = 0,
    not_after   = ?,
    updated_at  = ?
WHERE id = ?;

-- name: AddCertificate :execlastid
INSERT INTO certificates (name, auto_renew, active, dns, not_after, updated_at, authority, common_name, country, org,
                          org_unit, locality, province)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: AddCertificateOwner :exec
INSERT INTO owners (owner, cert_id)
VALUES (?, ?);

-- name: ChangeCertificateDetails :exec
UPDATE certificates
SET country            = ?,
    org                = ?,
    org_unit           = ?,
    locality           = ?,
    province           = ?,
    details_updated_at = DATETIME()
WHERE id = ?;

-- name: RemoveCertificate :exec
UPDATE certificates
SET active = 0
WHERE id = ?;

-- name: CheckCertOwner :one
SELECT cert.id
FROM certificates AS cert
         INNER JOIN owners ON owners.cert_id = cert.id
WHERE cert.active = 1
  AND cert.id = ?
  AND owners.owner = ?
LIMIT 1;

-- name: SetCertificateAutoRenew :exec
UPDATE certificates
SET auto_renew = ?
WHERE id = ?;
