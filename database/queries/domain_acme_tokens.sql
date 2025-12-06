-- name: FindDomainAcmeToken :many
SELECT * FROM dns_api_tokens WHERE domain LIKE CONCAT('%', CAST(? AS TEXT));
