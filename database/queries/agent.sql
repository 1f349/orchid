-- name: FindAgentToSync :many
SELECT agents.id as agent_id, agents.address, agents.user, agents.dir, agents.fingerprint, cert.id as cert_id, cert.not_after as cert_not_after
FROM agents
         INNER JOIN agent_certs
                    ON agent_certs.agent_id = agents.id
         INNER JOIN certificates AS cert
                    ON cert.id = agent_certs.cert_id
WHERE (agents.last_sync IS NULL OR agents.last_sync < cert.updated_at)
  AND (agent_certs.not_after IS NULL OR agent_certs.not_after IS NOT cert.not_after)
ORDER BY agents.last_sync NULLS FIRST;

-- name: UpdateAgentLastSync :exec
UPDATE agents
SET last_sync = ?
WHERE agents.id = ?;

-- name: UpdateAgentCertNotAfter :exec
UPDATE agent_certs
SET not_after = ?
WHERE agent_id = ?
  AND cert_id = ?;
