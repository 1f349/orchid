select cert.id, cert.auto_renew, cert.active, cert.renewing, cert.renew_failed, cert.not_after, cert.updated_at, certificate_domains.domain
from certificates as cert
    inner join certificate_domains on cert.id = certificate_domains.cert_id
