select cert.id, cert.not_after, dns_acme.type, dns_acme.token, cert.temp_parent
from certificates as cert
         left outer join dns_acme on cert.dns = dns_acme.id
where cert.active = 1
  and (cert.auto_renew = 1 or cert.not_after IS NULL)
  and cert.renewing = 0
  and cert.renew_failed = 0
  and (cert.not_after IS NULL or DATETIME(cert.not_after, 'utc', '-30 days') < DATETIME())
order by cert.temp_parent, cert.not_after DESC NULLS FIRST
