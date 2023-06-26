select cert.id, certdata.data_id, certdata.not_after, dns.type, dns.token
from certificates as cert
         left outer join certificate_data as certdata on cert.id = certdata.meta_id
         left outer join dns on cert.dns = dns.id
where cert.active = 1
  and cert.auto_renew = 1
  and cert.renewing = 0
  and cert.renew_failed = 0
  and (certdata.ready IS NULL or certdata.ready = 1)
  and (certdata.not_after IS NULL or DATETIME(certdata.not_after, 'utc', '-30 days') < DATETIME())
order by certdata.not_after DESC NULLS FIRST
