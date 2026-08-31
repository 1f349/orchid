ALTER TABLE certificates
    ADD COLUMN renew_at DATETIME;

UPDATE certificates
SET renew_at = DATETIME(not_after, 'utc', '-30 days')
WHERE certificates.renew_at IS NULL;
