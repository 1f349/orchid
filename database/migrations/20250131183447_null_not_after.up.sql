-- null not after

ALTER TABLE certificates
    RENAME COLUMN not_after TO not_after_2;

ALTER TABLE certificates
    ADD COLUMN not_after DATETIME NULL;

UPDATE certificates
SET not_after = not_after_2
WHERE not_after IS NULL;

ALTER TABLE certificates
    DROP COLUMN not_after_2;

-- null renew retry

ALTER TABLE certificates
    RENAME COLUMN renew_retry TO renew_retry_2;

ALTER TABLE certificates
    ADD COLUMN renew_retry DATETIME NULL;

UPDATE certificates
SET renew_retry = renew_retry_2
WHERE renew_retry IS NULL;

ALTER TABLE certificates
    DROP COLUMN renew_retry_2;
