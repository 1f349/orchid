ALTER TABLE certificates
    DROP COLUMN renew_failed;

ALTER TABLE certificates
    ADD COLUMN renew_retry DATETIME NOT NULL DEFAULT 0;
