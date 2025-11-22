ALTER TABLE certificates
    ADD COLUMN authority INTEGER NOT NULL DEFAULT 1; -- Default to LetsEncrypt
ALTER TABLE certificates
    ADD COLUMN country TEXT NOT NULL DEFAULT '';
ALTER TABLE certificates
    ADD COLUMN org TEXT NOT NULL DEFAULT '';
ALTER TABLE certificates
    ADD COLUMN org_unit TEXT NOT NULL DEFAULT '';
ALTER TABLE certificates
    ADD COLUMN locality TEXT NOT NULL DEFAULT '';
ALTER TABLE certificates
    ADD COLUMN province TEXT NOT NULL DEFAULT '';
ALTER TABLE certificates
    ADD COLUMN details_updated_at DATETIME NOT NULL DEFAULT updated_at;
