CREATE TABLE IF NOT EXISTS owners
(
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    owner   VARCHAR NOT NULL,
    cert_id INTEGER NOT NULL,
    UNIQUE (owner, cert_id),
    FOREIGN KEY (cert_id) REFERENCES certificates (id)
);

INSERT INTO owners(owner, cert_id)
SELECT owner, id
FROM certificates;

ALTER TABLE certificates
    DROP COLUMN owner;
