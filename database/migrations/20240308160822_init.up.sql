CREATE TABLE IF NOT EXISTS certificates
(
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    owner        VARCHAR  NOT NULL,
    dns          INTEGER,
    auto_renew   BOOLEAN  NOT NULL DEFAULT 0,
    active       BOOLEAN  NOT NULL DEFAULT 0,
    renewing     BOOLEAN  NOT NULL DEFAULT 0,
    renew_failed BOOLEAN  NOT NULL DEFAULT 0,
    not_after    DATETIME NOT NULL,
    updated_at   DATETIME NOT NULL,
    temp_parent  INTEGER,
    FOREIGN KEY (dns) REFERENCES dns_acme (id),
    FOREIGN KEY (temp_parent) REFERENCES certificates (id)
);

CREATE TABLE IF NOT EXISTS certificate_domains
(
    domain_id INTEGER PRIMARY KEY AUTOINCREMENT,
    cert_id   INTEGER NOT NULL,
    domain    VARCHAR NOT NULL,
    state     INTEGER NOT NULL DEFAULT 1,
    UNIQUE (cert_id, domain),
    FOREIGN KEY (cert_id) REFERENCES certificates (id)
);

CREATE TABLE IF NOT EXISTS dns_acme
(
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    type  VARCHAR NOT NULL,
    email VARCHAR NOT NULL,
    token VARCHAR NOT NULL
);
