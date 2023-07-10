CREATE TABLE IF NOT EXISTS certificates
(
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    owner        VARCHAR,
    dns          INTEGER,
    auto_renew   INTEGER DEFAULT 0,
    active       INTEGER DEFAULT 0,
    renewing     INTEGER DEFAULT 0,
    renew_failed INTEGER DEFAULT 0,
    not_after    DATETIME,
    updated_at   DATETIME,
    temp_parent  INTEGER DEFAULT 0,
    FOREIGN KEY (dns) REFERENCES dns_acme (id),
    FOREIGN KEY (temp_parent) REFERENCES certificates (id)
);

CREATE TABLE IF NOT EXISTS certificate_domains
(
    domain_id INTEGER PRIMARY KEY AUTOINCREMENT,
    cert_id   INTEGER,
    domain    VARCHAR,
    state     INTEGER DEFAULT 1,
    UNIQUE (cert_id, domain),
    FOREIGN KEY (cert_id) REFERENCES certificates (id)
);

CREATE TABLE IF NOT EXISTS dns_acme
(
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    type  VARCHAR,
    email VARCHAR,
    token VARCHAR
);
