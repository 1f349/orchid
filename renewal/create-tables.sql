CREATE TABLE IF NOT EXISTS certificates
(
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    owner        INTEGER,
    dns          INTEGER,
    auto_renew   INTEGER DEFAULT 0,
    active       INTEGER DEFAULT 0,
    renewing     INTEGER DEFAULT 0,
    renew_failed INTEGER DEFAULT 0,
    not_after    DATETIME,
    updated_at   DATETIME,
    FOREIGN KEY (dns) REFERENCES dns (id)
);

CREATE TABLE IF NOT EXISTS certificate_domains
(
    domain_id INTEGER PRIMARY KEY AUTOINCREMENT,
    cert_id   INTEGER,
    domain    VARCHAR,
    FOREIGN KEY (cert_id) REFERENCES certificates (id)
);

CREATE TABLE IF NOT EXISTS dns
(
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    type  VARCHAR,
    email VARCHAR,
    token VARCHAR
);
