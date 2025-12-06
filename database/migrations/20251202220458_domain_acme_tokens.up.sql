CREATE TABLE IF NOT EXISTS dns_api_tokens
(
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    domain VARCHAR NOT NULL UNIQUE,
    source VARCHAR NOT NULL,
    token  VARCHAR NOT NULL
);

INSERT INTO dns_api_tokens(domain, source, token)
SELECT email, type, token
FROM dns_acme;

DROP TABLE dns_acme;
