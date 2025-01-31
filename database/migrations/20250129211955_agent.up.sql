CREATE TABLE IF NOT EXISTS agents
(
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    address     TEXT     NOT NULL,
    user        TEXT     NOT NULL,
    dir         TEXT     NOT NULL,
    fingerprint TEXT     NOT NULL,
    last_sync   DATETIME NULL DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS agent_certs
(
    agent_id  INTEGER NOT NULL,
    cert_id   INTEGER NOT NULL,
    not_after INTEGER NULL DEFAULT NULL,

    PRIMARY KEY (agent_id, cert_id),

    FOREIGN KEY (agent_id) REFERENCES agents (id),
    FOREIGN KEY (cert_id) REFERENCES certificates (id)
);
