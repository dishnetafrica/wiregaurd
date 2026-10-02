CREATE TABLE address_pools (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    cidr        TEXT NOT NULL UNIQUE,
    block_len   INTEGER NOT NULL DEFAULT 28,
    created_at  TEXT NOT NULL
);

CREATE TABLE customers (
    id                      INTEGER PRIMARY KEY,
    name                    TEXT NOT NULL,
    contact                 TEXT NOT NULL DEFAULT '',
    status                  TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
    subscription_expires_at TEXT,
    device_limit            INTEGER NOT NULL DEFAULT 5,
    default_ports           TEXT NOT NULL DEFAULT '3389',
    vpn_block               TEXT NOT NULL UNIQUE,
    pool_id                 INTEGER NOT NULL REFERENCES address_pools(id),
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL
);

CREATE TABLE activation_codes (
    id           INTEGER PRIMARY KEY,
    customer_id  INTEGER NOT NULL REFERENCES customers(id),
    code_hash    TEXT NOT NULL UNIQUE,
    code_hint    TEXT NOT NULL,              -- first 4 chars after the prefix, for the admin UI only
    role         TEXT NOT NULL CHECK (role IN ('client','gateway')),
    label        TEXT NOT NULL DEFAULT '',
    max_uses     INTEGER NOT NULL DEFAULT 1,
    uses         INTEGER NOT NULL DEFAULT 0,
    expires_at   TEXT,
    revoked_at   TEXT,
    created_by   TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL
);
CREATE INDEX activation_codes_customer ON activation_codes(customer_id);

CREATE TABLE devices (
    id                 INTEGER PRIMARY KEY,
    customer_id        INTEGER NOT NULL REFERENCES customers(id),
    code_id            INTEGER REFERENCES activation_codes(id),
    name               TEXT NOT NULL,
    role               TEXT NOT NULL CHECK (role IN ('client','gateway')),
    public_key         TEXT NOT NULL UNIQUE,
    vpn_ip             TEXT NOT NULL UNIQUE,
    lan_subnets        TEXT NOT NULL DEFAULT '[]',   -- JSON array of CIDRs (gateway only)
    status             TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
    device_token_hash  TEXT NOT NULL UNIQUE,
    os                 TEXT NOT NULL DEFAULT '',
    client_version     TEXT NOT NULL DEFAULT '',
    config_version     INTEGER NOT NULL DEFAULT 1,
    last_seen_at       TEXT,
    last_handshake_at  TEXT,
    endpoint           TEXT NOT NULL DEFAULT '',
    rx_bytes           INTEGER NOT NULL DEFAULT 0,
    tx_bytes           INTEGER NOT NULL DEFAULT 0,
    registered_at      TEXT NOT NULL,
    revoked_at         TEXT,
    revoked_reason     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX devices_customer ON devices(customer_id);

CREATE TABLE access_policies (
    id              INTEGER PRIMARY KEY,
    customer_id     INTEGER NOT NULL REFERENCES customers(id),
    from_device_id  INTEGER REFERENCES devices(id),      -- NULL = any client device of the customer
    to_device_id    INTEGER NOT NULL REFERENCES devices(id),
    to_cidr         TEXT,                                -- NULL = the gateway device itself; else an office LAN CIDR it declared
    proto           TEXT NOT NULL CHECK (proto IN ('tcp','udp','icmp')),
    ports           TEXT NOT NULL DEFAULT '[]',          -- JSON array of ints, empty for icmp
    label           TEXT NOT NULL DEFAULT '',
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL
);
CREATE INDEX access_policies_customer ON access_policies(customer_id);

CREATE TABLE provisioning_jobs (
    id          INTEGER PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES customers(id),
    device_id   INTEGER REFERENCES devices(id),
    public_key  TEXT NOT NULL,
    action      TEXT NOT NULL CHECK (action IN ('add','remove','update','reconcile')),
    state       TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','applied','failed')),
    error       TEXT NOT NULL DEFAULT '',
    attempts    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    applied_at  TEXT
);
CREATE INDEX provisioning_jobs_state ON provisioning_jobs(state);

CREATE TABLE admins (
    id            INTEGER PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('owner','operator','viewer')),
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL
);

CREATE TABLE admin_sessions (
    token_hash  TEXT PRIMARY KEY,
    admin_id    INTEGER NOT NULL REFERENCES admins(id),
    csrf_token  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY,
    at          TEXT NOT NULL,
    actor_type  TEXT NOT NULL,   -- admin | device | system
    actor_id    TEXT NOT NULL,
    action      TEXT NOT NULL,
    target      TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '',
    ip          TEXT NOT NULL DEFAULT ''
);
CREATE INDEX audit_log_at ON audit_log(at);
