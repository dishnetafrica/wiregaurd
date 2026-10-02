-- DishNet Web Desktop: browser access to the office computer through the hub.
ALTER TABLE customers ADD COLUMN web_access INTEGER NOT NULL DEFAULT 0;

CREATE TABLE customer_users (
    id                   INTEGER PRIMARY KEY,
    customer_id          INTEGER NOT NULL REFERENCES customers(id),
    login                TEXT NOT NULL UNIQUE,            -- lower-case, e.g. grace@kampalatraders or grace.kt
    display_name         TEXT NOT NULL DEFAULT '',
    password_hash        TEXT NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 1,
    totp_secret          TEXT NOT NULL DEFAULT '',        -- base32; empty = two-factor off
    status               TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
    created_by           TEXT NOT NULL DEFAULT '',
    created_at           TEXT NOT NULL,
    last_login_at        TEXT
);
CREATE INDEX customer_users_customer ON customer_users(customer_id);

CREATE TABLE desk_sessions (
    token_hash     TEXT PRIMARY KEY,
    user_id        INTEGER NOT NULL REFERENCES customer_users(id),
    csrf_token     TEXT NOT NULL,
    totp_pending   INTEGER NOT NULL DEFAULT 0,            -- 1 = password ok, second factor still required
    expires_at     TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    ip             TEXT NOT NULL DEFAULT ''
);

-- Office computers must now also accept traffic from the hub itself (the web
-- desktop connects from there). Bump their config version so the office app
-- refetches its tunnel configuration.
UPDATE devices SET config_version = config_version + 1 WHERE role = 'gateway' AND status = 'active';
