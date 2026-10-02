CREATE TABLE trial_requests (
    id            INTEGER PRIMARY KEY,
    business      TEXT NOT NULL,
    contact_name  TEXT NOT NULL,
    phone         TEXT NOT NULL,
    email         TEXT NOT NULL DEFAULT '',
    pcs           INTEGER NOT NULL DEFAULT 1,
    office_type   TEXT NOT NULL DEFAULT 'unknown',   -- windows_pc | windows_server | unknown
    notes         TEXT NOT NULL DEFAULT '',
    ip            TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
    customer_id   INTEGER REFERENCES customers(id),
    decided_by    TEXT NOT NULL DEFAULT '',
    decision_note TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    decided_at    TEXT
);
CREATE INDEX trial_requests_status ON trial_requests(status);
