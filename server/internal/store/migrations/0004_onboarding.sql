CREATE TABLE customer_onboarding (
    customer_id        INTEGER PRIMARY KEY REFERENCES customers(id),
    office_edition     TEXT NOT NULL DEFAULT 'unknown' CHECK (office_edition IN ('unknown','pro','server','home')),
    readiness          TEXT NOT NULL DEFAULT 'not_checked' CHECK (readiness IN ('not_checked','ready','needs_attention')),
    readiness_note     TEXT NOT NULL DEFAULT '',
    acceptance_at      TEXT,          -- admin confirmed: customer opened Tally over Remote Desktop
    acceptance_by      TEXT NOT NULL DEFAULT '',
    handover_at        TEXT,          -- manual + support contact given to the customer
    handover_by        TEXT NOT NULL DEFAULT '',
    updated_at         TEXT NOT NULL
);

CREATE TABLE support_notes (
    id           INTEGER PRIMARY KEY,
    customer_id  INTEGER NOT NULL REFERENCES customers(id),
    author       TEXT NOT NULL,
    note         TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
CREATE INDEX support_notes_customer ON support_notes(customer_id, id);
