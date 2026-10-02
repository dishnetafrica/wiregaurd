ALTER TABLE customers ADD COLUMN plan TEXT NOT NULL DEFAULT 'paid' CHECK (plan IN ('trial','paid','unlimited'));
