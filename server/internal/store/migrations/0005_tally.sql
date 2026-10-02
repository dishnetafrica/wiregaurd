-- Tally remote-access readiness: additive columns only.
ALTER TABLE customer_onboarding ADD COLUMN tally_company TEXT NOT NULL DEFAULT '';
ALTER TABLE customer_onboarding ADD COLUMN concurrent_users INTEGER NOT NULL DEFAULT 1;
ALTER TABLE customer_onboarding ADD COLUMN concurrent_assessment TEXT NOT NULL DEFAULT 'not_needed';
ALTER TABLE customer_onboarding ADD COLUMN pilot_checks TEXT NOT NULL DEFAULT '';
