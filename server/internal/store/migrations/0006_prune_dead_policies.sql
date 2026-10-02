-- Policies that name a revoked device never reach the firewall (the policy
-- engine skips inactive devices) but cluttered the dashboard. From v0.6.1
-- revocation deletes them; this removes the ones created before that.
DELETE FROM access_policies
 WHERE to_device_id IN (SELECT id FROM devices WHERE status <> 'active')
    OR (from_device_id IS NOT NULL AND from_device_id IN (SELECT id FROM devices WHERE status <> 'active'));
