-- Run only against the isolated restored database, before starting any process.
-- This invalidates recovered browser sessions, grants and pending proofs. It
-- does not revoke offline JWTs or consuming applications' existing sessions.
BEGIN;
SET LOCAL lock_timeout = '5s';
SELECT pg_advisory_xact_lock(5065028,1);
DO $$
BEGIN
    IF (SELECT count(*) FROM memberid_schema) <> 1 OR
       (SELECT version FROM memberid_schema) NOT BETWEEN 26 AND 36 THEN
        RAISE EXCEPTION 'Unsupported recovery schema';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_stat_activity
        WHERE datid = (SELECT oid FROM pg_database WHERE datname=current_database())
        AND pid <> pg_backend_pid()
        AND (backend_type = 'client backend' OR backend_type IS NULL)) THEN
        RAISE EXCEPTION 'Stop all restored installation clients before recovery';
    END IF;
END $$;
DELETE FROM console_logins;
DELETE FROM console_sessions;
-- Consume pending proofs but retain request IDs until their normal expiry, so
-- recovery does not deliberately erase the retained SAML replay reservations.
UPDATE authentication_requests SET consumed_at=coalesce(consumed_at,clock_timestamp());
DELETE FROM phone_challenges;
DELETE FROM authentication_sessions;
COMMIT;
