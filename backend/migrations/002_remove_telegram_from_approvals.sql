-- Migration 002: Remove telegram_user_id from approver records and add provider, subject_id, and email.
-- Compatible with PostgreSQL. Uses no AUTOINCREMENT.

-- 1. Add new approver identity columns to governance_actions
ALTER TABLE governance_actions ADD COLUMN IF NOT EXISTS provider TEXT NOT NULL DEFAULT 'slack';
ALTER TABLE governance_actions ADD COLUMN IF NOT EXISTS subject_id TEXT NOT NULL DEFAULT '';
ALTER TABLE governance_actions ADD COLUMN IF NOT EXISTS email TEXT NOT NULL DEFAULT '';

-- 2. Backfill legacy telegram_user_id values if present
UPDATE governance_actions
SET subject_id = CAST(telegram_user_id AS TEXT),
    provider = 'telegram'
WHERE (subject_id IS NULL OR subject_id = '') 
  AND telegram_user_id IS NOT NULL;

-- 3. Drop legacy telegram_user_id column
ALTER TABLE governance_actions DROP COLUMN IF EXISTS telegram_user_id;

-- 4. Create index on (provider, subject_id) for fast identity lookups
CREATE INDEX IF NOT EXISTS idx_governance_actions_identity ON governance_actions (provider, subject_id);
