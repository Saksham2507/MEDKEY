-- Run this to update the samaritan tables for the Good Samaritan feature
-- Copy and paste this into psql or run: psql -U postgres -d medkey_db -f samaritan_migration.sql

ALTER TABLE samaritan_certificates
    ADD COLUMN IF NOT EXISTS location_hash TEXT,
    ADD COLUMN IF NOT EXISTS certificate_data TEXT,
    ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT TRUE;

-- Copy existing data to new columns if any
UPDATE samaritan_certificates
SET location_hash = accident_location_hash
WHERE location_hash IS NULL AND accident_location_hash IS NOT NULL;

-- Confirm
SELECT column_name FROM information_schema.columns
WHERE table_name = 'samaritan_certificates';