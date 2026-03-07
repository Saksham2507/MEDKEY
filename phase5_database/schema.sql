-- MedKey — Phase 5: PostgreSQL Database Schema
-- Run this file to initialize the complete database structure

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─── Patients Table ──────────────────────────────────────────────────────────
-- Stores encrypted patient records
-- NOTHING here is plaintext medical data except the public tier

CREATE TABLE IF NOT EXISTS patients (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Public tier: displayed to any scanner with no authentication
    public_tier         JSONB NOT NULL,
    -- Example: {"name": "John Doe", "blood_type": "O+", 
    --           "critical_alerts": ["PENICILLIN ALLERGY"], 
    --           "emergency_contact": {"name": "Jane", "phone": "555-0123"}}
    
    -- Encrypted private tier: AES-256-GCM ciphertext
    encrypted_record    TEXT NOT NULL,  -- base64 ciphertext
    record_iv           TEXT NOT NULL,  -- base64 AES-GCM IV (96 bits)
    record_tag          TEXT NOT NULL,  -- base64 GCM auth tag (128 bits)
    
    -- Metadata
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active           BOOLEAN DEFAULT TRUE
);

-- ─── Doctors Table ───────────────────────────────────────────────────────────
-- Doctor registry — only verified medical professionals

CREATE TABLE IF NOT EXISTS doctors (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Doctor identity
    full_name           TEXT NOT NULL,
    license_number      TEXT UNIQUE NOT NULL,
    specialty           TEXT NOT NULL,
    institution         TEXT NOT NULL,
    email               TEXT UNIQUE NOT NULL,
    
    -- Cryptographic identity
    public_key_pem      TEXT NOT NULL,  -- ECC secp256k1 public key
    key_fingerprint     TEXT NOT NULL,  -- SHA-256 fingerprint for audit logs
    
    -- Registry status
    is_verified         BOOLEAN DEFAULT FALSE,  -- Set TRUE after manual license check
    verified_at         TIMESTAMP WITH TIME ZONE,
    verified_by         TEXT,           -- Admin who verified
    
    -- Timestamps
    registered_at       TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_access         TIMESTAMP WITH TIME ZONE,
    is_active           BOOLEAN DEFAULT TRUE
);

-- ─── Key Map Table ───────────────────────────────────────────────────────────
-- Per-doctor per-patient encrypted Ks storage
-- Each row: "Doctor X's copy of Patient Y's symmetric key"

CREATE TABLE IF NOT EXISTS key_map (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id              UUID NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    doctor_id               UUID NOT NULL REFERENCES doctors(id) ON DELETE CASCADE,
    
    -- Wrapped Ks (encrypted with ECDH-derived wrap key)
    wrapped_key             TEXT NOT NULL,          -- base64 encrypted Ks
    ephemeral_public_pem    TEXT NOT NULL,          -- ephemeral public key for ECDH reconstruction
    wrap_iv                 TEXT NOT NULL,          -- base64 IV for the wrap operation
    wrap_tag                TEXT NOT NULL,          -- base64 GCM auth tag for wrap
    
    -- Created when doctor is added or patient is registered
    created_at              TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(patient_id, doctor_id)
);

-- ─── Nonce Blacklist Table ───────────────────────────────────────────────────
-- Used nonces — prevents replay attacks
-- Entries older than 1 hour are cleaned up automatically

CREATE TABLE IF NOT EXISTS used_nonces (
    nonce_hash      TEXT PRIMARY KEY,   -- SHA-256 of the used nonce
    used_at         TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    doctor_id       UUID REFERENCES doctors(id)
);

-- Auto-cleanup index for expired nonces
CREATE INDEX IF NOT EXISTS idx_nonces_used_at ON used_nonces(used_at);

-- ─── Audit Log Table ─────────────────────────────────────────────────────────
-- Tamper-evident access log — hash-chained entries
-- Each entry includes hash of previous entry → chain cannot be modified silently

CREATE TABLE IF NOT EXISTS audit_log (
    id                  BIGSERIAL PRIMARY KEY,
    
    -- Hash chain: SHA-256(previous_entry_hash || this_entry_content)
    entry_hash          TEXT NOT NULL UNIQUE,
    previous_hash       TEXT NOT NULL,  -- genesis block uses "MEDKEY_GENESIS"
    
    -- Event details
    event_type          TEXT NOT NULL,  -- 'ACCESS_PUBLIC', 'ACCESS_PRIVATE', 
                                        -- 'AUTH_SUCCESS', 'AUTH_FAIL', 'REGISTRATION'
    patient_id          UUID REFERENCES patients(id),
    doctor_fingerprint  TEXT,           -- Key fingerprint (not full key)
    
    -- Outcome
    success             BOOLEAN NOT NULL,
    failure_reason      TEXT,
    
    -- Context
    ip_address          TEXT,
    user_agent          TEXT,
    
    -- Timestamp
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ─── Good Samaritan Table ────────────────────────────────────────────────────
-- Anonymous bystander assistance certificates
-- No identity information stored

CREATE TABLE IF NOT EXISTS samaritan_commitments (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Cryptographic commitment (hash of identity + blinding factor)
    -- Identifies the person without revealing who they are
    commitment_hash     TEXT UNIQUE NOT NULL,
    
    registered_at       TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active           BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS samaritan_certificates (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- The ZK proof (serialized)
    zk_proof            TEXT NOT NULL,
    
    -- Accident context (no PII)
    accident_location_hash  TEXT NOT NULL,  -- SHA-256 of GPS coordinates
    assistance_timestamp    TIMESTAMP WITH TIME ZONE NOT NULL,
    
    -- Server signature over the certificate
    server_signature    TEXT NOT NULL,
    
    -- Issued certificate (for download)
    issued_at           TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ─── Indexes ─────────────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_patients_active     ON patients(is_active);
CREATE INDEX IF NOT EXISTS idx_doctors_verified    ON doctors(is_verified, is_active);
CREATE INDEX IF NOT EXISTS idx_doctors_fingerprint ON doctors(key_fingerprint);
CREATE INDEX IF NOT EXISTS idx_keymap_patient      ON key_map(patient_id);
CREATE INDEX IF NOT EXISTS idx_keymap_doctor       ON key_map(doctor_id);
CREATE INDEX IF NOT EXISTS idx_audit_patient       ON audit_log(patient_id);
CREATE INDEX IF NOT EXISTS idx_audit_created       ON audit_log(created_at);

-- ─── Cleanup Procedure ───────────────────────────────────────────────────────
-- Run periodically to remove expired nonces

CREATE OR REPLACE FUNCTION cleanup_expired_nonces()
RETURNS void AS $$
BEGIN
    DELETE FROM used_nonces 
    WHERE used_at < NOW() - INTERVAL '1 hour';
END;
$$ LANGUAGE plpgsql;

-- ─── Initial Genesis Audit Entry ─────────────────────────────────────────────
-- The first entry in the audit chain — anchors the hash chain

INSERT INTO audit_log (
    entry_hash,
    previous_hash,
    event_type,
    success
) VALUES (
    encode(digest('MEDKEY_GENESIS_BLOCK_V1', 'sha256'), 'hex'),
    'MEDKEY_GENESIS',
    'SYSTEM_INIT',
    TRUE
) ON CONFLICT DO NOTHING;