"""
MedKey — Phase 5: Database Manager
PostgreSQL connection handling and tamper-evident audit log.
"""

import os
import json
import hashlib
import time
from datetime import datetime, timezone
from typing import Optional
import psycopg2
from psycopg2.extras import RealDictCursor, Json
from dotenv import load_dotenv

load_dotenv()


# ─── Database Connection ──────────────────────────────────────────────────────

def get_db_connection():
    """Get a PostgreSQL database connection."""
    return psycopg2.connect(
        os.getenv("DATABASE_URL", "postgresql://localhost:5432/medkey_db"),
        cursor_factory=RealDictCursor
    )


# ─── Tamper-Evident Audit Log ─────────────────────────────────────────────────

class AuditLogger:
    """
    Hash-chained audit log — every entry includes the hash of the previous entry.
    Modifying any past entry breaks the chain, making tampering detectable.
    """

    GENESIS_HASH = hashlib.sha256(b"MEDKEY_GENESIS_BLOCK_V1").hexdigest()

    def _compute_entry_hash(
        self,
        previous_hash: str,
        event_type: str,
        patient_id: Optional[str],
        doctor_fingerprint: Optional[str],
        success: bool,
        timestamp: str,
    ) -> str:
        """Compute SHA-256 hash of this entry's content + previous hash."""
        content = "|".join([
            previous_hash,
            event_type,
            str(patient_id or ""),
            str(doctor_fingerprint or ""),
            str(success),
            timestamp,
        ])
        return hashlib.sha256(content.encode()).hexdigest()

    def _get_latest_hash(self, conn) -> str:
        """Get the hash of the most recent audit log entry."""
        with conn.cursor() as cur:
            cur.execute(
                "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
            )
            row = cur.fetchone()
            return row["entry_hash"] if row else self.GENESIS_HASH

    def log(
        self,
        conn,
        event_type: str,
        success: bool,
        patient_id: Optional[str] = None,
        doctor_fingerprint: Optional[str] = None,
        failure_reason: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> str:
        """
        Append a new entry to the tamper-evident audit log.
        
        Returns:
            The hash of the new entry
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        previous_hash = self._get_latest_hash(conn)

        entry_hash = self._compute_entry_hash(
            previous_hash, event_type, patient_id,
            doctor_fingerprint, success, timestamp
        )

        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO audit_log (
                    entry_hash, previous_hash, event_type,
                    patient_id, doctor_fingerprint,
                    success, failure_reason, ip_address, user_agent, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                entry_hash, previous_hash, event_type,
                patient_id, doctor_fingerprint,
                success, failure_reason, ip_address, user_agent, timestamp
            ))
        conn.commit()
        return entry_hash

    def verify_chain(self, conn) -> tuple[bool, str]:
        """
        Verify the integrity of the entire audit chain.
        
        Recomputes each entry's hash and checks it matches what's stored.
        Any tampering with past entries will cause a mismatch.
        
        Returns:
            (is_valid, message)
        """
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM audit_log ORDER BY id ASC"
            )
            entries = cur.fetchall()

        if not entries:
            return True, "Audit log is empty"

        for i, entry in enumerate(entries):
            if entry["event_type"] == "SYSTEM_INIT":
                continue

            # Recompute what this entry's hash should be
            expected_hash = self._compute_entry_hash(
                entry["previous_hash"],
                entry["event_type"],
                str(entry["patient_id"]) if entry["patient_id"] else None,
                entry["doctor_fingerprint"],
                entry["success"],
                entry["created_at"].isoformat(),
            )

            if expected_hash != entry["entry_hash"]:
                return False, f"Chain broken at entry {entry['id']} — tampering detected"

        return True, f"Audit chain verified — {len(entries)} entries intact"


# ─── Patient Database Operations ──────────────────────────────────────────────

class PatientDB:

    def store_patient(
        self,
        conn,
        public_tier: dict,
        encrypted_record: str,
        record_iv: str,
        record_tag: str,
    ) -> str:
        """Store a new encrypted patient record. Returns patient UUID."""
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO patients (public_tier, encrypted_record, record_iv, record_tag)
                VALUES (%s, %s, %s, %s)
                RETURNING id
            """, (Json(public_tier), encrypted_record, record_iv, record_tag))
            patient_id = str(cur.fetchone()["id"])
        conn.commit()
        return patient_id

    def get_patient_public_tier(self, conn, patient_id: str) -> Optional[dict]:
        """Get public tier — no authentication required."""
        with conn.cursor() as cur:
            cur.execute(
                "SELECT public_tier FROM patients WHERE id = %s AND is_active = TRUE",
                (patient_id,)
            )
            row = cur.fetchone()
            return dict(row["public_tier"]) if row else None

    def get_patient_encrypted_record(self, conn, patient_id: str) -> Optional[dict]:
        """Get encrypted record blob — only after authentication."""
        with conn.cursor() as cur:
            cur.execute("""
                SELECT encrypted_record, record_iv, record_tag
                FROM patients WHERE id = %s AND is_active = TRUE
            """, (patient_id,))
            row = cur.fetchone()
            if not row:
                return None
            return {
                "ciphertext_b64": row["encrypted_record"],
                "iv_b64": row["record_iv"],
                "tag_b64": row["record_tag"],
            }


# ─── Doctor Database Operations ───────────────────────────────────────────────

class DoctorDB:

    def register_doctor(
        self,
        conn,
        full_name: str,
        license_number: str,
        specialty: str,
        institution: str,
        email: str,
        public_key_pem: str,
        key_fingerprint: str,
    ) -> str:
        """Register a new doctor. Returns doctor UUID."""
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO doctors (
                    full_name, license_number, specialty, institution,
                    email, public_key_pem, key_fingerprint
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                full_name, license_number, specialty, institution,
                email, public_key_pem, key_fingerprint
            ))
            doctor_id = str(cur.fetchone()["id"])
        conn.commit()
        return doctor_id

    def get_doctor_public_key(self, conn, doctor_id: str) -> Optional[bytes]:
        """Get a verified doctor's public key for signature verification."""
        with conn.cursor() as cur:
            cur.execute("""
                SELECT public_key_pem FROM doctors
                WHERE id = %s AND is_verified = TRUE AND is_active = TRUE
            """, (doctor_id,))
            row = cur.fetchone()
            return row["public_key_pem"].encode() if row else None

    def verify_doctor(self, conn, doctor_id: str, verified_by: str):
        """Admin action: mark a doctor as verified after license check."""
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE doctors SET is_verified = TRUE, verified_at = NOW(), verified_by = %s
                WHERE id = %s
            """, (verified_by, doctor_id))
        conn.commit()


# ─── Key Map Operations ───────────────────────────────────────────────────────

class KeyMapDB:

    def store_wrapped_key(
        self,
        conn,
        patient_id: str,
        doctor_id: str,
        wrapped_key_data: dict,
    ):
        """Store a doctor's wrapped copy of a patient's Ks."""
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO key_map (
                    patient_id, doctor_id,
                    wrapped_key, ephemeral_public_pem, wrap_iv, wrap_tag
                ) VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (patient_id, doctor_id) DO UPDATE SET
                    wrapped_key = EXCLUDED.wrapped_key,
                    ephemeral_public_pem = EXCLUDED.ephemeral_public_pem,
                    wrap_iv = EXCLUDED.wrap_iv,
                    wrap_tag = EXCLUDED.wrap_tag
            """, (
                patient_id, doctor_id,
                wrapped_key_data["wrapped_key_b64"],
                wrapped_key_data["ephemeral_public_pem"],
                wrapped_key_data["iv_b64"],
                wrapped_key_data["tag_b64"],
            ))
        conn.commit()

    def get_wrapped_key(self, conn, patient_id: str, doctor_id: str) -> Optional[dict]:
        """Retrieve a doctor's wrapped Ks for a patient."""
        with conn.cursor() as cur:
            cur.execute("""
                SELECT wrapped_key, ephemeral_public_pem, wrap_iv, wrap_tag
                FROM key_map WHERE patient_id = %s AND doctor_id = %s
            """, (patient_id, doctor_id))
            row = cur.fetchone()
            if not row:
                return None
            return {
                "wrapped_key_b64": row["wrapped_key"],
                "ephemeral_public_pem": row["ephemeral_public_pem"],
                "iv_b64": row["wrap_iv"],
                "tag_b64": row["wrap_tag"],
            }


# ─── Nonce Management ─────────────────────────────────────────────────────────

class NonceDB:

    def mark_used(self, conn, nonce_hash: str, doctor_id: str):
        """Record a nonce as used to prevent replay attacks."""
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO used_nonces (nonce_hash, doctor_id)
                VALUES (%s, %s) ON CONFLICT DO NOTHING
            """, (nonce_hash, doctor_id))
        conn.commit()

    def is_used(self, conn, nonce_hash: str) -> bool:
        """Check if a nonce has already been used."""
        with conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM used_nonces WHERE nonce_hash = %s",
                (nonce_hash,)
            )
            return cur.fetchone() is not None

    def cleanup_expired(self, conn):
        """Remove nonces older than 1 hour."""
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM used_nonces WHERE used_at < NOW() - INTERVAL '1 hour'"
            )
        conn.commit()


# Singleton instances
audit_logger = AuditLogger()
patient_db   = PatientDB()
doctor_db    = DoctorDB()
key_map_db   = KeyMapDB()
nonce_db     = NonceDB()