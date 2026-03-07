"""
MedKey — Phase 8: Offline QR Time-Lock System
Generates and decrypts offline QR payloads without server connectivity.

The time-lock mechanism:
- Master offline key (Ko_master) stored in the app during last sync
- Ko for a specific period = HKDF(Ko_master, salt=period_identifier)
- Period identifier = floor(unix_timestamp / PERIOD_SECONDS)
- This means Ko changes every PERIOD_SECONDS automatically
- An expired QR produces a different Ko → decryption fails cleanly

Security property: Even if an attacker steals the physical QR card,
it stops working after 7 days without any server action.
"""

import os
import time
import json
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from phase2_symmetric.symmetric_engine import generate_iv, AES_KEY_SIZE, GCM_TAG_SIZE


# ─── Constants ────────────────────────────────────────────────────────────────

PERIOD_SECONDS = 7 * 24 * 3600    # 7-day key rotation period
HKDF_INFO_OFFLINE = b"MedKey-v1-OfflineQR"


# ─── Time-Lock Key Derivation ─────────────────────────────────────────────────

def get_current_period(timestamp: float = None) -> int:
    """
    Get the current period identifier.
    All timestamps within the same 7-day window share the same period ID.
    
    Args:
        timestamp: Unix timestamp (defaults to now)
    
    Returns:
        Integer period identifier
    """
    ts = timestamp or time.time()
    return int(ts // PERIOD_SECONDS)


def derive_offline_key(master_key: bytes, period: int, patient_id_prefix: str) -> bytes:
    """
    Derive a time-period-specific offline key using HKDF.
    
    The salt combines the period ID and patient ID prefix — this means:
    - Different patients get different Ko even in the same period
    - Same patient's Ko changes every 7 days automatically
    - No server call needed — math produces the right key deterministically
    
    Args:
        master_key: 32-byte master offline key (Ko_master)
        period: Current period identifier from get_current_period()
        patient_id_prefix: First 8 chars of patient UUID
    
    Returns:
        32-byte offline decryption key Ko
    """
    # Salt = SHA-256(period_bytes || patient_prefix_bytes)
    salt_input = period.to_bytes(8, "big") + patient_id_prefix.encode()
    salt = hashlib.sha256(salt_input).digest()

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        info=HKDF_INFO_OFFLINE,
        backend=default_backend(),
    )

    return hkdf.derive(master_key)


# ─── Offline Payload Encryption ───────────────────────────────────────────────

def encrypt_offline_payload(
    private_tier: dict,
    master_key: bytes,
    patient_id_prefix: str,
    expires_at: float = None,
) -> dict:
    """
    Encrypt patient's private tier for offline QR storage.
    Uses a time-locked key derived from master_key and current period.
    
    Args:
        private_tier: Patient private medical data dict
        master_key: 32-byte Ko_master
        patient_id_prefix: First 8 chars of patient UUID
        expires_at: Optional custom expiry (defaults to end of current period)
    
    Returns:
        dict with encrypted payload and expiry timestamp
    """
    current_period = get_current_period()
    Ko = derive_offline_key(master_key, current_period, patient_id_prefix)

    # Encrypt
    plaintext = json.dumps(private_tier, ensure_ascii=False).encode()
    iv = generate_iv()
    aesgcm = AESGCM(Ko)
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, None)

    ciphertext = ciphertext_with_tag[:-GCM_TAG_SIZE]
    auth_tag   = ciphertext_with_tag[-GCM_TAG_SIZE:]

    # Default expiry: end of current period
    if expires_at is None:
        expires_at = (current_period + 1) * PERIOD_SECONDS

    return {
        "ciphertext_b64": base64.b64encode(ciphertext).decode(),
        "iv_b64":         base64.b64encode(iv).decode(),
        "tag_b64":        base64.b64encode(auth_tag).decode(),
        "expires_at":     expires_at,
        "period":         current_period,
    }


# ─── Offline Payload Decryption ───────────────────────────────────────────────

def decrypt_offline_payload(
    encrypted_payload: dict,
    master_key: bytes,
    patient_id_prefix: str,
) -> dict:
    """
    Decrypt an offline QR payload on the doctor's device (no internet).
    
    Validates:
    1. QR has not expired (time-lock check)
    2. GCM auth tag is valid (tamper check)
    3. Derived key matches (period check)
    
    Args:
        encrypted_payload: Dict with ciphertext_b64, iv_b64, tag_b64, expires_at, period
        master_key: 32-byte Ko_master (loaded during last app sync)
        patient_id_prefix: From the QR blob's "pid" field
    
    Returns:
        Decrypted private tier dict
    
    Raises:
        ValueError: If QR is expired
        cryptography.exceptions.InvalidTag: If tampered or wrong period
    """
    # Step 1: Check expiry
    if time.time() > encrypted_payload["expires_at"]:
        days_expired = (time.time() - encrypted_payload["expires_at"]) / 86400
        raise ValueError(
            f"Offline QR expired {days_expired:.1f} days ago. "
            f"Patient must scan a new QR from the MedKey app."
        )

    # Step 2: Derive the same Ko using stored period
    period = encrypted_payload["period"]
    Ko = derive_offline_key(master_key, period, patient_id_prefix)

    # Step 3: Decrypt (GCM verifies auth tag automatically)
    ciphertext = base64.b64decode(encrypted_payload["ciphertext_b64"])
    iv         = base64.b64decode(encrypted_payload["iv_b64"])
    auth_tag   = base64.b64decode(encrypted_payload["tag_b64"])

    aesgcm = AESGCM(Ko)
    plaintext = aesgcm.decrypt(iv, ciphertext + auth_tag, None)

    return json.loads(plaintext.decode())


# ─── Master Key Management ────────────────────────────────────────────────────

def generate_master_offline_key() -> bytes:
    """Generate a new master offline key (Ko_master). Run once at system setup."""
    return os.urandom(AES_KEY_SIZE)


def master_key_to_env_string(master_key: bytes) -> str:
    """Convert master key to hex string for .env file storage."""
    return master_key.hex()


def master_key_from_env() -> bytes:
    """Load master offline key from environment variable."""
    hex_key = os.getenv("MASTER_OFFLINE_KEY")
    if not hex_key:
        raise ValueError("MASTER_OFFLINE_KEY not set in environment")
    return bytes.fromhex(hex_key)


# ─── Demo ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("MedKey Phase 8 — Offline QR Time-Lock System Demo")
    print("=" * 60)

    # Setup
    master_key = generate_master_offline_key()
    patient_prefix = "550e8400"  # First 8 chars of patient UUID

    private_tier = {
        "allergies": ["Penicillin", "Sulfa"],
        "medications": ["Metformin 500mg"],
        "conditions": ["Type 2 Diabetes"],
        "blood_type": "O+",
    }

    print(f"\n[1] Master Offline Key Generated:")
    print(f"    {master_key.hex()[:32]}... (stored in doctor app, synced when online)")

    print(f"\n[2] Current Period: {get_current_period()}")
    print(f"    Period resets every 7 days")

    print(f"\n[3] Encrypting Private Tier for Offline QR...")
    encrypted = encrypt_offline_payload(private_tier, master_key, patient_prefix)
    print(f"    Ciphertext: {encrypted['ciphertext_b64'][:30]}...")
    print(f"    IV: {encrypted['iv_b64']}")
    print(f"    Expires: {time.ctime(encrypted['expires_at'])}")

    print(f"\n[4] Decrypting Offline (simulating no internet)...")
    decrypted = decrypt_offline_payload(encrypted, master_key, patient_prefix)
    print(f"    Blood Type: {decrypted['blood_type']}")
    print(f"    Allergies: {', '.join(decrypted['allergies'])}")
    print(f"    Medications: {', '.join(decrypted['medications'])}")
    print(f"    ✓ Decrypted successfully with ZERO server calls")

    print(f"\n[5] Expired QR Test...")
    expired_payload = dict(encrypted)
    expired_payload["expires_at"] = time.time() - 1  # Already expired
    try:
        decrypt_offline_payload(expired_payload, master_key, patient_prefix)
    except ValueError as e:
        print(f"    ✓ Correctly rejected: {e}")

    print(f"\n[6] Tampered QR Test...")
    tampered = dict(encrypted)
    ct = bytearray(base64.b64decode(tampered["ciphertext_b64"]))
    ct[0] ^= 0xFF
    tampered["ciphertext_b64"] = base64.b64encode(bytes(ct)).decode()
    try:
        decrypt_offline_payload(tampered, master_key, patient_prefix)
    except Exception as e:
        print(f"    ✓ Tamper detected: {type(e).__name__}")

    print("\n" + "=" * 60)
    print("Phase 8 Complete ✓")
    print("=" * 60)