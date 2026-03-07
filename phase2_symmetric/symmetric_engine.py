"""
MedKey — Phase 2: Symmetric Encryption Engine
AES-256-GCM authenticated encryption for patient medical records.

Key concepts:
- AES-256: 256-bit key, virtually unbreakable by brute force
- GCM mode: Provides both encryption AND authentication in one step
- IV (Initialization Vector): Must be unique for every encryption operation
- Auth Tag: 16-byte proof that ciphertext was not tampered with
"""

import os
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ─── Constants ────────────────────────────────────────────────────────────────

AES_KEY_SIZE = 32       # 256 bits
GCM_IV_SIZE  = 12       # 96 bits — optimal for GCM
GCM_TAG_SIZE = 16       # 128-bit authentication tag


# ─── Core Encryption Functions ────────────────────────────────────────────────

def generate_symmetric_key() -> bytes:
    """
    Generate a cryptographically secure random 256-bit AES key.
    Uses os.urandom which is a CSPRNG — unpredictable and safe for crypto.
    
    Returns:
        32 bytes of random key material
    """
    return os.urandom(AES_KEY_SIZE)


def generate_iv() -> bytes:
    """
    Generate a cryptographically secure random 96-bit IV.
    CRITICAL: Never reuse an IV with the same key.
    In GCM mode, IV reuse catastrophically breaks security.
    
    Returns:
        12 bytes of random IV
    """
    return os.urandom(GCM_IV_SIZE)


def encrypt_medical_record(plaintext_data: dict, key: bytes) -> dict:
    """
    Encrypt a patient's medical record using AES-256-GCM.
    
    The plaintext JSON never leaves this function unencrypted.
    GCM produces ciphertext + auth tag together — we store both.
    
    Args:
        plaintext_data: Python dict containing patient medical info
        key: 32-byte AES key (Ks)
    
    Returns:
        dict with keys: ciphertext_b64, iv_b64, tag_b64
        (all base64 encoded for safe database storage)
    
    Raises:
        ValueError: If key is wrong length
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")

    # Serialize the medical record to JSON bytes
    plaintext_bytes = json.dumps(plaintext_data, ensure_ascii=False).encode("utf-8")

    # Generate fresh IV for this encryption
    iv = generate_iv()

    # AESGCM automatically appends the 16-byte auth tag to ciphertext
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext_bytes, None)

    # Split ciphertext and auth tag
    # GCM appends tag at the end: ciphertext = actual_ct + tag (last 16 bytes)
    ciphertext = ciphertext_with_tag[:-GCM_TAG_SIZE]
    auth_tag   = ciphertext_with_tag[-GCM_TAG_SIZE:]

    return {
        "ciphertext_b64": base64.b64encode(ciphertext).decode(),
        "iv_b64":         base64.b64encode(iv).decode(),
        "tag_b64":        base64.b64encode(auth_tag).decode(),
    }


def decrypt_medical_record(encrypted_payload: dict, key: bytes) -> dict:
    """
    Decrypt a patient's medical record using AES-256-GCM.
    
    IMPORTANT: GCM verifies the auth tag BEFORE decrypting.
    If the tag fails (tampered data), raises InvalidTag exception.
    This means corrupted or tampered records are detected immediately.
    
    Args:
        encrypted_payload: dict with ciphertext_b64, iv_b64, tag_b64
        key: 32-byte AES key (Ks)
    
    Returns:
        dict: Decrypted patient medical record
    
    Raises:
        cryptography.exceptions.InvalidTag: If data was tampered with
        ValueError: If key or payload is malformed
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")

    # Decode from base64
    ciphertext = base64.b64decode(encrypted_payload["ciphertext_b64"])
    iv         = base64.b64decode(encrypted_payload["iv_b64"])
    auth_tag   = base64.b64decode(encrypted_payload["tag_b64"])

    # Reconstruct the combined ciphertext+tag that AESGCM expects
    ciphertext_with_tag = ciphertext + auth_tag

    # Decrypt — this ALSO verifies the auth tag internally
    aesgcm = AESGCM(key)
    plaintext_bytes = aesgcm.decrypt(iv, ciphertext_with_tag, None)

    return json.loads(plaintext_bytes.decode("utf-8"))


# ─── Utility Functions ────────────────────────────────────────────────────────

def key_to_b64(key: bytes) -> str:
    """Convert binary key to base64 string for storage."""
    return base64.b64encode(key).decode()


def b64_to_key(key_b64: str) -> bytes:
    """Convert base64 string back to binary key."""
    return base64.b64decode(key_b64)


# ─── Test / Demo ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("MedKey Phase 2 — AES-256-GCM Encryption Engine Demo")
    print("=" * 60)

    # Sample patient medical record
    patient_record = {
        "name": "John Doe",
        "blood_type": "O+",
        "allergies": ["Penicillin", "Sulfa drugs"],
        "medications": ["Metformin 500mg", "Lisinopril 10mg"],
        "conditions": ["Type 2 Diabetes", "Hypertension"],
        "emergency_contact": {
            "name": "Jane Doe",
            "phone": "+1-555-0123",
            "relation": "Spouse"
        }
    }

    print("\n[1] Original Medical Record:")
    print(json.dumps(patient_record, indent=2))

    # Generate a random symmetric key
    Ks = generate_symmetric_key()
    print(f"\n[2] Generated Symmetric Key (Ks):")
    print(f"    {key_to_b64(Ks)} ({len(Ks)*8} bits)")

    # Encrypt
    encrypted = encrypt_medical_record(patient_record, Ks)
    print(f"\n[3] Encrypted Payload:")
    print(f"    IV:         {encrypted['iv_b64']}")
    print(f"    Ciphertext: {encrypted['ciphertext_b64'][:40]}... (truncated)")
    print(f"    Auth Tag:   {encrypted['tag_b64']}")
    print(f"\n    ✓ This is what gets stored in PostgreSQL — pure gibberish without Ks")

    # Decrypt
    decrypted = decrypt_medical_record(encrypted, Ks)
    print(f"\n[4] Decrypted Record:")
    print(json.dumps(decrypted, indent=2))
    print(f"\n    ✓ Decryption successful — data matches original: {decrypted == patient_record}")

    # Tamper detection demo
    print(f"\n[5] Tamper Detection Test:")
    import copy
    tampered = copy.deepcopy(encrypted)
    # Flip a byte in the ciphertext
    ct_bytes = bytearray(base64.b64decode(tampered["ciphertext_b64"]))
    ct_bytes[0] ^= 0xFF
    tampered["ciphertext_b64"] = base64.b64encode(bytes(ct_bytes)).decode()

    try:
        decrypt_medical_record(tampered, Ks)
        print("    ✗ TAMPER NOT DETECTED — this should never happen")
    except Exception as e:
        print(f"    ✓ Tamper detected! Exception: {type(e).__name__}")
        print(f"    ✓ AES-GCM Auth Tag correctly rejected modified ciphertext")

    print("\n" + "=" * 60)
    print("Phase 2 Complete ✓")
    print("=" * 60)