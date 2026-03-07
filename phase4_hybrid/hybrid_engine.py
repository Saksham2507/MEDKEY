"""
MedKey — Phase 4: Hybrid Encryption Engine
The "Key Wrap" mechanism — ECDH derives shared secret, HKDF cleans it,
then wraps the AES symmetric key (Ks) for each doctor individually.

This is the most important phase — it connects Phases 2 and 3.

Flow:
  Patient Ks ──► AES-GCM encrypt(Ks, per_doctor_wrap_key) ──► stored in DB
  per_doctor_wrap_key ◄── HKDF(shared_secret) ◄── ECDH(patient_ephemeral, doctor_public)

Key insight: Every doctor gets their OWN encrypted copy of Ks.
Compromising Dr. A's key gives access to Dr. A's copies only.
Dr. B's copies remain safe. No master key vulnerability.
"""

import os
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from phase2_symmetric.symmetric_engine import generate_iv, AES_KEY_SIZE, GCM_IV_SIZE, GCM_TAG_SIZE


# ─── Constants ────────────────────────────────────────────────────────────────

HKDF_INFO = b"MedKey-v1-KeyWrap"   # Context string for HKDF — prevents cross-protocol attacks
CURVE     = ec.SECP256K1()


# ─── ECDH + HKDF Key Derivation ───────────────────────────────────────────────

def derive_wrap_key(
    our_private_key,
    their_public_key,
    salt: bytes = None
) -> bytes:
    """
    Derive a 256-bit wrapping key using ECDH + HKDF.
    
    ECDH produces a shared secret known to both parties.
    But raw ECDH output is not uniformly random — HKDF cleans it.
    HKDF (HMAC-based Key Derivation Function) produces proper AES key material.
    
    Args:
        our_private_key: ECC private key (patient ephemeral OR doctor private)
        their_public_key: ECC public key (doctor public OR patient ephemeral public)
        salt: Optional random bytes for additional entropy
    
    Returns:
        32-byte wrapping key suitable for AES-256
    """
    # ECDH — compute shared secret
    shared_secret = our_private_key.exchange(ec.ECDH(), their_public_key)

    # HKDF — derive clean key material from shared secret
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        info=HKDF_INFO,
        backend=default_backend(),
    )

    return hkdf.derive(shared_secret)


# ─── Key Wrapping (Encrypting Ks for a Doctor) ────────────────────────────────

def wrap_key_for_doctor(
    Ks: bytes,
    doctor_public_key_pem: bytes
) -> dict:
    """
    Encrypt the patient's symmetric key (Ks) for a specific doctor.
    
    Uses an ephemeral ECC key pair — generated fresh for each wrap operation.
    The ephemeral public key is stored alongside the wrapped Ks so the doctor
    can perform ECDH from their side to recover the same shared secret.
    
    This is the "Key Encapsulation Mechanism" (KEM) pattern.
    
    Args:
        Ks: 32-byte patient symmetric key to wrap
        doctor_public_key_pem: Doctor's registered public key
    
    Returns:
        dict with: wrapped_key_b64, ephemeral_public_pem, iv_b64, tag_b64
    """
    # Load doctor's public key
    doctor_public_key = serialization.load_pem_public_key(
        doctor_public_key_pem, backend=default_backend()
    )

    # Generate ephemeral key pair — used once, never stored
    ephemeral_private = ec.generate_private_key(CURVE, default_backend())
    ephemeral_public  = ephemeral_private.public_key()

    # Derive wrapping key via ECDH + HKDF
    wrap_key = derive_wrap_key(ephemeral_private, doctor_public_key)

    # Encrypt Ks using the derived wrap key
    iv = generate_iv()
    aesgcm = AESGCM(wrap_key)
    wrapped_with_tag = aesgcm.encrypt(iv, Ks, None)

    wrapped_Ks = wrapped_with_tag[:-GCM_TAG_SIZE]
    auth_tag   = wrapped_with_tag[-GCM_TAG_SIZE:]

    # Serialize ephemeral public key — doctor needs this to reproduce shared secret
    ephemeral_public_pem = ephemeral_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return {
        "wrapped_key_b64":    base64.b64encode(wrapped_Ks).decode(),
        "ephemeral_public_pem": ephemeral_public_pem.decode(),
        "iv_b64":             base64.b64encode(iv).decode(),
        "tag_b64":            base64.b64encode(auth_tag).decode(),
    }


def unwrap_key_as_doctor(
    wrapped_key_data: dict,
    doctor_private_key_pem: bytes
) -> bytes:
    """
    Doctor's device recovers the patient's Ks using their private key.
    
    The doctor performs ECDH with their private key and the stored ephemeral
    public key to reproduce the same shared secret, runs HKDF to get the
    wrap key, then decrypts Ks.
    
    Args:
        wrapped_key_data: dict from wrap_key_for_doctor
        doctor_private_key_pem: Doctor's private key (stays on device)
    
    Returns:
        32-byte symmetric key Ks
    
    Raises:
        cryptography.exceptions.InvalidTag: If wrapped key was tampered with
    """
    # Load keys
    doctor_private_key = serialization.load_pem_private_key(
        doctor_private_key_pem, password=None, backend=default_backend()
    )
    ephemeral_public_key = serialization.load_pem_public_key(
        wrapped_key_data["ephemeral_public_pem"].encode(),
        backend=default_backend(),
    )

    # Reproduce the same shared secret via ECDH
    wrap_key = derive_wrap_key(doctor_private_key, ephemeral_public_key)

    # Decrypt Ks
    wrapped_Ks = base64.b64decode(wrapped_key_data["wrapped_key_b64"])
    iv         = base64.b64decode(wrapped_key_data["iv_b64"])
    auth_tag   = base64.b64decode(wrapped_key_data["tag_b64"])

    aesgcm = AESGCM(wrap_key)
    Ks = aesgcm.decrypt(iv, wrapped_Ks + auth_tag, None)

    return Ks


# ─── Full Patient Registration Key Setup ──────────────────────────────────────

def setup_patient_keys(Ks: bytes, doctor_public_keys: dict) -> dict:
    """
    Wrap a patient's Ks for multiple doctors simultaneously.
    
    Args:
        Ks: Patient's symmetric key
        doctor_public_keys: dict mapping doctor_id -> public_key_pem bytes
    
    Returns:
        dict mapping doctor_id -> wrapped key data
    """
    key_map = {}
    for doctor_id, public_key_pem in doctor_public_keys.items():
        key_map[doctor_id] = wrap_key_for_doctor(Ks, public_key_pem)
    return key_map


# ─── Test / Demo ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    sys.path.insert(0, "..")

    from phase2_symmetric.symmetric_engine import (
        generate_symmetric_key,
        encrypt_medical_record,
        decrypt_medical_record,
        key_to_b64,
    )
    from phase3_asymmetric.asymmetric_engine import generate_doctor_keypair

    print("=" * 60)
    print("MedKey Phase 4 — Hybrid Encryption (Full Flow) Demo")
    print("=" * 60)

    # Setup: Two doctors registered in the system
    print("\n[1] Registering Two Doctors...")
    dr_a_priv, dr_a_pub = generate_doctor_keypair()
    dr_b_priv, dr_b_pub = generate_doctor_keypair()
    print("    Dr. A: Key pair generated ✓")
    print("    Dr. B: Key pair generated ✓")

    # Patient registration
    print("\n[2] Patient Registration — Encrypting Medical Record...")
    Ks = generate_symmetric_key()
    patient_data = {
        "name": "Alice Smith",
        "blood_type": "A-",
        "allergies": ["Aspirin"],
        "medications": ["Atorvastatin 20mg"],
        "conditions": ["High Cholesterol"],
    }

    encrypted_record = encrypt_medical_record(patient_data, Ks)
    print(f"    Record encrypted with Ks ✓")
    print(f"    Ks value: {key_to_b64(Ks)[:20]}... (never stored in plaintext)")

    # Wrap Ks for each doctor separately
    print("\n[3] Wrapping Ks Separately for Each Doctor...")
    wrapped_for_dr_a = wrap_key_for_doctor(Ks, dr_a_pub)
    wrapped_for_dr_b = wrap_key_for_doctor(Ks, dr_b_pub)
    print("    Ks wrapped for Dr. A with Dr. A's public key ✓")
    print("    Ks wrapped for Dr. B with Dr. B's public key ✓")
    print("    [Each wrap uses a unique ephemeral key — completely independent]")

    # Emergency: Dr. A authenticates and decrypts
    print("\n[4] Emergency Access — Dr. A Decrypts Patient Record...")
    recovered_Ks_a = unwrap_key_as_doctor(wrapped_for_dr_a, dr_a_priv)
    decrypted_a = decrypt_medical_record(encrypted_record, recovered_Ks_a)
    print(f"    Dr. A recovered Ks: ✓")
    print(f"    Dr. A decrypted record: {decrypted_a['name']}, Blood: {decrypted_a['blood_type']}")
    print(f"    Allergies: {', '.join(decrypted_a['allergies'])}")

    # Dr. B also decrypts independently
    print("\n[5] Dr. B Independently Decrypts Same Patient Record...")
    recovered_Ks_b = unwrap_key_as_doctor(wrapped_for_dr_b, dr_b_priv)
    decrypted_b = decrypt_medical_record(encrypted_record, recovered_Ks_b)
    print(f"    Dr. B decrypted record: {decrypted_b['name']} ✓")

    # Cross-key failure test
    print("\n[6] Security Test — Dr. A Cannot Use Dr. B's Wrapped Key...")
    try:
        fail_Ks = unwrap_key_as_doctor(wrapped_for_dr_b, dr_a_priv)
        print("    ✗ SECURITY FAILURE — should not happen")
    except Exception as e:
        print(f"    ✓ Correctly rejected: {type(e).__name__}")

    print("\n" + "=" * 60)
    print("Phase 4 Complete ✓ — Hybrid System Fully Operational")
    print("=" * 60)