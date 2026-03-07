"""
MedKey — Phase 3: Asymmetric Encryption Engine
ECC key generation and ECDSA digital signatures for doctor identity.

Key concepts:
- ECC (secp256k1): Elliptic Curve Cryptography — doctor key pairs
- ECDSA: Signing algorithm — proves identity without sending private key
- Challenge-Response: Server sends nonce, doctor signs it, server verifies
- Private key: NEVER leaves doctor's device
- Public key: Stored in server registry, used to verify signatures
"""

import os
import json
import base64
import hashlib
import secrets
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


# ─── Constants ────────────────────────────────────────────────────────────────

CURVE          = ec.SECP256K1()   # Same curve Bitcoin uses
NONCE_SIZE     = 32               # 256-bit challenge nonce
NONCE_EXPIRY   = 30               # seconds


# ─── Key Generation ───────────────────────────────────────────────────────────

def generate_doctor_keypair() -> tuple[bytes, bytes]:
    """
    Generate an ECC key pair for a doctor on the secp256k1 curve.
    
    The private key is returned in PEM format for download to doctor's device.
    The public key is returned in PEM format for storage in the registry.
    
    CRITICAL: The private key must NEVER be stored on the server.
    It is generated here and immediately handed off — server forgets it.
    
    Returns:
        (private_key_pem, public_key_pem): Both as bytes
    """
    private_key = ec.generate_private_key(CURVE, default_backend())

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_key_pem, public_key_pem


def get_key_fingerprint(public_key_pem: bytes) -> str:
    """
    Generate a SHA-256 fingerprint of a public key for audit logs.
    Identifies who accessed a record without storing full key in logs.
    
    Returns:
        Colon-separated hex fingerprint (like SSH key fingerprint)
    """
    digest = hashlib.sha256(public_key_pem).digest()
    hex_str = digest.hex()
    return ":".join(hex_str[i:i+2] for i in range(0, 16, 2))  # first 8 bytes


# ─── Challenge-Response Authentication ────────────────────────────────────────

def generate_challenge() -> dict:
    """
    Generate a cryptographic challenge nonce for doctor authentication.
    
    The nonce is a random value that the doctor must sign with their private key.
    It expires after NONCE_EXPIRY seconds to prevent replay attacks.
    
    Returns:
        dict with nonce_b64 and expires_at timestamp
    """
    nonce = secrets.token_bytes(NONCE_SIZE)
    return {
        "nonce_b64": base64.b64encode(nonce).decode(),
        "expires_at": time.time() + NONCE_EXPIRY,
        "nonce_hash": hashlib.sha256(nonce).hexdigest(),  # for blacklist tracking
    }


def sign_challenge(nonce_b64: str, private_key_pem: bytes) -> str:
    """
    Doctor's device signs the server's challenge nonce using ECDSA.
    
    This proves the doctor holds the private key corresponding to their
    registered public key, WITHOUT transmitting the private key.
    
    Args:
        nonce_b64: Base64-encoded nonce from server
        private_key_pem: Doctor's PEM private key (stays on device)
    
    Returns:
        Base64-encoded DER signature
    """
    nonce = base64.b64decode(nonce_b64)

    private_key = serialization.load_pem_private_key(
        private_key_pem, password=None, backend=default_backend()
    )

    # ECDSA signs a hash of the nonce using SHA-256
    signature = private_key.sign(nonce, ec.ECDSA(hashes.SHA256()))

    return base64.b64encode(signature).decode()


def verify_challenge_response(
    nonce_b64: str,
    signature_b64: str,
    public_key_pem: bytes,
    expires_at: float,
    used_nonces: set,
) -> tuple[bool, str]:
    """
    Server verifies the doctor's ECDSA signature against their registered public key.
    
    Checks three things:
    1. Nonce has not expired (prevents stale response attacks)
    2. Nonce has not been used before (prevents replay attacks)
    3. Signature is cryptographically valid (proves private key possession)
    
    Args:
        nonce_b64: The original nonce sent to doctor
        signature_b64: The doctor's signed response
        public_key_pem: Doctor's registered public key
        expires_at: Expiry timestamp from challenge generation
        used_nonces: Set of already-used nonce hashes (server maintains this)
    
    Returns:
        (is_valid, reason): Boolean result and explanation string
    """
    # Check 1: Expiry
    if time.time() > expires_at:
        return False, "Challenge nonce has expired (30 second window)"

    # Check 2: Replay prevention
    nonce = base64.b64decode(nonce_b64)
    nonce_hash = hashlib.sha256(nonce).hexdigest()
    if nonce_hash in used_nonces:
        return False, "Nonce already used — replay attack detected"

    # Mark nonce as used immediately
    used_nonces.add(nonce_hash)

    # Check 3: Cryptographic signature verification
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem, backend=default_backend()
        )
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, nonce, ec.ECDSA(hashes.SHA256()))
        return True, "Authentication successful"

    except InvalidSignature:
        return False, "Invalid signature — key mismatch or tampering detected"
    except Exception as e:
        return False, f"Verification error: {str(e)}"


# ─── Key Serialization Helpers ────────────────────────────────────────────────

def load_private_key(private_key_pem: bytes):
    """Load private key from PEM bytes."""
    return serialization.load_pem_private_key(
        private_key_pem, password=None, backend=default_backend()
    )


def load_public_key(public_key_pem: bytes):
    """Load public key from PEM bytes."""
    return serialization.load_pem_public_key(
        public_key_pem, backend=default_backend()
    )


# ─── Test / Demo ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("MedKey Phase 3 — ECC & ECDSA Authentication Demo")
    print("=" * 60)

    # Generate doctor key pair
    print("\n[1] Generating Doctor ECC Key Pair (secp256k1)...")
    private_pem, public_pem = generate_doctor_keypair()
    fingerprint = get_key_fingerprint(public_pem)
    print(f"    Private Key: [GENERATED — stays on doctor device, NOT shown]")
    print(f"    Public Key Fingerprint: {fingerprint}")
    print(f"    Public Key stored in server registry ✓")

    # Server generates challenge
    print("\n[2] Server Generates Challenge Nonce...")
    challenge = generate_challenge()
    print(f"    Nonce: {challenge['nonce_b64'][:20]}... (truncated)")
    print(f"    Expires At: {challenge['expires_at']:.0f} (unix timestamp)")
    print(f"    Window: 30 seconds")

    # Doctor signs challenge
    print("\n[3] Doctor's Device Signs Challenge with Private Key...")
    signature = sign_challenge(challenge["nonce_b64"], private_pem)
    print(f"    Signature: {signature[:40]}... (truncated)")
    print(f"    [Private key used locally — never transmitted]")

    # Server verifies
    print("\n[4] Server Verifies Signature Against Registered Public Key...")
    used_nonces = set()
    is_valid, reason = verify_challenge_response(
        challenge["nonce_b64"],
        signature,
        public_pem,
        challenge["expires_at"],
        used_nonces,
    )
    print(f"    Result: {'✓ VALID' if is_valid else '✗ INVALID'}")
    print(f"    Reason: {reason}")

    # Replay attack demo
    print("\n[5] Replay Attack Test (reusing same signature)...")
    is_valid2, reason2 = verify_challenge_response(
        challenge["nonce_b64"],
        signature,
        public_pem,
        challenge["expires_at"],
        used_nonces,
    )
    print(f"    Result: {'✓ VALID' if is_valid2 else '✗ BLOCKED'}")
    print(f"    Reason: {reason2}")

    # Wrong key test
    print("\n[6] Wrong Key Test (different doctor's key)...")
    _, wrong_public_pem = generate_doctor_keypair()
    fresh_challenge = generate_challenge()
    fresh_sig = sign_challenge(fresh_challenge["nonce_b64"], private_pem)
    is_valid3, reason3 = verify_challenge_response(
        fresh_challenge["nonce_b64"],
        fresh_sig,
        wrong_public_pem,  # Wrong public key!
        fresh_challenge["expires_at"],
        set(),
    )
    print(f"    Result: {'✓ VALID' if is_valid3 else '✗ REJECTED'}")
    print(f"    Reason: {reason3}")

    print("\n" + "=" * 60)
    print("Phase 3 Complete ✓")
    print("=" * 60)