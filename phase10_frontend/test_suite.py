"""
MedKey — Phase 10: Integration Tests & Performance Benchmarks
Tests every cryptographic component and measures performance.
Run this to verify the entire system works end-to-end.
"""

import sys
import os
import time
import json
import statistics

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phase2_symmetric.symmetric_engine import (
    generate_symmetric_key, encrypt_medical_record, decrypt_medical_record, key_to_b64
)
from phase3_asymmetric.asymmetric_engine import (
    generate_doctor_keypair, get_key_fingerprint,
    generate_challenge, sign_challenge, verify_challenge_response
)
from phase4_hybrid.hybrid_engine import wrap_key_for_doctor, unwrap_key_as_doctor
from phase8_offline_qr.offline_qr_engine import (
    generate_master_offline_key, encrypt_offline_payload, decrypt_offline_payload,
    get_current_period
)
from phase9_samaritan.samaritan_engine import (
    generate_blinding_factor, create_commitment, verify_commitment,
    hash_location, generate_assistance_proof, verify_assistance_proof
)


# ─── Test Data ────────────────────────────────────────────────────────────────

SAMPLE_PATIENT = {
    "name": "John Doe",
    "blood_type": "O+",
    "allergies": ["Penicillin", "Sulfa drugs", "Latex"],
    "medications": ["Metformin 500mg", "Lisinopril 10mg", "Aspirin 81mg"],
    "conditions": ["Type 2 Diabetes", "Hypertension", "Atrial Fibrillation"],
    "surgical_history": "Appendectomy 2019",
    "emergency_contact": {"name": "Jane Doe", "phone": "+1-555-0123"},
}


# ─── Test Results Tracker ─────────────────────────────────────────────────────

class TestResults:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.benchmarks = {}

    def check(self, name: str, condition: bool, message: str = ""):
        if condition:
            self.passed += 1
            print(f"  ✓ {name}")
        else:
            self.failed += 1
            print(f"  ✗ {name} — {message}")

    def benchmark(self, name: str, duration_ms: float):
        self.benchmarks[name] = duration_ms
        status = "✓" if duration_ms < 500 else "⚠"
        print(f"  {status} {name}: {duration_ms:.2f}ms")

    def summary(self):
        total = self.passed + self.failed
        print(f"\n{'='*60}")
        print(f"TEST SUMMARY: {self.passed}/{total} passed")
        if self.failed > 0:
            print(f"⚠ {self.failed} test(s) failed")
        else:
            print("✓ All tests passed")

        print(f"\nPERFORMANCE BENCHMARKS:")
        for name, ms in self.benchmarks.items():
            target = "< 500ms" if ms < 500 else "> 500ms ⚠"
            print(f"  {name}: {ms:.2f}ms ({target})")
        print(f"{'='*60}")


results = TestResults()


# ─── Phase 2 Tests: Symmetric Encryption ──────────────────────────────────────

def test_phase2():
    print("\n[Phase 2] AES-256-GCM Symmetric Encryption")

    # Key generation
    Ks = generate_symmetric_key()
    results.check("Key generation produces 32 bytes", len(Ks) == 32)
    results.check("Keys are unique", generate_symmetric_key() != Ks)

    # Encryption/decryption roundtrip
    encrypted = encrypt_medical_record(SAMPLE_PATIENT, Ks)
    results.check("Encryption produces ciphertext", len(encrypted["ciphertext_b64"]) > 0)
    results.check("IV is present", len(encrypted["iv_b64"]) > 0)
    results.check("Auth tag is present", len(encrypted["tag_b64"]) > 0)

    decrypted = decrypt_medical_record(encrypted, Ks)
    results.check("Roundtrip decryption matches", decrypted == SAMPLE_PATIENT)

    # Tamper detection
    import base64, copy
    tampered = copy.deepcopy(encrypted)
    ct = bytearray(base64.b64decode(tampered["ciphertext_b64"]))
    ct[0] ^= 0xFF
    tampered["ciphertext_b64"] = base64.b64encode(bytes(ct)).decode()
    try:
        decrypt_medical_record(tampered, Ks)
        results.check("Tamper detection", False, "Should have raised exception")
    except Exception:
        results.check("Tamper detection rejects modified ciphertext", True)

    # Wrong key rejection
    wrong_key = generate_symmetric_key()
    try:
        decrypt_medical_record(encrypted, wrong_key)
        results.check("Wrong key rejection", False, "Should have raised exception")
    except Exception:
        results.check("Wrong key correctly rejected", True)

    # Performance benchmark
    iterations = 100
    start = time.perf_counter()
    for _ in range(iterations):
        encrypt_medical_record(SAMPLE_PATIENT, Ks)
    elapsed = (time.perf_counter() - start) * 1000 / iterations
    results.benchmark("AES-256-GCM encrypt (avg)", elapsed)


# ─── Phase 3 Tests: ECDSA Authentication ──────────────────────────────────────

def test_phase3():
    print("\n[Phase 3] ECC Key Generation & ECDSA Authentication")

    # Key generation
    priv_pem, pub_pem = generate_doctor_keypair()
    results.check("Private key generated (PEM)", b"PRIVATE KEY" in priv_pem)
    results.check("Public key generated (PEM)", b"PUBLIC KEY" in pub_pem)
    results.check("Keys are unique per generation",
                  generate_doctor_keypair()[1] != pub_pem)

    # Fingerprint
    fp = get_key_fingerprint(pub_pem)
    results.check("Fingerprint is non-empty string", len(fp) > 0)

    # Challenge-response (valid)
    challenge = generate_challenge()
    signature = sign_challenge(challenge["nonce_b64"], priv_pem)
    used = set()
    valid, reason = verify_challenge_response(
        challenge["nonce_b64"], signature, pub_pem,
        challenge["expires_at"], used
    )
    results.check("Valid auth succeeds", valid, reason)

    # Replay attack
    valid2, reason2 = verify_challenge_response(
        challenge["nonce_b64"], signature, pub_pem,
        challenge["expires_at"], used
    )
    results.check("Replay attack blocked", not valid2)

    # Wrong key
    _, wrong_pub = generate_doctor_keypair()
    fresh = generate_challenge()
    sig2 = sign_challenge(fresh["nonce_b64"], priv_pem)
    valid3, _ = verify_challenge_response(
        fresh["nonce_b64"], sig2, wrong_pub, fresh["expires_at"], set()
    )
    results.check("Wrong public key rejected", not valid3)

    # Expired challenge
    expired = generate_challenge()
    expired["expires_at"] = time.time() - 1
    sig3 = sign_challenge(expired["nonce_b64"], priv_pem)
    valid4, reason4 = verify_challenge_response(
        expired["nonce_b64"], sig3, pub_pem, expired["expires_at"], set()
    )
    results.check("Expired challenge rejected", not valid4)

    # Performance
    iterations = 50
    start = time.perf_counter()
    for _ in range(iterations):
        c = generate_challenge()
        s = sign_challenge(c["nonce_b64"], priv_pem)
        verify_challenge_response(c["nonce_b64"], s, pub_pem, c["expires_at"], set())
    elapsed = (time.perf_counter() - start) * 1000 / iterations
    results.benchmark("Full ECDSA challenge-response (avg)", elapsed)


# ─── Phase 4 Tests: Hybrid Encryption ────────────────────────────────────────

def test_phase4():
    print("\n[Phase 4] Hybrid ECC+AES Key Wrapping")

    priv_a, pub_a = generate_doctor_keypair()
    priv_b, pub_b = generate_doctor_keypair()
    Ks = generate_symmetric_key()

    # Wrap for doctor A
    wrapped_a = wrap_key_for_doctor(Ks, pub_a)
    results.check("Key wrapped for doctor A", "wrapped_key_b64" in wrapped_a)

    # Unwrap by doctor A
    recovered_Ks = unwrap_key_as_doctor(wrapped_a, priv_a)
    results.check("Doctor A recovers correct Ks", recovered_Ks == Ks)

    # Doctor B cannot unwrap doctor A's wrapped key
    try:
        wrong_Ks = unwrap_key_as_doctor(wrapped_a, priv_b)
        results.check("Cross-key isolation", wrong_Ks != Ks, "Keys should differ")
    except Exception:
        results.check("Cross-key isolation (exception on wrong key)", True)

    # End-to-end: encrypt record, wrap key, unwrap, decrypt
    encrypted = encrypt_medical_record(SAMPLE_PATIENT, Ks)
    wrapped = wrap_key_for_doctor(Ks, pub_a)
    recovered = unwrap_key_as_doctor(wrapped, priv_a)
    decrypted = decrypt_medical_record(encrypted, recovered)
    results.check("Full hybrid roundtrip", decrypted == SAMPLE_PATIENT)

    # Performance
    start = time.perf_counter()
    for _ in range(20):
        w = wrap_key_for_doctor(Ks, pub_a)
        unwrap_key_as_doctor(w, priv_a)
    elapsed = (time.perf_counter() - start) * 1000 / 20
    results.benchmark("ECDH key wrap + unwrap (avg)", elapsed)


# ─── Phase 8 Tests: Offline QR ────────────────────────────────────────────────

def test_phase8():
    print("\n[Phase 8] Offline QR Time-Lock System")

    master_key = generate_master_offline_key()
    patient_prefix = "abc12345"

    private_tier = {
        "blood_type": "A+",
        "allergies": ["Aspirin"],
        "medications": ["Warfarin 5mg"],
    }

    # Encrypt
    encrypted = encrypt_offline_payload(private_tier, master_key, patient_prefix)
    results.check("Offline payload encrypted", "ciphertext_b64" in encrypted)
    results.check("Expiry set correctly", encrypted["expires_at"] > time.time())

    # Decrypt
    decrypted = decrypt_offline_payload(encrypted, master_key, patient_prefix)
    results.check("Offline roundtrip correct", decrypted == private_tier)

    # Expired payload
    expired = dict(encrypted)
    expired["expires_at"] = time.time() - 1
    try:
        decrypt_offline_payload(expired, master_key, patient_prefix)
        results.check("Expired QR rejected", False, "Should have raised ValueError")
    except ValueError:
        results.check("Expired QR correctly rejected", True)

    # Wrong master key
    wrong_master = generate_master_offline_key()
    try:
        decrypt_offline_payload(encrypted, wrong_master, patient_prefix)
        results.check("Wrong master key rejected", False)
    except Exception:
        results.check("Wrong master key correctly rejected", True)


# ─── Phase 9 Tests: Good Samaritan ────────────────────────────────────────────

def test_phase9():
    print("\n[Phase 9] Anonymous Good Samaritan System")

    # Setup
    identity = "helper@example.com"
    blinding = generate_blinding_factor()
    commitment = create_commitment(identity, blinding)

    # Commitment scheme
    results.check("Commitment created", len(commitment) == 64)
    results.check("Commitment verifies correctly",
                  verify_commitment(identity, blinding, commitment))
    results.check("Wrong identity rejected",
                  not verify_commitment("wrong@example.com", blinding, commitment))

    # Location hashing
    loc_hash = hash_location(28.6139, 77.2090)
    results.check("Location hash is 64 chars", len(loc_hash) == 64)
    # Same location → same hash
    results.check("Location hash is deterministic",
                  hash_location(28.6139, 77.2090) == loc_hash)
    # Different location → different hash (use clearly different coordinates)
    results.check("Different location → different hash",
                  hash_location(28.7000, 77.3000) != loc_hash)

    # Proof generation and verification
    registered = [
        create_commitment("other@example.com", generate_blinding_factor()),
        commitment,
    ]

    proof = generate_assistance_proof(identity, blinding, commitment, 28.6139, 77.2090)
    is_valid, reason = verify_assistance_proof(proof, registered)
    results.check("Valid proof accepted", is_valid, reason)

    # Unregistered person
    fake_blinding = generate_blinding_factor()
    fake_commitment = create_commitment("fake@evil.com", fake_blinding)
    fake_proof = generate_assistance_proof("fake@evil.com", fake_blinding,
                                           fake_commitment, 28.6139, 77.2090)
    is_valid2, _ = verify_assistance_proof(fake_proof, registered)
    results.check("Unregistered person rejected", not is_valid2)


# ─── Full Integration Test ────────────────────────────────────────────────────

def test_full_integration():
    print("\n[Integration] Complete Emergency Access Flow")

    # Setup
    priv_pem, pub_pem = generate_doctor_keypair()
    Ks = generate_symmetric_key()

    # Patient registers
    encrypted_record = encrypt_medical_record(SAMPLE_PATIENT, Ks)
    wrapped_key = wrap_key_for_doctor(Ks, pub_pem)

    # Emergency: full flow timing
    start = time.perf_counter()

    # Step 1: Challenge
    challenge = generate_challenge()

    # Step 2: Doctor signs
    signature = sign_challenge(challenge["nonce_b64"], priv_pem)

    # Step 3: Server verifies
    is_valid, _ = verify_challenge_response(
        challenge["nonce_b64"], signature, pub_pem,
        challenge["expires_at"], set()
    )

    # Step 4: Doctor unwraps Ks
    recovered_Ks = unwrap_key_as_doctor(wrapped_key, priv_pem)

    # Step 5: Doctor decrypts record
    final_record = decrypt_medical_record(encrypted_record, recovered_Ks)

    total_ms = (time.perf_counter() - start) * 1000

    results.check("Authentication succeeded", is_valid)
    results.check("Final record matches original", final_record == SAMPLE_PATIENT)
    results.benchmark("Full emergency access flow (end-to-end)", total_ms)
    results.check(
        "Emergency access under 500ms target",
        total_ms < 500,
        f"Took {total_ms:.1f}ms"
    )


# ─── Run All Tests ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("MedKey Phase 10 — Full Test Suite & Benchmarks")
    print("=" * 60)

    test_phase2()
    test_phase3()
    test_phase4()
    test_phase8()
    test_phase9()
    test_full_integration()

    results.summary()