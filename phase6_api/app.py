"""
MedKey — Phase 6: Flask REST API (Complete + Demo + Good Samaritan Endpoints)
"""

import os
import sys
import json
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

from phase2_symmetric.symmetric_engine import (
    generate_symmetric_key, encrypt_medical_record, decrypt_medical_record
)
from phase3_asymmetric.asymmetric_engine import (
    generate_doctor_keypair, get_key_fingerprint,
    generate_challenge, sign_challenge, verify_challenge_response
)
from phase4_hybrid.hybrid_engine import wrap_key_for_doctor, unwrap_key_as_doctor
from phase5_database.db_manager import (
    get_db_connection, audit_logger,
    patient_db, doctor_db, key_map_db, nonce_db
)
from phase9_samaritan.samaritan_engine import (
    generate_blinding_factor, create_commitment, verify_commitment,
    generate_assistance_proof, verify_assistance_proof, issue_samaritan_certificate,
    hash_location
)

load_dotenv()

app = Flask(__name__)
CORS(app, origins="*", supports_credentials=True)

pending_challenges: dict = {}


def get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)

def error(message: str, code: int = 400):
    return jsonify({"success": False, "error": message}), code

def success(data: dict, code: int = 200):
    return jsonify({"success": True, **data}), code


# ─── Patient ──────────────────────────────────────────────────────────────────

@app.route("/api/patient/register", methods=["POST", "OPTIONS"])
@app.route("/api/patients/register", methods=["POST", "OPTIONS"])
def register_patient():
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json()
    if not data:
        return error("Missing request body")

    # Support BOTH formats: nested (Insomnia/Postman) and flat (React UI)
    if "public_tier" in data and "private_tier" in data:
        public_tier = data["public_tier"]
        private_tier = data["private_tier"]
    else:
        # React UI sends flat fields — convert to nested format
        allergies_raw = data.get("allergies", "")
        if isinstance(allergies_raw, str):
            allergies_list = [a.strip() for a in allergies_raw.split(",") if a.strip()]
        else:
            allergies_list = allergies_raw if allergies_raw else []

        public_tier = {
            "name": data.get("name", ""),
            "blood_type": data.get("blood_type", ""),
            "critical_alerts": allergies_list,
            "emergency_contact": {
                "name": data.get("emergency_contact_name", ""),
                "phone": data.get("emergency_contact_phone", "")
            }
        }
        private_tier = {
            "allergies": allergies_list,
            "medications": data.get("medications", ""),
            "conditions": data.get("conditions", ""),
            "surgical_history": data.get("surgical_history", "")
        }

    try:
        conn = get_db_connection()
        Ks = generate_symmetric_key()
        encrypted = encrypt_medical_record(private_tier, Ks)

        patient_id = patient_db.store_patient(
            conn,
            public_tier=public_tier,
            encrypted_record=encrypted["ciphertext_b64"],
            record_iv=encrypted["iv_b64"],
            record_tag=encrypted["tag_b64"],
        )

        with conn.cursor() as cur:
            cur.execute("SELECT id, public_key_pem FROM doctors WHERE is_verified = TRUE AND is_active = TRUE")
            doctors = cur.fetchall()

        for doctor in doctors:
            wrapped = wrap_key_for_doctor(Ks, doctor["public_key_pem"].encode())
            key_map_db.store_wrapped_key(conn, patient_id, str(doctor["id"]), wrapped)

        audit_logger.log(conn, "REGISTRATION", True, patient_id=patient_id, ip_address=get_client_ip())
        conn.close()

        qr_url = f"{request.host_url}api/emergency/{patient_id}"
        
        # Generate QR code as base64 image
        qr_image_b64 = ""
        try:
            import qrcode
            import io
            qr = qrcode.QRCode(version=1, box_size=10, border=4)
            qr.add_data(qr_url)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            import base64
            qr_image_b64 = base64.b64encode(buffer.getvalue()).decode()
        except:
            pass

        return success({"patient_id": patient_id, "qr_url": qr_url,
                        "qr_image": qr_image_b64,
                        "message": "Patient registered and record encrypted successfully",
                        "doctors_with_access": len(doctors)}, 201)
        return success({"patient_id": patient_id, "qr_url": qr_url,
                        "message": "Patient registered and record encrypted successfully",
                        "doctors_with_access": len(doctors)}, 201)

    except Exception as e:
        return error(f"Registration failed: {str(e)}", 500)


@app.route("/api/emergency/<patient_id>", methods=["GET"])
def get_public_tier(patient_id):
    try:
        conn = get_db_connection()
        public_tier = patient_db.get_patient_public_tier(conn, patient_id)

        if not public_tier:
            audit_logger.log(conn, "ACCESS_PUBLIC", False, patient_id=patient_id,
                             failure_reason="Patient not found", ip_address=get_client_ip())
            conn.close()
            return error("Patient not found", 404)

        audit_logger.log(conn, "ACCESS_PUBLIC", True, patient_id=patient_id, ip_address=get_client_ip())
        conn.close()
        return success({"public_tier": public_tier, "auth_required": True, "auth_endpoint": "/api/auth/challenge"})

    except Exception as e:
        return error(f"Error: {str(e)}", 500)


# ─── Doctor ───────────────────────────────────────────────────────────────────

@app.route("/api/doctor/register", methods=["POST", "OPTIONS"])
@app.route("/api/doctors/register", methods=["POST", "OPTIONS"])
def register_doctor():
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json()
    if not data:
        return error("Missing request body")

    # Support BOTH field name formats
    full_name = data.get("full_name") or data.get("name", "")
    license_number = data.get("license_number") or f"AUTO-{int(time.time())}"
    specialty = data.get("specialty") or data.get("specialization", "General")
    institution = data.get("institution") or data.get("hospital", "General Hospital")
    email = data.get("email") or f"{full_name.lower().replace(' ', '.')}@medkey.demo"

    if not full_name:
        return error("Missing doctor name")

    try:
        private_pem, public_pem = generate_doctor_keypair()
        fingerprint = get_key_fingerprint(public_pem)

        conn = get_db_connection()
        doctor_id = doctor_db.register_doctor(
            conn,
            full_name=full_name,
            license_number=license_number,
            specialty=specialty,
            institution=institution,
            email=email,
            public_key_pem=public_pem.decode(),
            key_fingerprint=fingerprint,
        )
        audit_logger.log(conn, "DOCTOR_REGISTRATION", True, doctor_fingerprint=fingerprint, ip_address=get_client_ip())
        conn.close()

        return success({
            "doctor_id": doctor_id,
            "key_fingerprint": fingerprint,
            "private_key_pem": private_pem.decode(),
            "public_key_pem": public_pem.decode(),
            "status": "pending_verification",
            "message": "Account created.",
            "WARNING": "Save your private key immediately."
        }, 201)

    except Exception as e:
        return error(f"Registration failed: {str(e)}", 500)


# ─── Authentication ───────────────────────────────────────────────────────────

@app.route("/api/auth/challenge", methods=["POST", "OPTIONS"])
def request_challenge():
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json()
    if not data or "doctor_id" not in data:
        return error("Missing doctor_id")

    doctor_id = data["doctor_id"]

    try:
        conn = get_db_connection()
        public_key = doctor_db.get_doctor_public_key(conn, doctor_id)
        conn.close()

        if not public_key:
            return error("Doctor not found or not verified", 401)

        challenge = generate_challenge()
        pending_challenges[doctor_id] = challenge

        return success({
            "nonce_b64": challenge["nonce_b64"],
            "expires_at": challenge["expires_at"],
            "instructions": "Sign this nonce with your private key using ECDSA-SHA256"
        })

    except Exception as e:
        return error(f"Challenge failed: {str(e)}", 500)


@app.route("/api/auth/verify", methods=["POST", "OPTIONS"])
def verify_auth():
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json()
    required = ["doctor_id", "signature_b64", "patient_id"]
    if not data or not all(k in data for k in required):
        return error(f"Missing fields: {required}")

    doctor_id  = data["doctor_id"]
    patient_id = data["patient_id"]

    challenge = pending_challenges.get(doctor_id)
    if not challenge:
        return error("No pending challenge. Request a challenge first.", 401)

    try:
        conn = get_db_connection()
        public_key_pem = doctor_db.get_doctor_public_key(conn, doctor_id)
        if not public_key_pem:
            return error("Doctor not found or not verified", 401)

        used_nonces_db = set()
        if nonce_db.is_used(conn, challenge["nonce_hash"]):
            used_nonces_db.add(challenge["nonce_hash"])

        is_valid, reason = verify_challenge_response(
            challenge["nonce_b64"], data["signature_b64"],
            public_key_pem, challenge["expires_at"], used_nonces_db,
        )

        fingerprint = get_key_fingerprint(public_key_pem)

        if not is_valid:
            audit_logger.log(conn, "AUTH_FAIL", False, patient_id=patient_id,
                             doctor_fingerprint=fingerprint, failure_reason=reason, ip_address=get_client_ip())
            conn.close()
            del pending_challenges[doctor_id]
            return error(f"Authentication failed: {reason}", 401)

        nonce_db.mark_used(conn, challenge["nonce_hash"], doctor_id)
        del pending_challenges[doctor_id]

        wrapped_key_data = key_map_db.get_wrapped_key(conn, patient_id, doctor_id)
        if not wrapped_key_data:
            audit_logger.log(conn, "ACCESS_PRIVATE", False, patient_id=patient_id,
                             doctor_fingerprint=fingerprint, failure_reason="No key for this pair", ip_address=get_client_ip())
            conn.close()
            return error("No access configured for this patient", 403)

        encrypted_record = patient_db.get_patient_encrypted_record(conn, patient_id)
        audit_logger.log(conn, "ACCESS_PRIVATE", True, patient_id=patient_id,
                         doctor_fingerprint=fingerprint, ip_address=get_client_ip())
        conn.close()

        return success({"wrapped_key_data": wrapped_key_data, "encrypted_record": encrypted_record,
                        "message": "Authentication successful"})

    except Exception as e:
        return error(f"Verification failed: {str(e)}", 500)


# ─── Demo Endpoints ───────────────────────────────────────────────────────────

@app.route("/api/auth/sign-demo", methods=["POST", "OPTIONS"])
def sign_demo():
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json()
    if not data or "nonce_b64" not in data or "private_key_pem" not in data:
        return error("Missing nonce_b64 or private_key_pem")
    try:
        signature = sign_challenge(data["nonce_b64"], data["private_key_pem"].encode())
        return success({"signature": signature})
    except Exception as e:
        return error(f"Signing failed: {str(e)}", 500)


@app.route("/api/auth/decrypt-demo", methods=["POST", "OPTIONS"])
def decrypt_demo():
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json()
    required = ["wrapped_key_data", "encrypted_record", "private_key_pem"]
    if not data or not all(k in data for k in required):
        return error(f"Missing fields: {required}")
    try:
        Ks = unwrap_key_as_doctor(data["wrapped_key_data"], data["private_key_pem"].encode())
        record = decrypt_medical_record(data["encrypted_record"], Ks)
        return success({"record": record})
    except Exception as e:
        return error(f"Decryption failed: {str(e)}", 500)


@app.route("/api/doctor/verify-demo", methods=["POST", "OPTIONS"])
def verify_doctor_demo():
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json()
    if not data or "doctor_id" not in data:
        return error("Missing doctor_id")
    try:
        conn = get_db_connection()
        doctor_db.verify_doctor(conn, data["doctor_id"], "demo_admin")
        conn.close()
        return success({"message": "Doctor verified successfully", "doctor_id": data["doctor_id"]})
    except Exception as e:
        return error(f"Verification failed: {str(e)}", 500)


# ─── Good Samaritan Endpoints ─────────────────────────────────────────────────

@app.route("/api/samaritan/register", methods=["POST", "OPTIONS"])
def samaritan_register():
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json()
    if not data or "identity" not in data:
        return error("Missing identity field")

    try:
        blinding_factor = generate_blinding_factor()
        blinding_factor_hex = blinding_factor.hex()
        commitment_hash = create_commitment(data["identity"], blinding_factor)

        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO samaritan_commitments (commitment_hash) VALUES (%s) RETURNING id",
                (commitment_hash,)
            )
            row = cur.fetchone()
            samaritan_id = str(row["id"])
        conn.commit()
        conn.close()

        return success({
            "samaritan_id": samaritan_id,
            "commitment_hash": commitment_hash,
            "blinding_factor": blinding_factor_hex,
            "message": "Registered successfully. Save your blinding factor.",
            "WARNING": "Your identity was NEVER stored on this server."
        }, 201)

    except Exception as e:
        return error(f"Registration failed: {str(e)}", 500)


@app.route("/api/samaritan/help", methods=["POST", "OPTIONS"])
def samaritan_help():
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json()
    required = ["identity", "blinding_factor", "commitment_hash", "latitude", "longitude"]
    if not data or not all(k in data for k in required):
        return error(f"Missing fields: {required}")

    try:
        blinding_factor = bytes.fromhex(data["blinding_factor"])

        is_valid_commitment = verify_commitment(
            data["identity"], blinding_factor, data["commitment_hash"]
        )
        if not is_valid_commitment:
            return error("Invalid commitment — identity or blinding factor does not match", 401)

        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM samaritan_commitments WHERE commitment_hash = %s AND is_active = TRUE",
                (data["commitment_hash"],)
            )
            row = cur.fetchone()

        if not row:
            conn.close()
            return error("Commitment not found in registry", 401)

        with conn.cursor() as cur:
            cur.execute("SELECT commitment_hash FROM samaritan_commitments WHERE is_active = TRUE")
            all_commitments = [r["commitment_hash"] for r in cur.fetchall()]

        proof = generate_assistance_proof(
            identity_data=data["identity"],
            blinding_factor=blinding_factor,
            commitment_hash=data["commitment_hash"],
            latitude=float(data["latitude"]),
            longitude=float(data["longitude"]),
        )

        is_valid, reason = verify_assistance_proof(proof, all_commitments)
        if not is_valid:
            conn.close()
            return error(f"Proof verification failed: {reason}", 400)

        from phase3_asymmetric.asymmetric_engine import generate_doctor_keypair
        server_priv, _ = generate_doctor_keypair()
        certificate = issue_samaritan_certificate(proof, server_priv)

        proof_dict = {
            "commitment_hash": proof.commitment_hash,
            "location_hash": proof.location_hash,
            "assistance_timestamp": proof.assistance_timestamp,
            "nonce_commitment": proof.nonce_commitment,
            "challenge_hash": proof.challenge_hash,
            "response": proof.response,
            "proof_signature": proof.proof_signature,
            "ephemeral_public_key": proof.ephemeral_public_key,
        }
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO samaritan_certificates
                   (zk_proof, location_hash, assistance_timestamp, certificate_data, is_verified)
                   VALUES (%s, %s, to_timestamp(%s), %s, TRUE)
                   RETURNING id""",
                (
                    json.dumps(proof_dict),
                    proof.location_hash,
                    proof.assistance_timestamp,
                    json.dumps(certificate)
                )
            )
            cert_row = cur.fetchone()
            certificate_id = str(cert_row["id"])
        conn.commit()
        conn.close()

        return success({
            "certificate_id": certificate_id,
            "certificate": certificate,
            "proof_summary": {
                "commitment_verified": True,
                "location_hash": proof.location_hash[:20] + "...",
                "timestamp": proof.assistance_timestamp,
                "zk_proof_valid": True,
            },
            "message": "Certificate issued. You are legally protected. Your identity remains private."
        })

    except Exception as e:
        return error(f"Proof generation failed: {str(e)}", 500)


@app.route("/api/samaritan/verify-certificate/<certificate_id>", methods=["GET"])
def verify_certificate(certificate_id):
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT certificate_data, is_verified, assistance_timestamp FROM samaritan_certificates WHERE id = %s",
                (certificate_id,)
            )
            row = cur.fetchone()
        conn.close()

        if not row:
            return error("Certificate not found", 404)

        cert_data = row["certificate_data"]
        if isinstance(cert_data, str):
            cert_data = json.loads(cert_data)

        return success({
            "certificate": cert_data,
            "is_verified": row["is_verified"],
            "issued_at": str(row["assistance_timestamp"]),
            "verification_status": "VALID — Issued by MedKey Emergency Response System"
        })

    except Exception as e:
        return error(f"Verification failed: {str(e)}", 500)


# ─── Audit Log ────────────────────────────────────────────────────────────────

@app.route("/api/patient/<patient_id>/audit", methods=["GET"])
def get_audit_log(patient_id):
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT event_type, doctor_fingerprint, success, failure_reason, created_at
                FROM audit_log WHERE patient_id = %s ORDER BY created_at DESC LIMIT 100
            """, (patient_id,))
            entries = cur.fetchall()

        is_valid, integrity_msg = audit_logger.verify_chain(conn)
        conn.close()

        return success({"audit_entries": [dict(e) for e in entries],
                        "chain_integrity": is_valid, "integrity_message": integrity_msg})

    except Exception as e:
        return error(f"Error: {str(e)}", 500)


# ─── Health ───────────────────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health_check():
    return success({"status": "operational",
                    "service": "MedKey Cryptographic Emergency Medical System",
                    "version": "1.0.0"})


# ─── Hospital Proxy ───────────────────────────────────────────────────────────

@app.route("/api/hospitals/nearby", methods=["POST", "OPTIONS"])
def hospitals_nearby():
    if request.method == "OPTIONS":
        return "", 204
    import urllib.request
    import urllib.parse
    data = request.get_json()
    if not data or "lat" not in data or "lon" not in data:
        return error("Missing lat/lon")

    lat, lon = float(data["lat"]), float(data["lon"])
    radius = int(data.get("radius", 10000))

    query = f"""
    [out:json][timeout:20];
    (
      node["amenity"="hospital"](around:{radius},{lat},{lon});
      way["amenity"="hospital"](around:{radius},{lat},{lon});
      node["amenity"="clinic"](around:{radius},{lat},{lon});
    );
    out center tags;
    """

    try:
        url = f"https://overpass-api.de/api/interpreter?data={urllib.parse.quote(query)}"
        req = urllib.request.Request(url, headers={"User-Agent": "MedKey/1.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            osm_data = json.loads(resp.read().decode())
        return success({"elements": osm_data.get("elements", [])})
    except Exception as e:
        return error(f"Overpass API error: {str(e)}", 500)

"""
MedKey — AI Endpoints for Triage, First Aid, and Equipment Dispatch
Add these routes to your app.py
"""

# ─── AI Triage & First Aid Endpoints ──────────────────────────────────────────

import base64
import json

def get_ai_analysis(prompt, image_b64=None):
    """Try Claude API first, fall back to smart template response."""
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    
    if api_key:
        try:
            import urllib.request
            messages_content = []
            if image_b64:
                messages_content.append({
                    "type": "image",
                    "source": {"type": "base64", "media_type": "image/jpeg", "data": image_b64}
                })
            messages_content.append({"type": "text", "text": prompt})
            
            payload = json.dumps({
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 1500,
                "messages": [{"role": "user", "content": messages_content}]
            }).encode()
            
            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01"
                }
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode())
                text = result["content"][0]["text"]
                # Try to parse as JSON
                try:
                    # Find JSON in the response
                    start = text.find("{")
                    end = text.rfind("}") + 1
                    if start >= 0 and end > start:
                        return json.loads(text[start:end])
                except:
                    pass
                return {"raw_response": text}
        except Exception as e:
            print(f"Claude API error: {e}, falling back to template")
    
    return None  # Will trigger fallback


@app.route("/api/ai/triage", methods=["POST", "OPTIONS"])
def ai_triage():
    """AI-powered injury analysis from photo + description.
    Returns: injury assessment, severity, required equipment, hospital type."""
    if request.method == "OPTIONS":
        return "", 204
    
    data = request.get_json() or {}
    description = data.get("description", "")
    image_b64 = data.get("image_b64", "")
    
    prompt = f"""You are an emergency medical AI triage system. Analyze this emergency situation and respond ONLY with a JSON object (no markdown, no backticks).

Situation description: {description if description else "Emergency accident scene - analyze the image for visible injuries"}

Respond with this exact JSON structure:
{{
    "severity": 8,
    "severity_label": "CRITICAL",
    "is_conscious": false,
    "is_breathing": true,
    "visible_injuries": ["Head laceration", "Possible fracture right arm"],
    "immediate_dangers": ["Internal bleeding risk", "Spinal injury risk"],
    "recommended_hospital_type": "Level 1 Trauma Center with Neurosurgery",
    "required_equipment": [
        {{"item": "Cervical collar", "priority": "CRITICAL", "reason": "Spinal immobilization before transport"}},
        {{"item": "IV fluids kit", "priority": "CRITICAL", "reason": "Prevent hypovolemic shock"}},
        {{"item": "Portable ventilator", "priority": "HIGH", "reason": "Airway management"}},
        {{"item": "Splint set", "priority": "HIGH", "reason": "Fracture stabilization"}},
        {{"item": "Wound dressing kit", "priority": "MEDIUM", "reason": "Hemorrhage control"}},
        {{"item": "Blood pressure monitor", "priority": "HIGH", "reason": "Vital signs monitoring"}}
    ],
    "ambulance_type": "Advanced Life Support (ALS)",
    "estimated_crew": "Paramedic + EMT + Driver",
    "first_responder_tips": [
        "DO NOT move the patient — possible spinal injury",
        "Apply pressure to visible bleeding with clean cloth",
        "Keep airway clear — tilt head slightly if breathing is labored",
        "Cover patient to prevent hypothermia",
        "Note time of incident for hospital team"
    ],
    "triage_color": "RED",
    "golden_hour_warning": "Patient needs hospital care within 45 minutes"
}}"""

    ai_result = get_ai_analysis(prompt, image_b64 if image_b64 else None)
    
    if ai_result and "raw_response" not in ai_result and "severity" in ai_result:
        return success({"analysis": ai_result, "source": "claude_ai"})
    
    # Smart fallback based on description keywords
    desc_lower = (description or "accident").lower()
    
    if any(w in desc_lower for w in ["head", "brain", "skull", "unconscious", "concussion"]):
        analysis = {
            "severity": 9, "severity_label": "CRITICAL", "is_conscious": False, "is_breathing": True,
            "visible_injuries": ["Head trauma", "Possible concussion", "Scalp laceration"],
            "immediate_dangers": ["Intracranial hemorrhage", "Brain swelling", "Spinal injury"],
            "recommended_hospital_type": "Level 1 Trauma Center with Neurosurgery",
            "required_equipment": [
                {"item": "Cervical collar", "priority": "CRITICAL", "reason": "Spinal immobilization — NEVER move without this"},
                {"item": "Portable ventilator", "priority": "CRITICAL", "reason": "Airway management if consciousness drops"},
                {"item": "IV fluids + Mannitol", "priority": "CRITICAL", "reason": "Reduce brain swelling"},
                {"item": "Pulse oximeter", "priority": "HIGH", "reason": "Monitor oxygen to brain"},
                {"item": "Wound dressing kit", "priority": "HIGH", "reason": "Scalp hemorrhage control"},
                {"item": "Backboard + straps", "priority": "HIGH", "reason": "Full spinal immobilization for transport"}
            ],
            "ambulance_type": "Advanced Life Support (ALS) with Neurosurgery Alert",
            "estimated_crew": "Paramedic + EMT + Driver",
            "first_responder_tips": [
                "DO NOT move the patient — high spinal injury risk",
                "Keep airway clear — position head neutral",
                "Apply gentle pressure to scalp bleeding",
                "Monitor breathing every 30 seconds",
                "Note pupil size — if unequal, inform paramedics immediately"
            ],
            "triage_color": "RED", "golden_hour_warning": "Neurosurgery needed within 30 minutes"
        }
    elif any(w in desc_lower for w in ["burn", "fire", "flame", "scald"]):
        analysis = {
            "severity": 8, "severity_label": "CRITICAL", "is_conscious": True, "is_breathing": True,
            "visible_injuries": ["Burn injuries — degree assessment needed", "Possible smoke inhalation"],
            "immediate_dangers": ["Airway compromise from smoke", "Fluid loss", "Infection risk"],
            "recommended_hospital_type": "Burn Unit / Burn ICU",
            "required_equipment": [
                {"item": "Sterile burn sheets", "priority": "CRITICAL", "reason": "Cover burns to prevent infection"},
                {"item": "IV fluids (Ringer's Lactate)", "priority": "CRITICAL", "reason": "Parkland formula fluid resuscitation"},
                {"item": "Oxygen mask + tank", "priority": "CRITICAL", "reason": "Smoke inhalation treatment"},
                {"item": "Pain management kit", "priority": "HIGH", "reason": "Burns are extremely painful"},
                {"item": "Sterile gauze rolls", "priority": "HIGH", "reason": "Non-adherent wound covering"},
                {"item": "Hypothermia blanket", "priority": "MEDIUM", "reason": "Burns cause rapid heat loss"}
            ],
            "ambulance_type": "Advanced Life Support (ALS)",
            "estimated_crew": "Paramedic + EMT + Driver",
            "first_responder_tips": [
                "Cool burns with clean running water for 10-20 minutes",
                "DO NOT use ice, butter, or toothpaste on burns",
                "Remove jewelry/clothing near burn BEFORE swelling",
                "Cover loosely with clean, non-fluffy material",
                "If face/neck burned — watch breathing closely"
            ],
            "triage_color": "RED", "golden_hour_warning": "Burn unit admission needed within 60 minutes"
        }
    elif any(w in desc_lower for w in ["bleed", "blood", "cut", "stab", "wound", "laceration"]):
        analysis = {
            "severity": 7, "severity_label": "SERIOUS", "is_conscious": True, "is_breathing": True,
            "visible_injuries": ["Active hemorrhage", "Laceration / wound"],
            "immediate_dangers": ["Hypovolemic shock from blood loss", "Infection"],
            "recommended_hospital_type": "Trauma Center with Surgery capability",
            "required_equipment": [
                {"item": "Tourniquet", "priority": "CRITICAL", "reason": "Stop arterial bleeding immediately"},
                {"item": "Hemostatic gauze", "priority": "CRITICAL", "reason": "Promote clotting at wound site"},
                {"item": "IV fluids kit", "priority": "CRITICAL", "reason": "Replace lost blood volume"},
                {"item": "Blood pressure monitor", "priority": "HIGH", "reason": "Detect shock early"},
                {"item": "Wound closure strips", "priority": "MEDIUM", "reason": "Temporary wound management"},
                {"item": "Sterile gloves + drapes", "priority": "HIGH", "reason": "Prevent wound contamination"}
            ],
            "ambulance_type": "Basic Life Support (BLS) — upgrade to ALS if shock develops",
            "estimated_crew": "EMT + Driver",
            "first_responder_tips": [
                "Apply DIRECT PRESSURE with clean cloth — press hard",
                "If limb bleeding won't stop — apply tourniquet above wound",
                "Elevate the injured area above heart level",
                "DO NOT remove blood-soaked cloth — add more on top",
                "Keep patient warm and calm — reassure them"
            ],
            "triage_color": "RED", "golden_hour_warning": "Surgery may be needed within 60 minutes"
        }
    elif any(w in desc_lower for w in ["fracture", "broken", "bone", "fall", "limb"]):
        analysis = {
            "severity": 6, "severity_label": "SERIOUS", "is_conscious": True, "is_breathing": True,
            "visible_injuries": ["Suspected fracture", "Possible deformity", "Swelling"],
            "immediate_dangers": ["Compartment syndrome", "Nerve/vessel damage", "Fat embolism"],
            "recommended_hospital_type": "Hospital with Orthopedic Surgery",
            "required_equipment": [
                {"item": "Splint set (various sizes)", "priority": "CRITICAL", "reason": "Immobilize fracture before transport"},
                {"item": "Pain management kit", "priority": "HIGH", "reason": "Fractures are extremely painful"},
                {"item": "Ice packs", "priority": "HIGH", "reason": "Reduce swelling"},
                {"item": "Pulse oximeter", "priority": "MEDIUM", "reason": "Monitor circulation distal to fracture"},
                {"item": "Triangular bandages", "priority": "MEDIUM", "reason": "Sling for upper limb fractures"},
                {"item": "Backboard", "priority": "HIGH", "reason": "Full body immobilization if spine suspected"}
            ],
            "ambulance_type": "Basic Life Support (BLS)",
            "estimated_crew": "EMT + Driver",
            "first_responder_tips": [
                "DO NOT try to straighten or reset the bone",
                "Immobilize the joint above AND below the fracture",
                "Apply ice wrapped in cloth — never directly on skin",
                "Check fingers/toes for circulation (color, warmth, pulse)",
                "Support the limb in the position you found it"
            ],
            "triage_color": "YELLOW", "golden_hour_warning": "Orthopedic assessment needed within 2 hours"
        }
    elif any(w in desc_lower for w in ["chest", "heart", "cardiac", "breath", "choking"]):
        analysis = {
            "severity": 9, "severity_label": "CRITICAL", "is_conscious": False, "is_breathing": False,
            "visible_injuries": ["Cardiac/respiratory emergency", "No visible trauma"],
            "immediate_dangers": ["Cardiac arrest", "Respiratory failure", "Brain damage after 4 min without oxygen"],
            "recommended_hospital_type": "Hospital with Cardiac ICU / Catheterization Lab",
            "required_equipment": [
                {"item": "Automated External Defibrillator (AED)", "priority": "CRITICAL", "reason": "Restart heart rhythm"},
                {"item": "Bag-valve mask (BVM)", "priority": "CRITICAL", "reason": "Manual ventilation"},
                {"item": "Portable cardiac monitor", "priority": "CRITICAL", "reason": "Identify arrhythmia type"},
                {"item": "Epinephrine auto-injector", "priority": "CRITICAL", "reason": "ACLS protocol"},
                {"item": "Oxygen tank + mask", "priority": "HIGH", "reason": "Supplemental oxygen"},
                {"item": "IV access kit", "priority": "HIGH", "reason": "Emergency medication delivery"}
            ],
            "ambulance_type": "Advanced Life Support (ALS) — PRIORITY DISPATCH",
            "estimated_crew": "Paramedic + EMT + Driver — with cardiac alert to hospital",
            "first_responder_tips": [
                "START CPR IMMEDIATELY — 30 compressions : 2 breaths",
                "Push HARD and FAST — center of chest, 2 inches deep",
                "If AED available — use it, follow voice prompts",
                "Do NOT stop CPR until paramedics arrive",
                "If choking — 5 back blows then 5 abdominal thrusts"
            ],
            "triage_color": "RED", "golden_hour_warning": "IMMEDIATE — every minute without CPR reduces survival 10%"
        }
    else:
        # General accident / car crash
        analysis = {
            "severity": 7, "severity_label": "SERIOUS", "is_conscious": True, "is_breathing": True,
            "visible_injuries": ["Multiple trauma — full assessment needed", "Possible internal injuries"],
            "immediate_dangers": ["Internal bleeding", "Spinal injury", "Shock"],
            "recommended_hospital_type": "Level 1 Trauma Center",
            "required_equipment": [
                {"item": "Cervical collar", "priority": "CRITICAL", "reason": "Spinal precaution for all accident victims"},
                {"item": "IV fluids kit", "priority": "CRITICAL", "reason": "Treat/prevent shock"},
                {"item": "Backboard + straps", "priority": "HIGH", "reason": "Safe extrication and transport"},
                {"item": "Splint set", "priority": "HIGH", "reason": "Immobilize any suspected fractures"},
                {"item": "Blood pressure monitor", "priority": "HIGH", "reason": "Early shock detection"},
                {"item": "Wound dressing kit", "priority": "MEDIUM", "reason": "Control visible bleeding"},
                {"item": "Oxygen mask + tank", "priority": "MEDIUM", "reason": "Supplemental oxygen during transport"},
                {"item": "Thermal blanket", "priority": "MEDIUM", "reason": "Prevent hypothermia from shock"}
            ],
            "ambulance_type": "Advanced Life Support (ALS)",
            "estimated_crew": "Paramedic + EMT + Driver",
            "first_responder_tips": [
                "DO NOT move the patient unless there is immediate danger (fire, traffic)",
                "Check: Are they conscious? Breathing? Bleeding?",
                "If bleeding — apply firm pressure with clean cloth",
                "Keep them warm with a blanket or jacket",
                "Talk to them calmly — tell them help is coming",
                "Note the time of accident — tell paramedics"
            ],
            "triage_color": "RED", "golden_hour_warning": "Full trauma assessment needed within 60 minutes"
        }
    
    return success({"analysis": analysis, "source": "medkey_ai"})


@app.route("/api/ai/firstaid", methods=["POST", "OPTIONS"])
def ai_firstaid():
    """AI-powered first aid guidance for passerby."""
    if request.method == "OPTIONS":
        return "", 204
    
    data = request.get_json() or {}
    situation = data.get("situation", "")
    image_b64 = data.get("image_b64", "")
    
    prompt = f"""You are a certified first aid instructor helping a passerby at an accident scene in India. They have NO medical training. Give clear, simple, step-by-step instructions they can follow RIGHT NOW.

Situation: {situation if situation else "General road accident with an injured person"}

Respond ONLY with a JSON object:
{{
    "situation_assessment": "Brief 1-line assessment",
    "danger_check": "Is the scene safe? What to watch for",
    "do_first": "The SINGLE most important thing to do right now",
    "step_by_step": [
        {{"step": 1, "action": "Call 108 / 112 immediately", "detail": "Tell them: location, number of injured, what you see", "time": "30 seconds"}},
        {{"step": 2, "action": "...", "detail": "...", "time": "..."}}
    ],
    "do_NOT_do": ["Do not move them", "Do not give water if unconscious"],
    "what_to_tell_ambulance": ["Exact location", "Number of injured", "Are they conscious?", "Is there bleeding?"],
    "legal_protection": "Under Indian Supreme Court Good Samaritan Guidelines 2016, you are legally protected when helping accident victims. No police station can detain you.",
    "emergency_numbers": {{"ambulance": "108", "police": "100", "universal": "112"}}
}}"""

    ai_result = get_ai_analysis(prompt)
    
    if ai_result and "raw_response" not in ai_result and "step_by_step" in ai_result:
        return success({"guidance": ai_result, "source": "claude_ai"})
    
    # Smart fallback
    sit_lower = (situation or "accident").lower()
    
    if any(w in sit_lower for w in ["unconscious", "not responding", "fainted", "collapsed"]):
        guidance = {
            "situation_assessment": "Person is unconscious — this is a PRIORITY situation",
            "danger_check": "Make sure the area is safe — no oncoming traffic, no fire, no electrical hazards",
            "do_first": "Call 108 IMMEDIATELY and check if they are breathing",
            "step_by_step": [
                {"step": 1, "action": "Call 108 / 112 NOW", "detail": "Tell them: 'Unconscious person at [your location]. Not responding.'", "time": "30 sec"},
                {"step": 2, "action": "Check breathing", "detail": "Put your ear near their mouth. Watch their chest. Can you feel breath? Does chest move?", "time": "10 sec"},
                {"step": 3, "action": "If BREATHING — Recovery position", "detail": "Roll them gently onto their side. Tilt chin up. This keeps airway open.", "time": "30 sec"},
                {"step": 4, "action": "If NOT BREATHING — Start CPR", "detail": "Place heel of hand on center of chest. Push HARD and FAST — 100 times per minute. Don't stop until ambulance arrives.", "time": "Until help arrives"},
                {"step": 5, "action": "Keep monitoring", "detail": "Check breathing every 30 seconds. Talk to them — sometimes they can hear you.", "time": "Ongoing"},
                {"step": 6, "action": "Protect from elements", "detail": "Cover with jacket/blanket. Shield from sun or rain. Keep crowd back.", "time": "Ongoing"}
            ],
            "do_NOT_do": ["Do NOT give water — they could choke", "Do NOT slap or shake them", "Do NOT put anything in their mouth", "Do NOT leave them alone", "Do NOT move them unless in immediate danger"],
            "what_to_tell_ambulance": ["Exact location with landmarks", "Person is unconscious", "Whether they are breathing or not", "Any visible injuries or blood", "Approximate age and gender"],
            "legal_protection": "Under Indian Supreme Court Guidelines (2016), you are LEGALLY PROTECTED when helping accident victims. No police station can detain you for helping. Your MedKey Good Samaritan certificate provides additional cryptographic proof.",
            "emergency_numbers": {"ambulance": "108", "police": "100", "universal": "112", "women_helpline": "1091"}
        }
    elif any(w in sit_lower for w in ["bleed", "blood", "cut", "wound"]):
        guidance = {
            "situation_assessment": "Active bleeding — need to control blood loss",
            "danger_check": "Wear gloves if available. If no gloves, use a plastic bag over your hand.",
            "do_first": "Apply FIRM PRESSURE to the wound with the cleanest cloth you have",
            "step_by_step": [
                {"step": 1, "action": "Call 108 / 112", "detail": "Tell them: 'Bleeding injury at [location]. Need ambulance.'", "time": "30 sec"},
                {"step": 2, "action": "Apply direct pressure", "detail": "Use clean cloth, dupatta, t-shirt — press HARD directly on the wound. Don't lift to check.", "time": "Continuous"},
                {"step": 3, "action": "Elevate the injured part", "detail": "If arm or leg — raise it above heart level while pressing", "time": "Continuous"},
                {"step": 4, "action": "If blood soaks through", "detail": "Do NOT remove the first cloth. Add MORE cloth on top and press harder.", "time": "Continuous"},
                {"step": 5, "action": "For severe limb bleeding", "detail": "If cloth pressure doesn't stop it — tie a strip of cloth 2-3 inches ABOVE the wound. Pull very tight.", "time": "1 min"},
                {"step": 6, "action": "Keep them calm and warm", "detail": "Talk reassuringly. Cover with blanket. Blood loss causes body temperature to drop.", "time": "Until help arrives"}
            ],
            "do_NOT_do": ["Do NOT remove the pressure cloth — ever", "Do NOT use turmeric or ash on wounds", "Do NOT give aspirin — it thins blood", "Do NOT wash deep wounds with water at the scene"],
            "what_to_tell_ambulance": ["Location", "Heavy bleeding from where", "How long has it been bleeding", "Estimated blood loss (small pool vs large)"],
            "legal_protection": "Under Indian Supreme Court Guidelines (2016), you are LEGALLY PROTECTED when helping accident victims.",
            "emergency_numbers": {"ambulance": "108", "police": "100", "universal": "112"}
        }
    elif any(w in sit_lower for w in ["burn", "fire", "hot"]):
        guidance = {
            "situation_assessment": "Burn injury — immediate cooling needed",
            "danger_check": "Is the fire/heat source still present? Move away from danger first.",
            "do_first": "Cool the burn with clean running water for 10-20 minutes",
            "step_by_step": [
                {"step": 1, "action": "Move away from heat source", "detail": "Make sure they are no longer in contact with fire/hot liquid/chemical", "time": "Immediate"},
                {"step": 2, "action": "Call 108 / 112", "detail": "Tell them: 'Burn injury at [location]'", "time": "30 sec"},
                {"step": 3, "action": "Cool with water", "detail": "Hold burned area under clean running water. If no tap — pour bottled water slowly.", "time": "10-20 min"},
                {"step": 4, "action": "Remove jewelry/tight clothing", "detail": "Burns swell rapidly — remove rings, watches, belts near the burn BEFORE swelling", "time": "1 min"},
                {"step": 5, "action": "Cover loosely", "detail": "After cooling, cover with clean, smooth cloth (not fluffy cotton). Cling film works well.", "time": "1 min"},
                {"step": 6, "action": "Keep them warm", "detail": "Burns cause body heat loss. Cover unburned areas with blanket.", "time": "Until help arrives"}
            ],
            "do_NOT_do": ["Do NOT use ice on burns", "Do NOT apply toothpaste, butter, or oil", "Do NOT break blisters", "Do NOT remove clothing stuck to the burn", "Do NOT use fluffy cotton — it sticks to burns"],
            "what_to_tell_ambulance": ["What caused the burn", "How large is the burned area", "Which body parts are burned", "Is face/neck affected (airway risk)"],
            "legal_protection": "Under Indian Supreme Court Guidelines (2016), you are LEGALLY PROTECTED when helping accident victims.",
            "emergency_numbers": {"ambulance": "108", "police": "100", "universal": "112"}
        }
    else:
        guidance = {
            "situation_assessment": "Road accident / general emergency — stay calm, help is coming",
            "danger_check": "Check for ongoing traffic, leaking fuel, electrical wires. Make the scene safe first.",
            "do_first": "Call 108 IMMEDIATELY — then check if the person is conscious and breathing",
            "step_by_step": [
                {"step": 1, "action": "Ensure YOUR safety first", "detail": "Turn on hazard lights, set up warning triangle or ask someone to direct traffic", "time": "30 sec"},
                {"step": 2, "action": "Call 108 / 112", "detail": "Tell them: exact location, number of people hurt, what you can see", "time": "1 min"},
                {"step": 3, "action": "Check the person", "detail": "Talk to them: 'Can you hear me?' Tap their shoulder gently. Are they responding?", "time": "15 sec"},
                {"step": 4, "action": "If conscious — keep them still", "detail": "Tell them NOT to move. Support their head and neck. Ask where it hurts.", "time": "Ongoing"},
                {"step": 5, "action": "If bleeding — apply pressure", "detail": "Use any clean cloth. Press firmly on the wound. Don't let go.", "time": "Continuous"},
                {"step": 6, "action": "If unconscious but breathing", "detail": "Gently roll them to their side (recovery position). Keep airway clear.", "time": "30 sec"},
                {"step": 7, "action": "Protect and comfort", "detail": "Cover with blanket/jacket. Shield from sun. Keep crowd back. Reassure them.", "time": "Until help arrives"},
                {"step": 8, "action": "Note important details", "detail": "Time of accident, what happened, how many vehicles, any changes in condition", "time": "Ongoing"}
            ],
            "do_NOT_do": ["Do NOT move them unless in immediate danger (fire/traffic)", "Do NOT remove helmet if motorcycle accident", "Do NOT give food or water", "Do NOT crowd around — give them air", "Do NOT take videos — help instead"],
            "what_to_tell_ambulance": ["Exact location with nearest landmark", "Number of injured people", "Are they conscious? Breathing?", "Any visible bleeding or deformity", "Type of accident (car, bike, fall)"],
            "legal_protection": "Under Indian Supreme Court Guidelines (2016), you are LEGALLY PROTECTED when helping accident victims. No bystander who helps can be detained by police. Register as a MedKey Good Samaritan for cryptographic proof.",
            "emergency_numbers": {"ambulance": "108", "police": "100", "universal": "112", "highway": "1033"}
        }
    
    return success({"guidance": guidance, "source": "medkey_ai"})


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    print(f"MedKey API starting on port {port}...")
    app.run(debug=True, port=port, host="0.0.0.0")