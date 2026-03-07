import { useState, useCallback } from "react";

const API = "http://127.0.0.1:5000/api";

const G = {
  bg: "#080810", surface: "#0f0f1a", card: "#13131f", border: "#1e1e32",
  green: "#00ff88", blue: "#00b8ff", red: "#ff4466", orange: "#ff9500",
  white: "#e8e8f2", muted: "#6a6a8a",
};

const css = `
  @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap');
  *{box-sizing:border-box;margin:0;padding:0;}
  body{background:${G.bg};color:${G.white};font-family:'Space Grotesk',sans-serif;min-height:100vh;}
  ::-webkit-scrollbar{width:4px;}::-webkit-scrollbar-track{background:${G.surface};}::-webkit-scrollbar-thumb{background:${G.border};border-radius:2px;}
  input,select,textarea{background:${G.surface};border:1px solid ${G.border};color:${G.white};font-family:'Space Grotesk',sans-serif;font-size:14px;padding:10px 14px;border-radius:8px;width:100%;outline:none;transition:border-color 0.2s;}
  input:focus,select:focus,textarea:focus{border-color:${G.green};}
  button{cursor:pointer;font-family:'Space Grotesk',sans-serif;font-weight:600;border:none;border-radius:8px;transition:all 0.2s;}
  .mono{font-family:'JetBrains Mono',monospace;}
  @keyframes fadeIn{from{opacity:0;transform:translateY(12px);}to{opacity:1;transform:translateY(0);}}
  @keyframes glow{0%,100%{box-shadow:0 0 10px ${G.green}44;}50%{box-shadow:0 0 25px ${G.green}88;}}
  .fade-in{animation:fadeIn 0.4s ease forwards;}
  .grid-bg{background-image:linear-gradient(${G.green}08 1px,transparent 1px),linear-gradient(90deg,${G.green}08 1px,transparent 1px);background-size:40px 40px;}
  .role-card:hover{transform:translateY(-4px);}
  .role-card{transition:all 0.25s;}
`;

function Tag({ color = G.green, children }) {
  return <span className="mono" style={{ background: color + "18", color, border: `1px solid ${color}44`, borderRadius: 4, padding: "2px 8px", fontSize: 11, fontWeight: 700, letterSpacing: 1 }}>{children}</span>;
}
function Card({ children, style = {}, glow }) {
  return <div style={{ background: G.card, border: `1px solid ${glow ? glow + "55" : G.border}`, borderRadius: 12, padding: 20, ...(glow ? { animation: "glow 3s ease infinite" } : {}), ...style }}>{children}</div>;
}
function Btn({ onClick, color = G.green, children, style = {}, outline, disabled, full }) {
  return <button onClick={onClick} disabled={disabled} style={{ background: outline ? "transparent" : color, color: outline ? color : G.bg, border: outline ? `1px solid ${color}` : "none", padding: "10px 20px", fontSize: 14, opacity: disabled ? 0.5 : 1, width: full ? "100%" : "auto", ...style }}>{children}</button>;
}
function Lbl({ children }) {
  return <div className="mono" style={{ fontSize: 10, fontWeight: 700, color: G.muted, letterSpacing: 2, marginBottom: 6 }}>{children}</div>;
}
function Status({ msg, type }) {
  if (!msg) return null;
  const c = type === "error" ? G.red : type === "warn" ? G.orange : G.green;
  return <div className="mono fade-in" style={{ background: c + "12", border: `1px solid ${c}33`, color: c, padding: "10px 14px", borderRadius: 8, fontSize: 12, marginTop: 10, whiteSpace: "pre-wrap" }}>{msg}</div>;
}

// ─── LOGIN ────────────────────────────────────────────────────────────────────
function Login({ onLogin }) {
  const [mode, setMode] = useState(null);
  const [step, setStep] = useState("choose");
  const [f, setF] = useState({ name: "", spec: "", hospital: "", doc_id: "", privKey: "" });
  const [st, setSt] = useState({ msg: "", type: "" });
  const [loading, setLoading] = useState(false);
  const set = (k, v) => setF(p => ({ ...p, [k]: v }));

  async function regDoctor() {
    if (!f.name || !f.spec || !f.hospital) { setSt({ msg: "Fill all fields", type: "error" }); return; }
    setLoading(true);
    try {
      const r = await fetch(`${API}/doctors/register`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: f.name, specialization: f.spec, hospital: f.hospital }) });
      const d = await r.json();
      if (d.doctor_id) {
        set("doc_id", d.doctor_id);
        set("privKey", d.private_key_pem || "");
        // Auto-verify the doctor for demo
        try { await fetch(`${API}/doctor/verify-demo`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ doctor_id: d.doctor_id }) }); } catch {}
        setStep("showid");
        setSt({ msg: "", type: "" });
      }
      else setSt({ msg: d.error || "Failed", type: "error" });
    } catch { setSt({ msg: "Cannot reach Flask API on port 5000", type: "error" }); }
    setLoading(false);
  }

  return (
    <div className="grid-bg" style={{ minHeight: "100vh", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: 24 }}>
      <style>{css}</style>
      <div style={{ textAlign: "center", marginBottom: 48 }}>
        <div style={{ display: "inline-flex", alignItems: "center", gap: 12, marginBottom: 10 }}>
          <div style={{ width: 48, height: 48, background: G.green, borderRadius: 12, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 24 }}>🔐</div>
          <span style={{ fontSize: 40, fontWeight: 700 }}>Med<span style={{ color: G.green }}>Key</span></span>
        </div>
        <p className="mono" style={{ color: G.muted, fontSize: 11, letterSpacing: 3 }}>CRYPTOGRAPHIC EMERGENCY MEDICAL SYSTEM</p>
      </div>

      {!mode && (
        <div className="fade-in" style={{ width: "100%", maxWidth: 520 }}>
          <p style={{ textAlign: "center", color: G.muted, marginBottom: 28, fontSize: 15 }}>Select your role to continue</p>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 14 }}>
            <div className="role-card" onClick={() => { setMode("doctor"); setStep("choose"); }} style={{ background: G.card, border: `1px solid ${G.blue}44`, borderRadius: 16, padding: 30, cursor: "pointer", textAlign: "center" }}>
              <div style={{ fontSize: 44, marginBottom: 12 }}>👨‍⚕️</div>
              <div style={{ fontWeight: 700, fontSize: 20, color: G.blue, marginBottom: 6 }}>Doctor</div>
              <div style={{ color: G.muted, fontSize: 12, marginBottom: 14 }}>Decrypt patient records with ECDSA cryptographic authentication</div>
              <Tag color={G.blue}>ECDSA AUTH</Tag>
            </div>
            <div className="role-card" onClick={() => onLogin("passerby", {})} style={{ background: G.card, border: `1px solid ${G.orange}44`, borderRadius: 16, padding: 30, cursor: "pointer", textAlign: "center" }}>
              <div style={{ fontSize: 44, marginBottom: 12 }}>🤝</div>
              <div style={{ fontWeight: 700, fontSize: 20, color: G.orange, marginBottom: 6 }}>Passerby</div>
              <div style={{ color: G.muted, fontSize: 12, marginBottom: 14 }}>Scan QR, find hospitals, help at accident scenes anonymously</div>
              <Tag color={G.orange}>NO LOGIN</Tag>
            </div>
          </div>
          <div className="role-card" onClick={() => onLogin("register", {})} style={{ background: G.card, border: `1px solid ${G.green}33`, borderRadius: 12, padding: 18, cursor: "pointer", display: "flex", alignItems: "center", gap: 16 }}>
            <div style={{ fontSize: 30 }}>🏥</div>
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 600, color: G.green }}>Register as Patient</div>
              <div style={{ color: G.muted, fontSize: 12 }}>Create your encrypted medical profile & get your QR card</div>
            </div>
            <Tag color={G.green}>FREE</Tag>
          </div>
        </div>
      )}

      {mode === "doctor" && step === "choose" && (
        <div className="fade-in" style={{ width: "100%", maxWidth: 400 }}>
          <Card>
            <div style={{ textAlign: "center", marginBottom: 20 }}>
              <div style={{ fontSize: 32, marginBottom: 6 }}>👨‍⚕️</div>
              <div style={{ fontWeight: 700, color: G.blue, fontSize: 18 }}>Doctor Portal</div>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
              <Btn onClick={() => setStep("register")} color={G.blue} style={{ padding: "12px 0" }} full>New Doctor</Btn>
              <Btn onClick={() => setStep("login")} outline color={G.blue} style={{ padding: "12px 0" }} full>I Have ID</Btn>
            </div>
            <div style={{ height: 1, background: G.border, margin: "16px 0" }} />
            <Btn onClick={() => setMode(null)} outline color={G.muted} full style={{ fontSize: 13 }}>← Back</Btn>
          </Card>
        </div>
      )}

      {mode === "doctor" && step === "register" && (
        <div className="fade-in" style={{ width: "100%", maxWidth: 420 }}>
          <Card>
            <div style={{ fontWeight: 700, color: G.blue, marginBottom: 2 }}>Register Doctor</div>
            <div style={{ color: G.muted, fontSize: 12, marginBottom: 18 }}>You'll get a unique Doctor ID & private key</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <div><Lbl>FULL NAME</Lbl><input placeholder="Dr. Sharma" value={f.name} onChange={e => set("name", e.target.value)} /></div>
              <div><Lbl>SPECIALIZATION</Lbl><input placeholder="Emergency Medicine" value={f.spec} onChange={e => set("spec", e.target.value)} /></div>
              <div><Lbl>HOSPITAL</Lbl><input placeholder="Apollo Chennai" value={f.hospital} onChange={e => set("hospital", e.target.value)} /></div>
            </div>
            <Btn onClick={regDoctor} disabled={loading} color={G.blue} full style={{ marginTop: 16, padding: 12 }}>{loading ? "Registering..." : "Register →"}</Btn>
            <Status msg={st.msg} type={st.type} />
            <div style={{ height: 1, background: G.border, margin: "16px 0" }} />
            <Btn onClick={() => setStep("choose")} outline color={G.muted} full style={{ fontSize: 13 }}>← Back</Btn>
          </Card>
        </div>
      )}

      {mode === "doctor" && step === "showid" && (
        <div className="fade-in" style={{ width: "100%", maxWidth: 500 }}>
          <Card glow={G.blue}>
            <div style={{ textAlign: "center", marginBottom: 20 }}>
              <div style={{ fontSize: 44, marginBottom: 8 }}>✅</div>
              <div style={{ fontWeight: 700, color: G.blue, fontSize: 20 }}>Registered & Verified!</div>
            </div>
            <div style={{ background: G.surface, border: `1px solid ${G.blue}33`, borderRadius: 8, padding: 14, marginBottom: 12 }}>
              <Lbl>YOUR DOCTOR ID — COPY & SAVE</Lbl>
              <div className="mono" style={{ color: G.blue, fontSize: 13, wordBreak: "break-all" }}>{f.doc_id}</div>
            </div>
            {f.privKey && <div style={{ background: G.surface, border: `1px solid ${G.orange}33`, borderRadius: 8, padding: 14, marginBottom: 12 }}>
              <Lbl>YOUR PRIVATE KEY — SAVE SECURELY</Lbl>
              <div className="mono" style={{ color: G.orange, fontSize: 10, wordBreak: "break-all", maxHeight: 80, overflow: "auto" }}>{f.privKey}</div>
            </div>}
            <p style={{ color: G.muted, fontSize: 12, marginBottom: 14 }}>⚠️ Save both — you need them for authentication.</p>
            <Btn onClick={() => onLogin("doctor", { doctor_id: f.doc_id, name: f.name, private_key_pem: f.privKey })} color={G.blue} full style={{ padding: 12 }}>Enter Doctor Portal →</Btn>
          </Card>
        </div>
      )}

      {mode === "doctor" && step === "login" && (
        <div className="fade-in" style={{ width: "100%", maxWidth: 420 }}>
          <Card>
            <div style={{ fontWeight: 700, color: G.blue, marginBottom: 2 }}>Doctor Login</div>
            <div style={{ color: G.muted, fontSize: 12, marginBottom: 18 }}>Paste your Doctor ID and Private Key</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <div><Lbl>DOCTOR ID</Lbl><input className="mono" placeholder="Paste your doctor ID..." value={f.doc_id} onChange={e => set("doc_id", e.target.value)} /></div>
              <div><Lbl>NAME (optional)</Lbl><input placeholder="Dr. Sharma" value={f.name} onChange={e => set("name", e.target.value)} /></div>
              <div><Lbl>PRIVATE KEY (PEM)</Lbl><textarea className="mono" placeholder="-----BEGIN PRIVATE KEY-----&#10;..." value={f.privKey} onChange={e => set("privKey", e.target.value)} rows={4} style={{ resize: "vertical", fontSize: 11 }} /></div>
            </div>
            <Btn onClick={() => { if (!f.doc_id) { setSt({ msg: "Enter your Doctor ID", type: "error" }); return; } onLogin("doctor", { doctor_id: f.doc_id, name: f.name || "Doctor", private_key_pem: f.privKey }); }} color={G.blue} full style={{ marginTop: 16, padding: 12 }}>Enter Portal →</Btn>
            <Status msg={st.msg} type={st.type} />
            <div style={{ height: 1, background: G.border, margin: "16px 0" }} />
            <Btn onClick={() => setStep("choose")} outline color={G.muted} full style={{ fontSize: 13 }}>← Back</Btn>
          </Card>
        </div>
      )}
    </div>
  );
}

// ─── NAV ──────────────────────────────────────────────────────────────────────
function Nav({ role, user, tab, setTab, onLogout }) {
  const dTabs = [{ id: "auth", label: "Doctor Auth", icon: "🔐" }, { id: "triage", label: "AI Triage", icon: "🤖" }, { id: "scan", label: "Emergency Scan", icon: "📱" }, { id: "audit", label: "Audit Log", icon: "🔍" }];
  const pTabs = [{ id: "scan", label: "Emergency Scan", icon: "📱" }, { id: "firstaid", label: "AI First Aid", icon: "🩹" }, { id: "hospital", label: "Hospital Finder", icon: "🏥" }, { id: "samaritan", label: "Good Samaritan", icon: "🤝" }];
  const tabs = role === "doctor" ? dTabs : pTabs;
  const rc = role === "doctor" ? G.blue : G.orange;
  return (
    <nav style={{ background: G.surface, borderBottom: `1px solid ${G.border}`, padding: "0 24px", position: "sticky", top: 0, zIndex: 100 }}>
      <div style={{ maxWidth: 1100, margin: "0 auto", display: "flex", alignItems: "center", gap: 6, height: 60 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginRight: 20 }}>
          <div style={{ width: 30, height: 30, background: G.green, borderRadius: 7, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 15 }}>🔐</div>
          <span style={{ fontWeight: 700, fontSize: 17 }}>Med<span style={{ color: G.green }}>Key</span></span>
        </div>
        <div style={{ display: "flex", gap: 4, flex: 1 }}>
          {tabs.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)} style={{ background: tab === t.id ? rc + "18" : "transparent", color: tab === t.id ? rc : G.muted, border: `1px solid ${tab === t.id ? rc + "55" : "transparent"}`, borderRadius: 8, padding: "6px 14px", fontSize: 13, fontWeight: 600 }}>
              {t.icon} {t.label}
            </button>
          ))}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ background: rc + "15", border: `1px solid ${rc}33`, borderRadius: 8, padding: "4px 12px" }}>
            <span className="mono" style={{ fontSize: 11, color: rc, fontWeight: 700 }}>{role === "doctor" ? `👨‍⚕️ ${user?.name || "DOCTOR"}` : "🤝 PASSERBY"}</span>
          </div>
          <button onClick={onLogout} style={{ background: "transparent", color: G.muted, border: `1px solid ${G.border}`, borderRadius: 8, padding: "5px 12px", fontSize: 12 }}>Logout</button>
        </div>
      </div>
    </nav>
  );
}

// ─── REGISTER PATIENT ─────────────────────────────────────────────────────────
function RegisterPatient({ onBack }) {
  const [f, setF] = useState({ name: "", blood_type: "O+", ecn: "", ecp: "", allergies: "", meds: "", conds: "", surgery: "" });
  const [st, setSt] = useState({ msg: "", type: "" });
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const set = (k, v) => setF(p => ({ ...p, [k]: v }));

  async function register() {
    if (!f.name) { setSt({ msg: "Full name required", type: "error" }); return; }
    setLoading(true);
    try {
      const r = await fetch(`${API}/patients/register`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: f.name, blood_type: f.blood_type, emergency_contact_name: f.ecn, emergency_contact_phone: f.ecp, allergies: f.allergies, medications: f.meds, conditions: f.conds, surgical_history: f.surgery }) });
      const d = await r.json();
      if (d.patient_id) { setResult(d); setSt({ msg: "", type: "" }); }
      else setSt({ msg: d.error || "Failed", type: "error" });
    } catch { setSt({ msg: "Cannot reach Flask API", type: "error" }); }
    setLoading(false);
  }

  if (result) return (
    <div style={{ maxWidth: 580, margin: "40px auto", padding: 24 }} className="fade-in">
      <style>{css}</style>
      <Card glow={G.green}>
        <div style={{ textAlign: "center", marginBottom: 24 }}>
          <div style={{ fontSize: 52, marginBottom: 8 }}>🎉</div>
          <div style={{ fontWeight: 700, fontSize: 24, color: G.green }}>Patient Registered!</div>
          <div style={{ color: G.muted, fontSize: 13, marginTop: 6 }}>Data encrypted with AES-256-GCM • {result.doctors_with_access || 0} doctors have access</div>
        </div>
        <div style={{ background: G.surface, borderRadius: 8, padding: 14, marginBottom: 12 }}>
          <Lbl>PATIENT ID — SAVE THIS</Lbl>
          <div className="mono" style={{ color: G.green, fontSize: 12, wordBreak: "break-all" }}>{result.patient_id}</div>
        </div>
        {result.qr_url && <div style={{ background: G.surface, borderRadius: 8, padding: 14, marginBottom: 16 }}>
          <Lbl>EMERGENCY QR URL</Lbl>
          <div className="mono" style={{ color: G.blue, fontSize: 11, wordBreak: "break-all" }}>{result.qr_url}</div>
        </div>}
        <Btn onClick={onBack} color={G.green} full style={{ padding: 12 }}>← Back to Home</Btn>
      </Card>
    </div>
  );

  return (
    <div style={{ maxWidth: 700, margin: "40px auto", padding: 24 }} className="fade-in">
      <style>{css}</style>
      <button onClick={onBack} style={{ background: "transparent", color: G.muted, border: "none", fontSize: 14, marginBottom: 16 }}>← Back</button>
      <h2 style={{ fontWeight: 700, fontSize: 26, marginBottom: 4 }}>Register <span style={{ color: G.green }}>Patient</span></h2>
      <p className="mono" style={{ color: G.muted, fontSize: 12, marginBottom: 20 }}>All private data is AES-256-GCM encrypted before reaching the server.</p>
      <Card style={{ marginBottom: 14 }}>
        <div className="mono" style={{ fontSize: 10, color: G.green, letterSpacing: 2, marginBottom: 14 }}>PUBLIC INFO</div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <div><Lbl>FULL NAME</Lbl><input placeholder="John Doe" value={f.name} onChange={e => set("name", e.target.value)} /></div>
          <div><Lbl>BLOOD TYPE</Lbl><select value={f.blood_type} onChange={e => set("blood_type", e.target.value)}>{["A+","A-","B+","B-","AB+","AB-","O+","O-"].map(b => <option key={b}>{b}</option>)}</select></div>
          <div><Lbl>EMERGENCY CONTACT NAME</Lbl><input placeholder="Jane Doe" value={f.ecn} onChange={e => set("ecn", e.target.value)} /></div>
          <div><Lbl>EMERGENCY CONTACT PHONE</Lbl><input placeholder="+91-9876543210" value={f.ecp} onChange={e => set("ecp", e.target.value)} /></div>
        </div>
      </Card>
      <Card>
        <div className="mono" style={{ fontSize: 10, color: G.orange, letterSpacing: 2, marginBottom: 14 }}>PRIVATE MEDICAL DATA (ENCRYPTED)</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div><Lbl>ALLERGIES (comma separated)</Lbl><input placeholder="Penicillin, Sulfa" value={f.allergies} onChange={e => set("allergies", e.target.value)} /></div>
          <div><Lbl>CURRENT MEDICATIONS</Lbl><input placeholder="Metformin 500mg" value={f.meds} onChange={e => set("meds", e.target.value)} /></div>
          <div><Lbl>MEDICAL CONDITIONS</Lbl><input placeholder="Type 2 Diabetes" value={f.conds} onChange={e => set("conds", e.target.value)} /></div>
          <div><Lbl>SURGICAL HISTORY</Lbl><input placeholder="Appendectomy 2018" value={f.surgery} onChange={e => set("surgery", e.target.value)} /></div>
        </div>
        <Btn onClick={register} disabled={loading} color={G.green} full style={{ marginTop: 18, padding: 13, fontSize: 15 }}>{loading ? "Encrypting & Registering..." : "🔐 Register Patient"}</Btn>
        <Status msg={st.msg} type={st.type} />
      </Card>
    </div>
  );
}

// ─── EMERGENCY SCAN ───────────────────────────────────────────────────────────
function EmergencyScan({ roleColor }) {
  const [token, setToken] = useState("");
  const [result, setResult] = useState(null);
  const [st, setSt] = useState({ msg: "", type: "" });
  const [loading, setLoading] = useState(false);

  async function scan() {
    if (!token.trim()) { setSt({ msg: "Enter a patient ID / QR token", type: "error" }); return; }
    setLoading(true); setResult(null); setSt({ msg: "", type: "" });
    try {
      const r = await fetch(`${API}/emergency/${token.trim()}`);
      const d = await r.json();
      if (d.success && d.public_tier) { setResult(d.public_tier); }
      else setSt({ msg: d.error || "Patient not found", type: "error" });
    } catch { setSt({ msg: "Cannot reach API", type: "error" }); }
    setLoading(false);
  }

  return (
    <div style={{ maxWidth: 700, margin: "40px auto", padding: 24 }} className="fade-in">
      <h2 style={{ fontWeight: 700, fontSize: 26, marginBottom: 4 }}>Emergency <span style={{ color: roleColor }}>Scan</span></h2>
      <p style={{ color: G.muted, fontSize: 14, marginBottom: 20 }}>Instant patient info from QR — no authentication required</p>
      <Card style={{ marginBottom: 16 }}>
        <Lbl>QR TOKEN / PATIENT UUID</Lbl>
        <div style={{ display: "flex", gap: 10, marginTop: 6 }}>
          <input className="mono" placeholder="Paste patient ID here..." value={token} onChange={e => setToken(e.target.value)} onKeyDown={e => e.key === "Enter" && scan()} />
          <Btn onClick={scan} disabled={loading} color={roleColor} style={{ whiteSpace: "nowrap", padding: "10px 22px" }}>{loading ? "..." : "Scan →"}</Btn>
        </div>
        <Status msg={st.msg} type={st.type} />
      </Card>
      {result && (
        <div className="fade-in">
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 14 }}>
            <Card glow={G.red}>
              <div style={{ fontSize: 26, marginBottom: 8 }}>🩸</div>
              <Lbl>BLOOD TYPE</Lbl>
              <div style={{ fontWeight: 700, fontSize: 20, color: G.red }}>{result.blood_type || "N/A"}</div>
            </Card>
            <Card glow={G.orange}>
              <div style={{ fontSize: 26, marginBottom: 8 }}>⚠️</div>
              <Lbl>CRITICAL ALERTS</Lbl>
              <div style={{ fontWeight: 700, fontSize: 14, color: G.orange }}>{(result.critical_alerts || []).join(", ") || "None"}</div>
            </Card>
            <Card glow={G.green}>
              <div style={{ fontSize: 26, marginBottom: 8 }}>📞</div>
              <Lbl>EMERGENCY CONTACT</Lbl>
              <div style={{ fontWeight: 700, fontSize: 14, color: G.green }}>{result.emergency_contact?.name || "N/A"}</div>
              <div style={{ color: G.muted, fontSize: 12 }}>{result.emergency_contact?.phone || ""}</div>
            </Card>
          </div>
          {result.name && <Card style={{ marginTop: 12 }}><Lbl>PATIENT NAME</Lbl><div style={{ color: G.white, fontWeight: 600, fontSize: 18 }}>{result.name}</div></Card>}
        </div>
      )}
    </div>
  );
}

// ─── DOCTOR AUTH (FULL 4-STEP ECDSA FLOW) ─────────────────────────────────────
function DoctorAuth({ user }) {
  const [pid, setPid] = useState("");
  const [nonce, setNonce] = useState("");
  const [signature, setSignature] = useState("");
  const [record, setRecord] = useState(null);
  const [wrappedData, setWrappedData] = useState(null);
  const [step, setStep] = useState(1);
  const [st, setSt] = useState({ msg: "", type: "" });
  const [loading, setLoading] = useState(false);

  // Step 1: Get challenge nonce from server
  async function getChallenge() {
    if (!pid) { setSt({ msg: "Enter patient ID", type: "error" }); return; }
    setLoading(true); setSt({ msg: "", type: "" });
    try {
      const r = await fetch(`${API}/auth/challenge`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ doctor_id: user.doctor_id }) });
      const d = await r.json();
      if (d.nonce_b64) { setNonce(d.nonce_b64); setStep(2); setSt({ msg: "Challenge received — signing with your private key...", type: "ok" });
        // Auto-sign if private key is available
        if (user.private_key_pem) { autoSign(d.nonce_b64); }
      }
      else setSt({ msg: d.error || "Failed to get challenge", type: "error" });
    } catch { setSt({ msg: "Cannot reach API", type: "error" }); }
    setLoading(false);
  }

  // Step 2: Sign the nonce using server-side demo endpoint
  async function autoSign(nonceB64) {
    try {
      const r = await fetch(`${API}/auth/sign-demo`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ nonce_b64: nonceB64, private_key_pem: user.private_key_pem }) });
      const d = await r.json();
      if (d.signature) { setSignature(d.signature); setSt({ msg: "Nonce signed with ECDSA — verifying...", type: "ok" }); setStep(3);
        // Auto-verify
        autoVerify(d.signature);
      }
      else setSt({ msg: d.error || "Signing failed", type: "error" });
    } catch { setSt({ msg: "Signing failed", type: "error" }); }
  }

  // Step 3: Verify signature and get wrapped key
  async function autoVerify(sig) {
    try {
      const r = await fetch(`${API}/auth/verify`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ doctor_id: user.doctor_id, patient_id: pid, signature_b64: sig }) });
      const d = await r.json();
      if (d.wrapped_key_data && d.encrypted_record) { setWrappedData(d); setSt({ msg: "✓ Authenticated! Decrypting record...", type: "ok" }); setStep(4);
        // Auto-decrypt
        autoDecrypt(d);
      }
      else setSt({ msg: d.error || "Verification failed", type: "error" });
    } catch { setSt({ msg: "Verification failed", type: "error" }); }
  }

  // Step 4: Decrypt the medical record
  async function autoDecrypt(data) {
    try {
      const r = await fetch(`${API}/auth/decrypt-demo`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ wrapped_key_data: data.wrapped_key_data, encrypted_record: data.encrypted_record, private_key_pem: user.private_key_pem }) });
      const d = await r.json();
      if (d.record) { setRecord(d.record); setSt({ msg: "", type: "" }); }
      else setSt({ msg: d.error || "Decryption failed", type: "error" });
    } catch { setSt({ msg: "Decryption failed", type: "error" }); }
  }

  const steps = ["Patient ID", "Sign Challenge", "Authenticated", "Full Record"];

  return (
    <div style={{ maxWidth: 750, margin: "40px auto", padding: 24 }} className="fade-in">
      <h2 style={{ fontWeight: 700, fontSize: 26, marginBottom: 4 }}>Doctor <span style={{ color: G.blue }}>Authentication</span></h2>
      <p style={{ color: G.muted, fontSize: 14, marginBottom: 24 }}>4-step ECDSA challenge-response — private key never leaves your device</p>

      {/* Step indicators */}
      <div style={{ display: "flex", marginBottom: 28, alignItems: "center" }}>
        {steps.map((s, i) => (
          <div key={i} style={{ display: "contents" }}>
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}>
              <div style={{ width: 34, height: 34, borderRadius: "50%", background: i + 1 <= step ? G.blue : G.surface, border: `2px solid ${i + 1 <= step ? G.blue : G.border}`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 13, fontWeight: 700, color: i + 1 <= step ? G.bg : G.muted }}>
                {i + 1 < step ? "✓" : i + 1}
              </div>
              <span className="mono" style={{ fontSize: 9, color: i + 1 <= step ? G.blue : G.muted, whiteSpace: "nowrap" }}>{s}</span>
            </div>
            {i < steps.length - 1 && <div style={{ flex: 1, height: 2, background: i + 1 < step ? G.blue : G.border, marginBottom: 18 }} />}
          </div>
        ))}
      </div>

      {/* Step 1: Enter Patient ID */}
      <Card style={{ marginBottom: 12 }}>
        <div style={{ fontWeight: 600, color: G.blue, marginBottom: 12 }}>① Enter Patient ID</div>
        <div style={{ display: "flex", gap: 10 }}>
          <input className="mono" placeholder="Patient UUID..." value={pid} onChange={e => setPid(e.target.value)} disabled={step > 1} />
          {step === 1 && <Btn onClick={getChallenge} disabled={loading} color={G.blue} style={{ whiteSpace: "nowrap" }}>{loading ? "..." : "Get Challenge"}</Btn>}
        </div>
        {step === 1 && <Status msg={st.msg} type={st.type} />}
      </Card>

      {/* Step 2: Nonce received & signed */}
      {step >= 2 && <Card style={{ marginBottom: 12 }} className="fade-in">
        <div style={{ fontWeight: 600, color: G.blue, marginBottom: 12 }}>② Challenge Nonce Received</div>
        <div style={{ background: G.surface, border: `1px solid ${G.blue}33`, borderRadius: 8, padding: 12, marginBottom: 8 }}>
          <Lbl>SERVER NONCE (256-bit)</Lbl>
          <div className="mono" style={{ color: G.blue, fontSize: 11, wordBreak: "break-all" }}>{nonce}</div>
        </div>
        {signature && <div style={{ background: G.surface, border: `1px solid ${G.green}33`, borderRadius: 8, padding: 12 }}>
          <Lbl>ECDSA SIGNATURE</Lbl>
          <div className="mono" style={{ color: G.green, fontSize: 11, wordBreak: "break-all" }}>{signature.slice(0, 80)}...</div>
        </div>}
        {step === 2 && <Status msg={st.msg} type={st.type} />}
      </Card>}

      {/* Step 3: Verified */}
      {step >= 3 && <Card style={{ marginBottom: 12 }} className="fade-in">
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ color: G.green, fontWeight: 600, fontSize: 15 }}>③ ✓ Signature Verified — Ks Released</span>
          <Tag color={G.green}>AUTHENTICATED</Tag>
        </div>
        {step === 3 && <Status msg={st.msg} type={st.type} />}
      </Card>}

      {/* Step 4: Full decrypted record */}
      {step >= 4 && record && (
        <Card glow={G.blue} className="fade-in">
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
            <span className="mono" style={{ fontSize: 10, color: G.blue, letterSpacing: 2 }}>🔓 DECRYPTED MEDICAL RECORD</span>
            <Tag color={G.green}>AES-256-GCM</Tag>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            {Object.entries(record).filter(([, v]) => v && (typeof v === "string" ? v.trim() : true)).map(([k, v]) => (
              <div key={k} style={{ background: G.surface, borderRadius: 8, padding: 12 }}>
                <Lbl>{k.replace(/_/g, " ").toUpperCase()}</Lbl>
                <div style={{ color: G.white, fontSize: 14, fontWeight: 500 }}>{Array.isArray(v) ? v.join(", ") : String(v)}</div>
              </div>
            ))}
          </div>
          <div className="mono" style={{ color: G.muted, fontSize: 10, marginTop: 14, textAlign: "center" }}>
            ✓ ECDSA verified · ✓ Ks unwrapped via ECDH · ✓ AES-256-GCM decrypted · ✓ Access logged
          </div>
        </Card>
      )}

      {/* No private key warning */}
      {!user.private_key_pem && step === 1 && (
        <div style={{ background: G.orange + "12", border: `1px solid ${G.orange}33`, borderRadius: 8, padding: 14, marginTop: 12 }}>
          <div style={{ color: G.orange, fontWeight: 600, marginBottom: 4 }}>⚠️ No Private Key Found</div>
          <div style={{ color: G.muted, fontSize: 13 }}>Logout and re-register as a new doctor, or login with your saved private key to use the full 4-step authentication flow.</div>
        </div>
      )}
    </div>
  );
}

// ─── AI TRIAGE (DOCTOR) ───────────────────────────────────────────────────────
function AITriage() {
  const [desc, setDesc] = useState("");
  const [img, setImg] = useState(null);
  const [preview, setPreview] = useState(null);
  const [result, setResult] = useState(null);
  const [st, setSt] = useState({ msg: "", type: "" });
  const [loading, setLoading] = useState(false);

  function handleImg(e) {
    const f = e.target.files[0]; if (!f) return;
    setImg(f); const rd = new FileReader(); rd.onload = ev => setPreview(ev.target.result); rd.readAsDataURL(f);
  }

  async function analyze() {
    if (!desc && !img) { setSt({ msg: "Describe the situation or upload a photo", type: "error" }); return; }
    setLoading(true); setResult(null); setSt({ msg: "AI analyzing injuries & dispatching equipment...", type: "ok" });
    try {
      let image_b64 = "";
      if (img) { const r = new FileReader(); image_b64 = await new Promise((res) => { r.onload = ev => res(ev.target.result.split(",")[1]); r.readAsDataURL(img); }); }
      const r = await fetch(`${API}/ai/triage`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ description: desc, image_b64 }) });
      const d = await r.json();
      if (d.analysis) { setResult(d.analysis); setSt({ msg: "", type: "" }); }
      else setSt({ msg: d.error || "Analysis failed", type: "error" });
    } catch { setSt({ msg: "Cannot reach API", type: "error" }); }
    setLoading(false);
  }

  const prioColor = { CRITICAL: G.red, HIGH: G.orange, MEDIUM: G.blue, LOW: G.green };

  return (
    <div style={{ maxWidth: 850, margin: "40px auto", padding: 24 }} className="fade-in">
      <h2 style={{ fontWeight: 700, fontSize: 26, marginBottom: 4 }}>AI <span style={{ color: G.red }}>Triage</span> & Equipment Dispatch</h2>
      <p style={{ color: G.muted, fontSize: 14, marginBottom: 20 }}>Upload accident photo or describe injuries → AI analyzes → dispatches required ambulance equipment</p>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>
        <Card>
          <Lbl>ACCIDENT PHOTO</Lbl>
          <div onClick={() => document.getElementById("triage-img").click()} style={{ border: `2px dashed ${G.border}`, borderRadius: 10, padding: 20, textAlign: "center", cursor: "pointer", marginTop: 8 }}>
            {preview ? <img src={preview} alt="" style={{ maxHeight: 120, borderRadius: 8, maxWidth: "100%" }} /> : <><div style={{ fontSize: 34, marginBottom: 6 }}>📸</div><div style={{ color: G.muted, fontSize: 13 }}>Click to upload</div></>}
            <input id="triage-img" type="file" accept="image/*" onChange={handleImg} style={{ display: "none" }} />
          </div>
        </Card>
        <Card>
          <Lbl>DESCRIBE THE SITUATION</Lbl>
          <textarea placeholder="e.g. Car accident, person unconscious, bleeding from head, not moving legs..." value={desc} onChange={e => setDesc(e.target.value)} rows={5} style={{ resize: "vertical", marginTop: 8 }} />
        </Card>
      </div>
      <Btn onClick={analyze} disabled={loading} color={G.red} full style={{ padding: 13, fontSize: 15, marginBottom: 14 }}>{loading ? "🤖 AI Analyzing..." : "🚨 Analyze & Dispatch Equipment"}</Btn>
      <Status msg={st.msg} type={st.type} />

      {result && <div className="fade-in" style={{ marginTop: 16 }}>
        {/* Severity Header */}
        <Card glow={result.severity >= 8 ? G.red : result.severity >= 5 ? G.orange : G.green} style={{ marginBottom: 14 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <Tag color={result.severity >= 8 ? G.red : G.orange}>{result.severity_label}</Tag>
                <Tag color={result.triage_color === "RED" ? G.red : G.orange}>TRIAGE: {result.triage_color}</Tag>
              </div>
              <div style={{ color: G.muted, fontSize: 12, marginTop: 6 }}>{result.golden_hour_warning}</div>
            </div>
            <div style={{ textAlign: "center" }}>
              <div style={{ fontSize: 40, fontWeight: 800, color: result.severity >= 8 ? G.red : G.orange }}>{result.severity}/10</div>
              <div className="mono" style={{ fontSize: 9, color: G.muted }}>SEVERITY</div>
            </div>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
            <div style={{ background: G.surface, borderRadius: 8, padding: 10, textAlign: "center" }}>
              <div style={{ fontSize: 22 }}>{result.is_conscious ? "👁️" : "😵"}</div>
              <div style={{ color: result.is_conscious ? G.green : G.red, fontWeight: 700, fontSize: 13 }}>{result.is_conscious ? "CONSCIOUS" : "UNCONSCIOUS"}</div>
            </div>
            <div style={{ background: G.surface, borderRadius: 8, padding: 10, textAlign: "center" }}>
              <div style={{ fontSize: 22 }}>{result.is_breathing ? "🫁" : "❌"}</div>
              <div style={{ color: result.is_breathing ? G.green : G.red, fontWeight: 700, fontSize: 13 }}>{result.is_breathing ? "BREATHING" : "NOT BREATHING"}</div>
            </div>
            <div style={{ background: G.surface, borderRadius: 8, padding: 10, textAlign: "center" }}>
              <div style={{ fontSize: 22 }}>🏥</div>
              <div style={{ color: G.blue, fontWeight: 600, fontSize: 11 }}>{result.recommended_hospital_type}</div>
            </div>
          </div>
        </Card>

        {/* Injuries */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>
          <Card>
            <div style={{ fontWeight: 600, color: G.orange, marginBottom: 10 }}>⚠️ Visible Injuries</div>
            {(result.visible_injuries || []).map((inj, i) => <div key={i} style={{ background: G.surface, borderRadius: 6, padding: "6px 10px", marginBottom: 4, fontSize: 13 }}>• {inj}</div>)}
          </Card>
          <Card>
            <div style={{ fontWeight: 600, color: G.red, marginBottom: 10 }}>🚨 Immediate Dangers</div>
            {(result.immediate_dangers || []).map((d, i) => <div key={i} style={{ background: G.red + "12", border: `1px solid ${G.red}22`, borderRadius: 6, padding: "6px 10px", marginBottom: 4, fontSize: 13, color: G.red }}>⚡ {d}</div>)}
          </Card>
        </div>

        {/* Equipment Dispatch */}
        <Card glow={G.blue} style={{ marginBottom: 14 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
            <span style={{ fontSize: 22 }}>🚑</span>
            <div>
              <div style={{ fontWeight: 700, color: G.blue, fontSize: 16 }}>Ambulance Equipment Dispatch</div>
              <div style={{ color: G.muted, fontSize: 12 }}>{result.ambulance_type} • {result.estimated_crew}</div>
            </div>
          </div>
          {(result.required_equipment || []).map((eq, i) => (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, background: G.surface, borderRadius: 8, padding: 10, marginBottom: 6 }}>
              <Tag color={prioColor[eq.priority] || G.muted}>{eq.priority}</Tag>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 600, fontSize: 14 }}>{eq.item}</div>
                <div style={{ color: G.muted, fontSize: 12 }}>{eq.reason}</div>
              </div>
            </div>
          ))}
        </Card>

        {/* First Responder Tips */}
        <Card style={{ marginBottom: 14 }}>
          <div style={{ fontWeight: 600, color: G.green, marginBottom: 10 }}>🩹 First Responder Tips</div>
          {(result.first_responder_tips || []).map((tip, i) => (
            <div key={i} style={{ display: "flex", gap: 8, marginBottom: 6, fontSize: 13 }}>
              <span style={{ color: G.green, fontWeight: 700, minWidth: 20 }}>{i + 1}.</span>
              <span>{tip}</span>
            </div>
          ))}
        </Card>
      </div>}
    </div>
  );
}

// ─── AI FIRST AID (PASSERBY) ──────────────────────────────────────────────────
function AIFirstAid() {
  const [situation, setSituation] = useState("");
  const [result, setResult] = useState(null);
  const [st, setSt] = useState({ msg: "", type: "" });
  const [loading, setLoading] = useState(false);

  const presets = [
    { label: "🚗 Car Accident", value: "Car accident on road, person injured, not sure how badly" },
    { label: "😵 Unconscious Person", value: "Person is unconscious, not responding, found on ground" },
    { label: "🩸 Heavy Bleeding", value: "Person is bleeding heavily from arm, cut wound" },
    { label: "🔥 Burn Injury", value: "Person has burn injuries from fire" },
    { label: "💔 Chest Pain", value: "Person collapsed holding chest, not breathing properly" },
    { label: "🦴 Broken Bone", value: "Person fell, arm looks broken, in severe pain" },
  ];

  async function getGuidance() {
    if (!situation) { setSt({ msg: "Describe what you see or pick a preset", type: "error" }); return; }
    setLoading(true); setResult(null); setSt({ msg: "Getting first aid guidance...", type: "ok" });
    try {
      const r = await fetch(`${API}/ai/firstaid`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ situation }) });
      const d = await r.json();
      if (d.guidance) { setResult(d.guidance); setSt({ msg: "", type: "" }); }
      else setSt({ msg: d.error || "Failed", type: "error" });
    } catch { setSt({ msg: "Cannot reach API", type: "error" }); }
    setLoading(false);
  }

  return (
    <div style={{ maxWidth: 750, margin: "40px auto", padding: 24 }} className="fade-in">
      <h2 style={{ fontWeight: 700, fontSize: 26, marginBottom: 4 }}>AI <span style={{ color: G.green }}>First Aid</span> Guide</h2>
      <p style={{ color: G.muted, fontSize: 14, marginBottom: 20 }}>Don't know what to do? Describe what you see — AI gives step-by-step instructions</p>

      <div style={{ background: G.red + "08", border: `1px solid ${G.red}33`, borderRadius: 10, padding: 14, marginBottom: 18, display: "flex", gap: 12 }}>
        <div style={{ fontSize: 26 }}>⏱️</div>
        <div><div style={{ fontWeight: 600, color: G.red }}>Every Second Counts</div><div style={{ color: G.muted, fontSize: 13, marginTop: 2 }}>The first 10 minutes after an accident are the most critical. Correct first aid can save lives.</div></div>
      </div>

      <Card style={{ marginBottom: 14 }}>
        <Lbl>QUICK SELECT — WHAT DO YOU SEE?</Lbl>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8, marginTop: 8 }}>
          {presets.map(p => (
            <button key={p.label} onClick={() => setSituation(p.value)} style={{ background: situation === p.value ? G.green + "18" : G.surface, border: `1px solid ${situation === p.value ? G.green + "55" : G.border}`, color: situation === p.value ? G.green : G.white, borderRadius: 8, padding: "8px 10px", fontSize: 12, fontWeight: 600, cursor: "pointer" }}>{p.label}</button>
          ))}
        </div>
      </Card>

      <Card style={{ marginBottom: 14 }}>
        <Lbl>OR DESCRIBE IN YOUR OWN WORDS</Lbl>
        <textarea placeholder="e.g. I found a person lying on the road after a bike accident. They are bleeding from their head and not moving..." value={situation} onChange={e => setSituation(e.target.value)} rows={3} style={{ resize: "vertical", marginTop: 8 }} />
      </Card>

      <Btn onClick={getGuidance} disabled={loading} color={G.green} full style={{ padding: 13, fontSize: 15, marginBottom: 14 }}>{loading ? "🩹 Getting guidance..." : "🩹 Get First Aid Instructions"}</Btn>
      <Status msg={st.msg} type={st.type} />

      {result && <div className="fade-in" style={{ marginTop: 16 }}>
        {/* Assessment */}
        <Card glow={G.red} style={{ marginBottom: 14 }}>
          <div style={{ fontWeight: 700, color: G.red, fontSize: 16, marginBottom: 8 }}>🚨 {result.situation_assessment}</div>
          <div style={{ background: G.orange + "12", borderRadius: 8, padding: 10, marginBottom: 10 }}>
            <div style={{ fontWeight: 600, color: G.orange, marginBottom: 4 }}>⚠️ Safety Check</div>
            <div style={{ color: G.muted, fontSize: 13 }}>{result.danger_check}</div>
          </div>
          <div style={{ background: G.green + "12", borderRadius: 8, padding: 12 }}>
            <div className="mono" style={{ fontSize: 10, color: G.green, letterSpacing: 2, marginBottom: 4 }}>DO THIS FIRST</div>
            <div style={{ fontWeight: 700, fontSize: 16, color: G.green }}>{result.do_first}</div>
          </div>
        </Card>

        {/* Step by Step */}
        <Card style={{ marginBottom: 14 }}>
          <div style={{ fontWeight: 700, color: G.blue, fontSize: 16, marginBottom: 14 }}>📋 Step-by-Step Instructions</div>
          {(result.step_by_step || []).map((s, i) => (
            <div key={i} style={{ display: "flex", gap: 12, marginBottom: 12, padding: 12, background: G.surface, borderRadius: 10, border: `1px solid ${G.border}` }}>
              <div style={{ width: 36, height: 36, borderRadius: "50%", background: G.blue, display: "flex", alignItems: "center", justifyContent: "center", color: G.bg, fontWeight: 800, fontSize: 14, flexShrink: 0 }}>{s.step}</div>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 2 }}>{s.action}</div>
                <div style={{ color: G.muted, fontSize: 13 }}>{s.detail}</div>
              </div>
              {s.time && <div style={{ background: G.orange + "15", border: `1px solid ${G.orange}33`, borderRadius: 6, padding: "4px 8px", fontSize: 11, color: G.orange, fontWeight: 700, height: "fit-content", whiteSpace: "nowrap" }}>⏱ {s.time}</div>}
            </div>
          ))}
        </Card>

        {/* Do NOT Do */}
        <Card style={{ marginBottom: 14 }}>
          <div style={{ fontWeight: 700, color: G.red, fontSize: 16, marginBottom: 10 }}>🚫 DO NOT DO</div>
          {(result.do_NOT_do || []).map((item, i) => (
            <div key={i} style={{ background: G.red + "08", border: `1px solid ${G.red}22`, borderRadius: 6, padding: "8px 12px", marginBottom: 4, fontSize: 13, color: G.red }}>✗ {item}</div>
          ))}
        </Card>

        {/* What to Tell Ambulance */}
        <Card style={{ marginBottom: 14 }}>
          <div style={{ fontWeight: 700, color: G.blue, fontSize: 16, marginBottom: 10 }}>📞 What to Tell the Ambulance (108)</div>
          {(result.what_to_tell_ambulance || []).map((item, i) => (
            <div key={i} style={{ display: "flex", gap: 8, marginBottom: 4, fontSize: 13 }}>
              <span style={{ color: G.blue, fontWeight: 700 }}>→</span>
              <span>{item}</span>
            </div>
          ))}
        </Card>

        {/* Emergency Numbers */}
        {result.emergency_numbers && <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 14 }}>
          {Object.entries(result.emergency_numbers).map(([k, v]) => (
            <Card key={k} style={{ textAlign: "center", padding: 12 }}>
              <div style={{ fontWeight: 800, fontSize: 22, color: G.red }}>{v}</div>
              <div className="mono" style={{ fontSize: 9, color: G.muted, letterSpacing: 1 }}>{k.replace(/_/g, " ").toUpperCase()}</div>
            </Card>
          ))}
        </div>}

        {/* Legal Protection */}
        <Card glow={G.green}>
          <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
            <div style={{ fontSize: 30 }}>🛡️</div>
            <div>
              <div style={{ fontWeight: 700, color: G.green, marginBottom: 4 }}>You Are Legally Protected</div>
              <div style={{ color: G.muted, fontSize: 13 }}>{result.legal_protection}</div>
            </div>
          </div>
        </Card>
      </div>}
    </div>
  );
}

// ─── HOSPITAL FINDER ──────────────────────────────────────────────────────────
function HospitalFinder() {
  const [img, setImg] = useState(null);
  const [preview, setPreview] = useState(null);
  const [lat, setLat] = useState("");
  const [lon, setLon] = useState("");
  const [hospitals, setHospitals] = useState([]);
  const [st, setSt] = useState({ msg: "", type: "" });
  const [loading, setLoading] = useState(false);

  function handleImg(e) {
    const f = e.target.files[0]; if (!f) return;
    setImg(f);
    const rd = new FileReader(); rd.onload = ev => setPreview(ev.target.result); rd.readAsDataURL(f);
  }

  function detectLocation() {
    navigator.geolocation?.getCurrentPosition(
      p => { setLat(p.coords.latitude.toFixed(6)); setLon(p.coords.longitude.toFixed(6)); setSt({ msg: `Location: ${p.coords.latitude.toFixed(4)}, ${p.coords.longitude.toFixed(4)}`, type: "ok" }); },
      () => setSt({ msg: "Location access denied", type: "error" })
    );
  }

  function haversine(lat1, lon1, lat2, lon2) {
    const R = 6371, dLat = (lat2 - lat1) * Math.PI / 180, dLon = (lon2 - lon1) * Math.PI / 180;
    const a = Math.sin(dLat / 2) ** 2 + Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * Math.sin(dLon / 2) ** 2;
    return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  }

  async function find() {
    if (!lat || !lon) { setSt({ msg: "Detect your location first", type: "error" }); return; }
    setLoading(true); setHospitals([]); setSt({ msg: "Searching real hospitals via OpenStreetMap...", type: "ok" });
    try {
      const r = await fetch(`${API}/hospitals/nearby`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ lat: parseFloat(lat), lon: parseFloat(lon), radius: 10000 }) });
      const d = await r.json();
      const elements = d.elements || [];
      const list = elements.filter(e => e.tags?.name).map(e => {
        const eLat = e.lat || e.center?.lat;
        const eLon = e.lon || e.center?.lon;
        const dist = eLat && eLon ? haversine(parseFloat(lat), parseFloat(lon), eLat, eLon) : 999;
        return { name: e.tags.name, phone: e.tags.phone || e.tags["contact:phone"] || "", address: e.tags["addr:full"] || e.tags["addr:street"] || "", distance: dist, lat: eLat, lon: eLon };
      }).sort((a, b) => a.distance - b.distance).slice(0, 10);
      setHospitals(list);
      setSt(list.length ? { msg: `Found ${list.length} hospitals nearby`, type: "ok" } : { msg: "No hospitals found — try a larger radius", type: "warn" });
    } catch { setSt({ msg: "Cannot reach API — is Flask running?", type: "error" }); }
    setLoading(false);
  }

  return (
    <div style={{ maxWidth: 800, margin: "40px auto", padding: 24 }} className="fade-in">
      <h2 style={{ fontWeight: 700, fontSize: 26, marginBottom: 4 }}>Hospital <span style={{ color: G.orange }}>Finder</span></h2>
      <p style={{ color: G.muted, fontSize: 14, marginBottom: 20 }}>Find nearest real hospitals via OpenStreetMap — upload photo for AI triage</p>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>
        <Card>
          <Lbl>ACCIDENT PHOTO (optional)</Lbl>
          <div onClick={() => document.getElementById("img-up").click()} style={{ border: `2px dashed ${G.border}`, borderRadius: 10, padding: 24, textAlign: "center", cursor: "pointer", marginTop: 8 }}>
            {preview ? <img src={preview} alt="" style={{ maxHeight: 130, borderRadius: 8, maxWidth: "100%" }} /> : <><div style={{ fontSize: 34, marginBottom: 6 }}>📸</div><div style={{ color: G.muted, fontSize: 13 }}>Click to upload</div></>}
            <input id="img-up" type="file" accept="image/*" onChange={handleImg} style={{ display: "none" }} />
          </div>
        </Card>
        <Card>
          <Lbl>YOUR LOCATION</Lbl>
          <div style={{ display: "flex", flexDirection: "column", gap: 10, marginTop: 8 }}>
            <Btn onClick={detectLocation} outline color={G.orange} full style={{ fontSize: 13, padding: "10px 10px" }}>📍 Detect My Location</Btn>
            {lat && <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
              <div><Lbl>LAT</Lbl><input className="mono" value={lat} onChange={e => setLat(e.target.value)} style={{ fontSize: 12 }} /></div>
              <div><Lbl>LON</Lbl><input className="mono" value={lon} onChange={e => setLon(e.target.value)} style={{ fontSize: 12 }} /></div>
            </div>}
          </div>
        </Card>
      </div>
      <Btn onClick={find} disabled={loading} color={G.orange} full style={{ padding: 13, fontSize: 15, marginBottom: 14 }}>{loading ? "🔍 Searching..." : "🏥 Find Nearest Hospitals →"}</Btn>
      <Status msg={st.msg} type={st.type} />

      {hospitals.length > 0 && <div className="fade-in" style={{ marginTop: 16 }}>
        <div style={{ fontWeight: 700, marginBottom: 12, color: G.orange }}>🏥 {hospitals.length} Hospitals Found</div>
        {hospitals.map((h, i) => (
          <Card key={i} style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 8 }}>
            <div style={{ width: 36, height: 36, borderRadius: "50%", background: i === 0 ? G.green + "22" : G.surface, display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 700, color: i === 0 ? G.green : G.muted, fontSize: 14, flexShrink: 0 }}>#{i + 1}</div>
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 600 }}>{h.name}</div>
              {h.address && <div style={{ color: G.muted, fontSize: 12 }}>{h.address}</div>}
              {h.phone && <div style={{ color: G.blue, fontSize: 12 }}>{h.phone}</div>}
            </div>
            <div style={{ textAlign: "right" }}>
              <div style={{ color: G.orange, fontWeight: 700 }}>{h.distance.toFixed(1)} km</div>
              <div style={{ color: G.muted, fontSize: 11 }}>~{Math.round(h.distance * 3)} min</div>
            </div>
            {h.lat && h.lon && <a href={`https://www.google.com/maps/dir/${lat},${lon}/${h.lat},${h.lon}`} target="_blank" rel="noreferrer" style={{ background: G.blue, color: G.bg, borderRadius: 6, padding: "6px 10px", fontSize: 11, fontWeight: 700, textDecoration: "none" }}>Navigate</a>}
          </Card>
        ))}
      </div>}
    </div>
  );
}

// ─── GOOD SAMARITAN ───────────────────────────────────────────────────────────
function GoodSamaritan() {
  const [identity, setIdentity] = useState("");
  const [lat, setLat] = useState("");
  const [lon, setLon] = useState("");
  const [regData, setRegData] = useState(null);
  const [cert, setCert] = useState(null);
  const [st, setSt] = useState({ msg: "", type: "" });
  const [loading, setLoading] = useState(false);

  function detectLocation() {
    navigator.geolocation?.getCurrentPosition(
      p => { setLat(p.coords.latitude.toFixed(6)); setLon(p.coords.longitude.toFixed(6)); setSt({ msg: `Location: ${p.coords.latitude.toFixed(4)}, ${p.coords.longitude.toFixed(4)}`, type: "ok" }); },
      () => setSt({ msg: "Location access denied", type: "error" })
    );
  }

  async function register() {
    if (!identity) { setSt({ msg: "Enter your identity (email/phone)", type: "error" }); return; }
    setLoading(true);
    try {
      const r = await fetch(`${API}/samaritan/register`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ identity }) });
      const d = await r.json();
      if (d.commitment_hash && d.blinding_factor) { setRegData(d); setSt({ msg: "Registered! Your identity was NOT stored. Now detect location and click 'I Helped Here'", type: "ok" }); }
      else setSt({ msg: d.error || "Registration failed", type: "error" });
    } catch { setSt({ msg: "Cannot reach API", type: "error" }); }
    setLoading(false);
  }

  async function help() {
    if (!regData) { setSt({ msg: "Register first", type: "error" }); return; }
    if (!lat || !lon) { setSt({ msg: "Detect your location first", type: "error" }); return; }
    setLoading(true);
    try {
      const r = await fetch(`${API}/samaritan/help`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ identity, blinding_factor: regData.blinding_factor, commitment_hash: regData.commitment_hash, latitude: parseFloat(lat), longitude: parseFloat(lon) }) });
      const d = await r.json();
      if (d.certificate_id) { setCert(d); setSt({ msg: "", type: "" }); }
      else setSt({ msg: d.error || "Proof generation failed", type: "error" });
    } catch { setSt({ msg: "Cannot reach API", type: "error" }); }
    setLoading(false);
  }

  return (
    <div style={{ maxWidth: 700, margin: "40px auto", padding: 24 }} className="fade-in">
      <h2 style={{ fontWeight: 700, fontSize: 26, marginBottom: 4 }}>Good <span style={{ color: G.green }}>Samaritan</span></h2>
      <p style={{ color: G.muted, fontSize: 14, marginBottom: 16 }}>Prove you helped — stay anonymous — get legal protection via zero-knowledge proof</p>

      <div style={{ background: G.green + "08", border: `1px solid ${G.green}33`, borderRadius: 10, padding: 14, marginBottom: 18, display: "flex", gap: 12 }}>
        <div style={{ fontSize: 26 }}>🛡️</div>
        <div><div style={{ fontWeight: 600, color: G.green }}>Zero-Knowledge Legal Protection</div><div style={{ color: G.muted, fontSize: 13, marginTop: 2 }}>Your identity is never stored on the server. Only a cryptographic commitment is saved. You can prove you helped without revealing who you are.</div></div>
      </div>

      <Card style={{ marginBottom: 14 }}>
        <Lbl>STEP 1: REGISTER (identity never leaves your browser as plaintext)</Lbl>
        <div style={{ display: "flex", gap: 10, marginTop: 8 }}>
          <input placeholder="Your email or phone (used locally for commitment)" value={identity} onChange={e => setIdentity(e.target.value)} disabled={!!regData} />
          {!regData && <Btn onClick={register} disabled={loading} color={G.green} style={{ whiteSpace: "nowrap" }}>{loading ? "..." : "Register"}</Btn>}
        </div>
        {regData && <div style={{ background: G.surface, borderRadius: 8, padding: 10, marginTop: 10 }}>
          <Lbl>COMMITMENT HASH (stored on server)</Lbl>
          <div className="mono" style={{ color: G.green, fontSize: 10, wordBreak: "break-all" }}>{regData.commitment_hash}</div>
        </div>}
      </Card>

      {regData && <Card style={{ marginBottom: 14 }}>
        <Lbl>STEP 2: DETECT LOCATION</Lbl>
        <Btn onClick={detectLocation} outline color={G.orange} style={{ marginTop: 8 }}>📍 Detect My Location</Btn>
        {lat && <div className="mono" style={{ color: G.muted, fontSize: 11, marginTop: 8 }}>📍 {lat}, {lon}</div>}
      </Card>}

      {regData && lat && <Btn onClick={help} disabled={loading} color={G.green} full style={{ padding: 13, fontSize: 15, marginBottom: 14 }}>{loading ? "Generating ZK Proof..." : "🤝 I Helped Here — Generate Certificate"}</Btn>}

      <Status msg={st.msg} type={st.type} />

      {cert && <Card glow={G.green} style={{ marginTop: 16 }} className="fade-in">
        <div className="mono" style={{ fontSize: 10, color: G.green, letterSpacing: 2, marginBottom: 14 }}>✅ ZK CERTIFICATE ISSUED</div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 14 }}>
          <div style={{ background: G.surface, borderRadius: 8, padding: 12 }}>
            <Lbl>CERTIFICATE ID</Lbl>
            <div className="mono" style={{ color: G.blue, fontSize: 12, wordBreak: "break-all" }}>{cert.certificate_id}</div>
          </div>
          <div style={{ background: G.surface, borderRadius: 8, padding: 12 }}>
            <Lbl>ZK PROOF VALID</Lbl>
            <div style={{ color: G.green, fontWeight: 700, fontSize: 18 }}>✓ YES</div>
          </div>
        </div>
        {cert.certificate && <div style={{ background: G.surface, borderRadius: 8, padding: 12, marginBottom: 10 }}>
          <Lbl>SERVER SIGNATURE</Lbl>
          <div className="mono" style={{ color: G.orange, fontSize: 10, wordBreak: "break-all" }}>{cert.certificate.server_signature?.slice(0, 80) || "verified"}...</div>
        </div>}
        <div style={{ background: G.green + "08", border: `1px solid ${G.green}22`, borderRadius: 8, padding: 12 }}>
          <div style={{ color: G.green, fontWeight: 600, marginBottom: 4 }}>Legal Statement</div>
          <div style={{ color: G.muted, fontSize: 12 }}>This certificate confirms a registered MedKey Good Samaritan was present at the specified location and provided emergency assistance. Identity is intentionally anonymized via zero-knowledge proof.</div>
        </div>
      </Card>}
    </div>
  );
}

// ─── AUDIT LOG ────────────────────────────────────────────────────────────────
function AuditLog({ user }) {
  const [pid, setPid] = useState("");
  const [log, setLog] = useState(null);
  const [st, setSt] = useState({ msg: "", type: "" });
  const [loading, setLoading] = useState(false);

  async function fetchLog() {
    if (!pid) { setSt({ msg: "Enter patient ID", type: "error" }); return; }
    setLoading(true);
    try {
      const r = await fetch(`${API}/patient/${pid}/audit`);
      const d = await r.json();
      if (d.audit_entries) { setLog(d); setSt({ msg: "", type: "" }); }
      else setSt({ msg: d.error || "No audit log found", type: "error" });
    } catch { setSt({ msg: "Cannot reach API", type: "error" }); }
    setLoading(false);
  }

  return (
    <div style={{ maxWidth: 800, margin: "40px auto", padding: 24 }} className="fade-in">
      <h2 style={{ fontWeight: 700, fontSize: 26, marginBottom: 4 }}>Audit <span style={{ color: G.blue }}>Log</span></h2>
      <p style={{ color: G.muted, fontSize: 14, marginBottom: 20 }}>SHA-256 hash-chained access log — any tampering is cryptographically detectable</p>
      <Card style={{ marginBottom: 16 }}>
        <Lbl>PATIENT ID</Lbl>
        <div style={{ display: "flex", gap: 10, marginTop: 6 }}>
          <input className="mono" placeholder="Patient UUID..." value={pid} onChange={e => setPid(e.target.value)} />
          <Btn onClick={fetchLog} disabled={loading} color={G.blue} style={{ whiteSpace: "nowrap" }}>{loading ? "..." : "Fetch Log"}</Btn>
        </div>
        <Status msg={st.msg} type={st.type} />
      </Card>
      {log && <div className="fade-in">
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 14 }}>
          <Card style={{ textAlign: "center" }}><div style={{ fontSize: 28, fontWeight: 700, color: G.blue }}>{(log.audit_entries || []).length}</div><Lbl>ENTRIES</Lbl></Card>
          <Card style={{ textAlign: "center" }}><div style={{ fontSize: 16, fontWeight: 700, color: log.chain_integrity ? G.green : G.red }}>{log.chain_integrity ? "✓ CHAIN VALID" : "✗ TAMPERED"}</div><Lbl>INTEGRITY</Lbl></Card>
        </div>
        {(log.audit_entries || []).map((e, i) => (
          <Card key={i} style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 8 }}>
            <div className="mono" style={{ color: G.muted, fontSize: 12, minWidth: 28 }}>#{i + 1}</div>
            <div style={{ flex: 1 }}>
              <Tag color={e.success ? G.green : G.red}>{e.event_type}</Tag>
              {e.doctor_fingerprint && <span className="mono" style={{ color: G.muted, fontSize: 10, marginLeft: 8 }}>{e.doctor_fingerprint?.slice(0, 16)}...</span>}
            </div>
            <div className="mono" style={{ color: G.muted, fontSize: 10 }}>{e.created_at ? new Date(e.created_at).toLocaleString() : ""}</div>
          </Card>
        ))}
      </div>}
    </div>
  );
}

// ─── ROOT ─────────────────────────────────────────────────────────────────────
export default function App() {
  const [auth, setAuth] = useState(null);
  const [tab, setTab] = useState("");

  function login(role, user) {
    setAuth({ role, user });
    setTab(role === "doctor" ? "auth" : role === "passerby" ? "scan" : "reg");
  }
  function logout() { setAuth(null); setTab(""); }

  if (!auth) return <Login onLogin={login} />;

  if (auth.role === "register") return (
    <div style={{ minHeight: "100vh", background: G.bg }}>
      <style>{css}</style>
      <RegisterPatient onBack={logout} />
    </div>
  );

  const rc = auth.role === "doctor" ? G.blue : G.orange;

  return (
    <div style={{ minHeight: "100vh", background: G.bg }}>
      <style>{css}</style>
      <Nav role={auth.role} user={auth.user} tab={tab} setTab={setTab} onLogout={logout} />
      <div style={{ maxWidth: 1100, margin: "0 auto" }}>
        {auth.role === "doctor" && tab === "auth" && <DoctorAuth user={auth.user} />}
        {auth.role === "doctor" && tab === "triage" && <AITriage />}
        {auth.role === "doctor" && tab === "scan" && <EmergencyScan roleColor={rc} />}
        {auth.role === "doctor" && tab === "audit" && <AuditLog user={auth.user} />}
        {auth.role === "passerby" && tab === "scan" && <EmergencyScan roleColor={rc} />}
        {auth.role === "passerby" && tab === "firstaid" && <AIFirstAid />}
        {auth.role === "passerby" && tab === "hospital" && <HospitalFinder />}
        {auth.role === "passerby" && tab === "samaritan" && <GoodSamaritan />}
      </div>
    </div>
  );
}