# 🔐 MEDKEY — Secure Medical Records Platform

> A multi-phase medical records security system implementing symmetric, asymmetric, and hybrid encryption to protect sensitive patient data — with emergency access via offline QR codes.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Environment Variables](#environment-variables)
- [API Endpoints](#api-endpoints)
- [Encryption System](#encryption-system)
- [Samaritan Module](#samaritan-module)
- [Contributing](#contributing)
- [Author](#author)

---

## 🌐 Overview

**MEDKEY** is a secure medical records platform designed to protect sensitive patient data using a multi-layered encryption approach. It provides healthcare providers with a robust REST API for managing encrypted health records, while enabling emergency access through an offline QR code system — even without internet connectivity. All access by emergency personnel is audit-logged for accountability.

---

## ✨ Features

- 🔒 **Multi-Phase Encryption** — Symmetric, asymmetric, and hybrid encryption for layered data security
- 🗄️ **Encrypted Health Records** — Secure CRUD operations on patient data via PostgreSQL
- 📲 **Offline QR Code System** — Emergency access to critical medical info without internet
- 🚨 **Samaritan Module** — Authorized emergency personnel access with full audit logging
- 🔑 **Key Management** — Secure generation, storage, and rotation of encryption keys
- 🛡️ **REST API Layer** — Clean and secure endpoints for all health record operations
- 📋 **Audit Logs** — Every access to patient records is logged with timestamp and personnel ID

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python |
| Frontend | JavaScript, HTML, CSS |
| Database | PostgreSQL (SQL) |
| Encryption | Python Cryptography library (Fernet, RSA) |
| QR Code | Python `qrcode` library |
| API | REST (Flask / FastAPI) |
| Version Control | Git, GitHub |

---

## 📁 Project Structure

```
MEDKEY/
├── frontend/                    # Web UI
│   ├── index.html
│   ├── style.css
│   └── app.js
│
├── backend/                     # Core application
│   ├── main.py                  # API entry point
│   ├── routes/
│   │   ├── records.py           # Health record CRUD routes
│   │   ├── auth.py              # Authentication routes
│   │   └── samaritan.py        # Emergency access routes
│   ├── models/
│   │   ├── patient.py           # Patient data model
│   │   └── audit_log.py        # Audit log model
│   ├── encryption/
│   │   ├── symmetric.py         # AES / Fernet encryption
│   │   ├── asymmetric.py        # RSA encryption
│   │   └── hybrid.py            # Hybrid encryption logic
│   ├── qr/
│   │   ├── generate_qr.py       # QR code generation
│   │   └── decode_qr.py         # QR code decoding
│   └── samaritan/
│       ├── access.py            # Emergency access logic
│       └── audit.py             # Audit logging
│
├── db/
│   └── schema.sql               # PostgreSQL schema
│
├── .env                         # Environment variables
├── requirements.txt
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites

Make sure you have the following installed:

- [Python](https://www.python.org/) (v3.9+)
- [PostgreSQL](https://www.postgresql.org/)
- [Git](https://git-scm.com/)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Saksham2507/MEDKEY.git
   cd MEDKEY
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up PostgreSQL database**
   ```bash
   psql -U postgres -c "CREATE DATABASE medkey;"
   psql -U postgres -d medkey -f db/schema.sql
   ```

4. **Set up environment variables** (see [Environment Variables](#environment-variables))

5. **Start the API server**
   ```bash
   python backend/main.py
   ```

6. Open your browser and go to `http://localhost:5000`

---

## 🔑 Environment Variables

Create a `.env` file in the root directory with the following:

```env
DATABASE_URL=postgresql://username:password@localhost:5432/medkey
SECRET_KEY=your_secret_key
RSA_PRIVATE_KEY_PATH=keys/private.pem
RSA_PUBLIC_KEY_PATH=keys/public.pem
FERNET_KEY=your_fernet_key
```

---

## 📡 API Endpoints

### Auth Routes
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register a new user |
| POST | `/api/auth/login` | Login and receive access token |

### Health Record Routes
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/records` | Get all records (encrypted) |
| GET | `/api/records/:id` | Get a specific patient record |
| POST | `/api/records` | Create a new encrypted record |
| PUT | `/api/records/:id` | Update an existing record |
| DELETE | `/api/records/:id` | Delete a record |

### QR Code Routes
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/qr/generate` | Generate QR code for a patient |
| POST | `/api/qr/decode` | Decode and retrieve QR data |

### Samaritan Routes
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/samaritan/access` | Emergency access to patient record |
| GET | `/api/samaritan/logs` | View audit logs for emergency access |

---

## 🔐 Encryption System

MEDKEY uses a three-phase encryption approach:

### Phase 1 — Symmetric Encryption (AES / Fernet)
- Fast encryption for bulk patient data
- Used for encrypting the actual medical records stored in the database

### Phase 2 — Asymmetric Encryption (RSA)
- Used for encrypting the symmetric keys
- Each patient's symmetric key is encrypted with the provider's RSA public key

### Phase 3 — Hybrid Encryption
- Combines both approaches for maximum security and performance
- Symmetric key encrypted with RSA; data encrypted with symmetric key

---

## 🚨 Samaritan Module

The **Samaritan Module** allows authorized emergency personnel to access critical patient records when the patient is unable to provide consent.

- Access is granted only to pre-authorized emergency roles
- Every access event is logged with: personnel ID, timestamp, patient ID, and reason
- Audit logs are immutable and stored separately from patient records
- QR codes can be scanned offline to retrieve critical data (blood type, allergies, emergency contacts) without internet

---

## 🤝 Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a new branch: `git checkout -b feature/your-feature-name`
3. Commit your changes: `git commit -m 'Add some feature'`
4. Push to the branch: `git push origin feature/your-feature-name`
5. Open a Pull Request

---

## 👤 Author

**Saksham Raj**  
📧 sakshamraj2507@gmail.com  
🔗 [GitHub](https://github.com/Saksham2507)

---

> ⭐ If you found this project useful, please consider giving it a star!
