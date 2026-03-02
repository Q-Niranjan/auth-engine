# AuthEngine

> A production-ready Identity & Access Management (IAM) system built with FastAPI.
> Build authentication once — every app connects to AuthEngine to verify users and check permissions.

[![Live Docs](https://img.shields.io/badge/Live%20Docs-Swagger%20UI-blue)](https://authengine-1-0-0.onrender.com/docs)
[![Docker](https://img.shields.io/badge/Docker-qniranjan01%2Fauthengine-blue)](https://hub.docker.com/r/qniranjan01/authengine)

---

## How It Works

Instead of building login, roles, and permissions into every service you create, you build it once here. Every app connects to AuthEngine to verify users and check permissions.

```
  ┌─────────────────────┐        ┌──────────────────────────┐        ┌─────────────────────┐
  │    LOGIN METHODS    │        │        AUTHENGINE         │        │    YOUR SERVICES    │
  │─────────────────────│        │    (Identity Hub)         │        │─────────────────────│
  │  📧 Email+Password  │        │──────────────────────────│        │  ▸ YourCompany      │
  │  🔵 Google OAuth    │        │  ✓ Issues JWT on login   │        │    web / mobile app │
  │  ⚫ GitHub OAuth    │        │  ✓ Validates tokens via  │        │                     │
  │  🪟 Microsoft OAuth │        │    /introspect           │        │  ▸ ServiceA         │
  │  🔗 Magic Links     │        │  ✓ Manages users, roles  │        │    backend service  │
  │  🔐 TOTP / MFA      │        │  ✓ Multi-tenant isolation│        │                     │
  │  🌐 WebAuthn API    │        │  ✓ OIDC Provider Flows   │        │  ▸ Third-Party Apps │
  └──────────┬──────────┘        └──────────────────────────┘        └──────────┬──────────┘
             │                                │                                  │
             ├── POST /auth/login ───────────►│◄── POST /introspect + X-API-Key ─┤
             │◄── JWT token ─────────────────┤├── { active, email, permissions }►│
             │                                │                                  │
             │           (Or OIDC)            │                                  │
             ├── GET /oidc/authorize ────────►│◄── OIDC /token Auth Code Flow ───┤
             │◄── Auth Code / ID Token ──────┤├── Standard OIDC Validation ─────►│
```

**Your services never hold the JWT secret** — they just ask AuthEngine "is this token valid right now?" or use standard OIDC flows.

---

## Core Features

| Feature | Description |
|---------|-------------|
| **OIDC Provider** | Full OpenID Connect support (Discovery, Auth Code, Dynamic Registration) |
| **Multiple Login Methods** | Email/password, Google, GitHub, Microsoft OAuth, Magic Links |
| **TOTP / MFA** | Two-factor auth via Google Authenticator or Authy |
| **WebAuthn / Passkeys** | Passwordless login via biometric/hardware keys |
| **Permission-Based Access Control** | Fine-grained permissions — not just role names |
| **Multi-Tenancy** | One user, multiple organizations, isolated roles per org |
| **Token Introspection** | Real-time token validation with instant revocation |
| **Service API Keys** | Scoped keys for each service calling introspect |
| **Audit Logging** | Every sensitive action logged to MongoDB |
| **Session Management** | Redis-backed sessions with per-device revocation |
| **Auto-Bootstrap** | Seeds roles, permissions, and super admin on first run |

---

## Authentication Methods

| Method | Status |
|--------|--------|
| Email + Password (Argon2) | Live |
| Google OAuth 2.0 | Live |
| GitHub OAuth 2.0 | Live |
| Microsoft OAuth 2.0 | Live |
| Magic Links (passwordless) | Live |
| TOTP / MFA | Live |
| WebAuthn / Passkeys | Live |

---

## Quick Start

**Option 1 — Docker Compose (recommended)**

```bash
git clone https://github.com/your-org/auth-engine
cd auth-engine

cp .env.example .env
# Edit .env — set SECRET_KEY, JWT_SECRET_KEY, and database credentials

docker compose up -d
docker compose exec app auth-engine migrate
```

**Option 2 — Run manually**

```bash
pip install uv
uv sync

cp .env.example .env
auth-engine migrate
auth-engine run
```

Visit `http://localhost:8000/docs` for the interactive API explorer.

---

## Deployed Stack

| Layer | Service |
|-------|---------|
| FastAPI App | [Render](https://render.com) |
| PostgreSQL | [Supabase](https://supabase.com) |
| MongoDB | [MongoDB Atlas](https://cloud.mongodb.com) |
| Redis | [Upstash](https://upstash.com) |

---

## Role Hierarchy

```
Level 100  ██████████  SUPER_ADMIN     — Full platform control (auto-created on first run)
Level  80  ████████░░  PLATFORM_ADMIN  — Manage all tenants and users
Level  60  ██████░░░░  TENANT_OWNER    — Full control of their organization
Level  50  █████░░░░░  TENANT_ADMIN    — Manage members and roles within tenant
Level  30  ███░░░░░░░  TENANT_MANAGER  — Day-to-day operational management
Level  10  █░░░░░░░░░  TENANT_USER     — Standard authenticated tenant member
```

A role can only assign roles with a **strictly lower** level than their own — privilege escalation is impossible by design.

---

## Integrating a Service

**Step 1 — Create a service API key (Platform Admin):**

```bash
POST /api/v1/platform/service-keys
Authorization: Bearer <platform_admin_jwt>

{ "service_name": "YourCompany", "tenant_id": "<tenant_uuid>" }
```

The response contains `raw_key` — shown only once. Store it securely.

**Step 2 — Validate tokens from your service:**

```python
async def verify_user(access_token: str) -> dict:
    response = await httpx.post(
        "https://authengine-1-0-0.onrender.com/api/v1/auth/introspect",
        headers={"X-API-Key": settings.AUTHENGINE_API_KEY},
        json={"token": access_token, "tenant_id": str(YOUR_TENANT_ID)},
    )
    data = response.json()
    if not data["active"]:
        raise HTTPException(status_code=401)
    # data contains: user_id, email, permissions, tenant_ids, auth_strategy, ...
    return data
```

---

> For architecture diagrams, data models, full API reference, configuration, and extension guides — see **[TECHNICAL.md](TECHNICAL.md)**.
> For OpenID Connect (OIDC) provider capabilities and integration, see **[OIDC.md](OIDC.md)**.