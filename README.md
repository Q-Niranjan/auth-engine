# AuthEngine

> A production-ready Identity & Access Management (IAM) system built with FastAPI. Handles authentication, multi-tenancy, fine-grained permissions, and token introspection — designed to power multiple applications from a single identity layer.

---

## What It Does

AuthEngine is the authentication and authorization backbone for your platform. Instead of building login, roles, and permissions into every app you create, you build it once here and every app connects to it.

```
                        ┌──────────────────────────────┐
                        │         AuthEngine           │
                        │     (Identity Provider)      │
                        └──────────────┬───────────────┘
                                       │
              ┌──────── issues JWT ────┘──────── verifies JWT ────────┐
              │                                                        │
              ▼                                                        ▼
   ┌─────────────────────┐                          ┌──────────────────────────┐
   │   User logs in via  │                          │  Your Company /ServiceA  │
   │  Google / GitHub /  │                          │  calls /auth/introspect  │
   │  Email + Password   │                          │  with user's token       │
   └─────────────────────┘                          └──────────────────────────┘
```

---

## Authentication Methods

| Method | Status | Description |
|--------|--------|-------------|
| Email + Password | Live | Argon2 hashing, password policy enforcement |
| Google OAuth 2.0 | Live | One-click login via Google account |
| GitHub OAuth 2.0 | Live | One-click login via GitHub account |
| Microsoft OAuth 2.0 | Live | Personal & Azure AD / work accounts |
| Magic Links | Next | Passwordless email login |
| TOTP / MFA | Next | Google Authenticator / Authy |
| WebAuthn / Passkeys | Planned | Biometric & hardware key support |

---

## Core Features

**Permission-Based Access Control (PBAC)** — roles carry explicit permissions like `tenant.roles.assign` rather than hardcoded names. Roles have numeric levels (0–100) to prevent privilege escalation.

**Multi-Tenancy** — full organizational isolation. One user can belong to multiple tenants with different roles in each. YourComapny and ServiceA share the same identity layer but are completely isolated.

**OAuth 2.0 Social Login** — users authenticate via Google, GitHub, or Microsoft. AuthEngine receives their identity, creates or links a local account, and issues its own JWT. Multiple providers can be linked to one account.

**Token Introspection** — external services validate user tokens by calling `/auth/introspect` instead of holding the JWT secret. When a user logs out, the session is deleted from Redis and the next introspect call instantly returns `active: false` across all services.

**Service API Keys** — each external service that calls introspect authenticates itself with a scoped API key (`X-API-Key` header). Keys are stored as SHA-256 hashes, shown only once at creation, and can be revoked instantly by a Platform Admin.

**Session Management** — Redis-backed sessions with device tracking. Users can view all active sessions and revoke any of them instantly.

**Audit Logging** — every sensitive action logged to MongoDB with actor, resource, action, and metadata.

**Auto-Bootstrap** — on first startup, AuthEngine seeds all default roles, permissions, and a `SUPER_ADMIN` account automatically.

---

## How Your Company will Uses AuthEngine

```
1.  User visits YourCompany → clicks "Login with Google"
2.  YourCompany redirects to  GET /api/v1/auth/oauth/google/login
3.  AuthEngine redirects user to Google consent page
4.  User approves → Google sends callback to AuthEngine
5.  AuthEngine creates/finds user, issues its own JWT
6.  JWT returned to YourComapny → stored in frontend

On every protected request:
7.  YourCompany sends token to  POST /api/v1/auth/introspect  (X-API-Key header)
8.  AuthEngine validates token + checks live session in Redis + checks user status
9.  Returns { active: true, email, permissions, tenant_ids, ... }
10. YourCompany serves or rejects the request
```

YourCompany **never holds the JWT secret** — it simply asks AuthEngine "is this token valid right now?"

---

## Quick Start

### Option 1 — Docker Compose (Recommended)

The fastest way to get everything running:

```bash
git clone https://github.com/your-org/auth-engine
cd auth-engine

cp .env.example .env
# Edit .env — set SECRET_KEY, JWT_SECRET_KEY, and database passwords

docker compose up -d
docker compose exec app auth-engine migrate
```

Visit `http://localhost:8000/docs` for interactive API documentation.

### Option 2 — Manual Setup

**Step 1 — Start infrastructure with Docker:**

```bash
# PostgreSQL
docker run -d \
  --name authengine-postgres \
  -p 5432:5432 \
  -e POSTGRES_USER=authengine \
  -e POSTGRES_PASSWORD=strongpassword \
  -e POSTGRES_DB=authengine \
  -v authengine_pg_data:/var/lib/postgresql/data \
  --restart unless-stopped \
  postgres:16

# MongoDB (requires auth credentials)
docker run -d \
  --name authengine-mongo \
  -p 27017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=admin \
  -e MONGO_INITDB_ROOT_PASSWORD=strongpassword \
  -v authengine_mongo_data:/data/db \
  --restart unless-stopped \
  mongo:latest

# Redis — no password required for local development
docker run -d \
  --name authengine-redis \
  -p 6379:6379 \
  -v authengine_redis_data:/data \
  --restart unless-stopped \
  redis:7-alpine
```

**Step 2 — Install and run AuthEngine:**

```bash
pip install uv
uv sync

cp .env.example .env
# Edit .env with your credentials

auth-engine migrate
auth-engine run
```

---

## Environment Configuration

Copy `.env.example` to `.env` and set these key values:

```env
# Security — generate with: openssl rand -hex 32
SECRET_KEY=your-secret-key-min-32-characters
JWT_SECRET_KEY=your-jwt-secret-key-min-32-characters

# Databases
POSTGRES_URL=postgresql+asyncpg://<authengine>:<strongpassword>@localhost:5432/authengine
MONGODB_URL=mongodb://admin:<strongpassword>@localhost:27017
REDIS_URL=redis://localhost:6379        # no password for local dev

# Super Admin — auto-created on first startup
SUPERADMIN_EMAIL=admin@yourdomain.com
SUPERADMIN_PASSWORD=YourStrongPassword123!

# OAuth — leave CLIENT_ID empty to disable that provider
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
MICROSOFT_CLIENT_ID=
MICROSOFT_CLIENT_SECRET=
```

---

## Full API Reference

**Base URL:** `http://localhost:8000/api/v1`  
**Interactive Docs:** `http://localhost:8000/docs`

### Authentication (Public)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/register` | Register with email + password |
| `POST` | `/auth/login` | Login, returns access + refresh tokens |
| `POST` | `/auth/logout` | Revoke session |
| `POST` | `/auth/refresh` | Get new access token using refresh token |
| `POST` | `/auth/password-reset/request` | Initiate password reset |
| `GET`  | `/auth/password-reset/confirm` | Validate reset token |
| `POST` | `/auth/password-reset/confirm` | Confirm/Update password |
| `POST` | `/auth/set-password` | Set password (for OAuth users with no password) |
| `GET`  | `/auth/verify-email` | Verify email with token |
| `POST` | `/auth/verify-phone` | Verify phone with OTP |
| `POST` | `/auth/request-token` | Request a specific action token |

### OAuth 2.0 Social Login (Public)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/auth/oauth/{provider}/login` | Initiate OAuth flow — redirects to provider |
| `GET`  | `/auth/oauth/{provider}/callback` | OAuth callback — returns JWT tokens |
| `GET`  | `/auth/oauth/{provider}/link` | Link additional provider to existing account |
| `GET`  | `/auth/oauth/accounts` | List all OAuth providers linked to my account |

Supported providers: `google`, `github`, `microsoft`

### Token Introspection (Service-to-Service)

| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| `POST` | `/auth/introspect` | `X-API-Key` header | Validate user token, returns identity + permissions |

### User Context (Authenticated Users)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/me` | Get current user profile |
| `GET`  | `/me/tenants` | List all tenants I belong to |
| `GET`  | `/me/tenants/{tenant_id}/permissions` | My permissions in a specific tenant |

### Platform Management (SUPER_ADMIN / PLATFORM_ADMIN)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`    | `/platform/tenants` | List all organizations |
| `POST`   | `/platform/tenants` | Create new organization |
| `GET`    | `/platform/tenants/{id}` | Get organization details |
| `PUT`    | `/platform/tenants/{id}` | Update organization |
| `DELETE` | `/platform/tenants/{id}` | Delete organization |
| `GET`    | `/platform/users` | List all platform users |
| `POST`   | `/platform/users/{id}/roles` | Assign platform-level role |
| `DELETE` | `/platform/users/{id}/roles/{role}` | Remove platform-level role |
| `GET`    | `/platform/audit-logs` | View platform-wide audit logs |
| `GET`    | `/platform/tenants/{id}/audit-logs` | View audit logs for a tenant |
| `POST`   | `/platform/service-keys` | Create service API key for a service |
| `GET`    | `/platform/service-keys` | List all service API keys |
| `DELETE` | `/platform/service-keys/{id}` | Revoke a service API key |

### Tenant Management (Tenant Admins)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`    | `/tenants/{id}/users` | List all members of tenant |
| `POST`   | `/tenants/{id}/users` | Invite user to tenant |
| `GET`    | `/tenants/{id}/users/{uid}` | Get a user's details in tenant |
| `DELETE` | `/tenants/{id}/users/{uid}` | Remove user from tenant |
| `GET`    | `/tenants/{id}/roles` | List available roles |
| `GET`    | `/tenants/{id}/users/{uid}/roles` | Get user's roles in tenant |
| `POST`   | `/tenants/{id}/users/{uid}/roles` | Assign role to user in tenant |
| `DELETE` | `/tenants/{id}/users/{uid}/roles/{role}` | Remove role from user in tenant |
| `GET`    | `/tenants/{id}/audit-logs` | View tenant audit logs |

### System

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/health` | Health check — reports DB + Redis status |

---

## Role Hierarchy

| Role | Level | Scope | What They Can Do |
|------|-------|-------|-----------------|
| `SUPER_ADMIN` | 100 | Platform | Everything — bootstrap only, cannot be assigned manually |
| `PLATFORM_ADMIN` | 80 | Platform | Manage all tenants, users, and service keys |
| `TENANT_OWNER` | 60 | Tenant | Full control of their organization |
| `TENANT_ADMIN` | 50 | Tenant | Manage members and roles within tenant |
| `TENANT_MANAGER` | 30 | Tenant | Day-to-day operational management |
| `TENANT_USER` | 10 | Tenant | Standard authenticated tenant member |

The level hierarchy prevents privilege escalation: a role can only assign or remove roles with a strictly lower level than their own. A `TENANT_ADMIN` (50) cannot touch another `TENANT_ADMIN` (50).

---

## Integrating a Service with Introspection

**Step 1 — Platform Admin creates a service API key:**

```bash
POST /api/v1/platform/service-keys
Authorization: Bearer <platform_admin_jwt>
Content-Type: application/json

{
  "service_name": "YourCompany Name",
  "tenant_id": "<your_company_tenant_tenant_uuid>"
}
```

Response contains `raw_key` — shown only once, store it securely.

**Step 2 — Service uses the key to validate user tokens:**

```python
# YourComapany auth middleware
async def verify_user_token(access_token: str) -> dict:
    response = await httpx.post(
        "https://authengine.com/api/v1/auth/introspect",
        headers={"X-API-Key": settings.AUTHENGINE_API_KEY},
        json={
            "token": access_token,
            "tenant_id": str(YOUR_COMPANY_TENANT_ID)
        }
    )
    data = response.json()

    if not data["active"]:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # data contains: user_id, email, first_name, last_name,
    #                permissions, tenant_ids, auth_strategy,
    #                issued_at, expires_at
    return data
```

---

---

## Running Tests

```bash
# Run all tests
pytest

# With coverage report
pytest --cov=auth_engine tests/
```

---

## License

MIT
