# AuthEngine

> A production-ready Identity & Access Management (IAM) system built with FastAPI. One auth layer for all your applications — login, roles, permissions, and token validation in one place.

📖 **[Technical Reference →](TECHNICAL.md)** — architecture, data models, flows, Redis keys, config, and extension guide.

---

## What It Does

Instead of building authentication into every service you create, you build it once here. Every app connects to AuthEngine to verify users and check permissions.

```
                        ┌─────────────────┐
                        │   AuthEngine    │
                        │  (Identity Hub) │
                        └────────┬────────┘
                                 │
          ┌──── issues JWT ──────┴────── verifies JWT ────┐
          ▼                                               ▼
   User logs in                               YourApp calls /introspect
   via any method                             "Is this token still valid?"
```

---

## Authentication Methods

| Method | Status |
|--------|--------|
| Email + Password | ✅ Live |
| Google OAuth 2.0 | ✅ Live |
| GitHub OAuth 2.0 | ✅ Live |
| Microsoft OAuth 2.0 | ✅ Live |
| Magic Links (passwordless) | ✅ Live |
| TOTP / MFA (Google Authenticator) | ✅ Live |
| WebAuthn / Passkeys | 🔜 Planned |

---

## Core Features

**Multiple login methods** — users can sign in with email/password, Google, GitHub, Microsoft, or a one-click magic link. Multiple providers can be linked to one account.

**MFA / Two-Factor Auth** — users can enable TOTP-based MFA via any authenticator app (Google Authenticator, Authy, etc.). Once enabled, login requires a second step after the password.

**Permission-Based Access Control** — roles carry named permissions like `tenant.users.manage`. Your services check permissions, not role names, so access rules stay flexible.

**Multi-Tenancy** — one user can belong to multiple organizations with different roles in each. Organizations are fully isolated from each other.

**Token Introspection** — your services don't hold the JWT secret. They ask AuthEngine "is this token valid?" on each request. When a user logs out, all services see `active: false` instantly.

**Audit Logging** — every login, logout, role change, and sensitive action is logged with actor, resource, and metadata.

**Auto-Bootstrap** — on first startup, all default roles, permissions, and a super admin account are created automatically.

---

## How Integration Works

```
1.  User logs in → AuthEngine issues a JWT
2.  JWT stored in your frontend

On every protected request to YourApp:
3.  YourApp sends the JWT to POST /auth/introspect  (with X-API-Key header)
4.  AuthEngine checks: is the token valid? is the session alive? is the user active?
5.  Returns { active: true, email, permissions, ... }
6.  YourApp serves or rejects the request
```

Your app **never holds the JWT secret** — it just asks AuthEngine in real time.

---

## Quick Start

**Option 1 — Docker Compose (recommended):**

```bash
git clone https://github.com/your-org/auth-engine
cd auth-engine

cp .env.example .env
# Set SECRET_KEY, JWT_SECRET_KEY, and database passwords

docker compose up -d
docker compose exec app auth-engine migrate
```

**Option 2 — Manual:**

```bash
pip install uv
uv sync

cp .env.example .env
auth-engine migrate
auth-engine run
```

Visit `http://localhost:8000/docs` for the interactive API explorer.

---

## Environment Setup

Minimum required variables in `.env`:

```env
SECRET_KEY=<generate with: openssl rand -hex 32>
JWT_SECRET_KEY=<generate with: openssl rand -hex 32>

POSTGRES_URL=postgresql+asyncpg://authengine:password@localhost:5432/authengine # pragma: allowlist secret
MONGODB_URL=mongodb://admin:password@localhost:27017 # pragma: allowlist secret
REDIS_URL=redis://localhost:6379

SUPERADMIN_EMAIL=admin@yourdomain.com
SUPERADMIN_PASSWORD=YourStrongPassword123!

EMAIL_PROVIDER=sendgrid
EMAIL_PROVIDER_API_KEY=your-api-key
EMAIL_SENDER=noreply@yourdomain.com

# Leave blank to disable that OAuth provider
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
MICROSOFT_CLIENT_ID=
MICROSOFT_CLIENT_SECRET=
```

---

## API Overview

**Base URL:** `http://localhost:8000/api/v1`  
**Interactive docs:** `http://localhost:8000/docs`

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/register` | Register with email + password |
| `POST` | `/auth/login` | Login — returns tokens or MFA challenge |
| `POST` | `/auth/logout` | Revoke session |
| `POST` | `/auth/refresh` | Refresh access token |
| `POST` | `/auth/password-reset/request` | Request password reset email |
| `POST` | `/auth/password-reset/confirm` | Confirm new password |
| `GET`  | `/auth/verify-email` | Verify email address |
| `POST` | `/auth/magic-link/request` | Send passwordless login link |
| `GET`  | `/auth/magic-link/verify` | Exchange magic link for tokens |
| `POST` | `/auth/mfa/complete` | Complete MFA step after login |

### OAuth Social Login

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/auth/oauth/{provider}/login` | Start OAuth flow (google / github / microsoft) |
| `GET`  | `/auth/oauth/{provider}/callback` | OAuth callback — returns tokens |
| `GET`  | `/auth/oauth/{provider}/link` | Link a provider to an existing account |
| `GET`  | `/auth/oauth/accounts` | List my linked OAuth providers |

### MFA (Authenticated Users)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST`   | `/me/mfa/enroll` | Start MFA setup — returns QR code URI |
| `POST`   | `/me/mfa/verify` | Confirm first TOTP code to activate MFA |
| `DELETE` | `/me/mfa/disable` | Disable MFA (requires valid TOTP code) |
| `GET`    | `/me/mfa/status` | Check if MFA is enabled |

### Token Introspection

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/auth/introspect` | `X-API-Key` | Validate user token — returns identity + permissions |

### User Context

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/me` | My profile |
| `GET` | `/me/tenants` | Organizations I belong to |
| `GET` | `/me/tenants/{id}/permissions` | My permissions in an organization |

### Platform Admin

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET/POST` | `/platform/tenants` | List or create organizations |
| `GET/PUT/DELETE` | `/platform/tenants/{id}` | Manage an organization |
| `GET` | `/platform/users` | List all users |
| `POST/DELETE` | `/platform/roles/users/{id}/roles` | Assign or remove platform roles |
| `POST` | `/platform/service-keys` | Create an API key for a service |
| `DELETE` | `/platform/service-keys/{id}` | Revoke a service API key |
| `GET` | `/platform/audit` | Platform-wide audit logs |

### Tenant Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET/POST` | `/tenants/users/{tenant_id}/users` | List or invite users |
| `DELETE` | `/tenants/users/{tenant_id}/users/{uid}` | Remove user from organization |
| `POST/DELETE` | `/tenants/roles/{tenant_id}/users/{uid}/roles` | Assign or remove tenant roles |
| `GET` | `/tenants/audit/{tenant_id}/audit-logs` | Tenant audit logs |

---

## Roles

| Role | Scope | Can Do |
|------|-------|--------|
| `SUPER_ADMIN` | Platform | Everything. Auto-created on first run. |
| `PLATFORM_ADMIN` | Platform | Manage all tenants, users, and service keys |
| `TENANT_OWNER` | Tenant | Full control of their organization |
| `TENANT_ADMIN` | Tenant | Manage members and roles |
| `TENANT_MANAGER` | Tenant | Day-to-day operations |
| `TENANT_USER` | Tenant | Standard member access |

---

## License

MIT

---

> For architecture deep-dives, data models, Redis key patterns, and extension guides see **[TECHNICAL.md](TECHNICAL.md)**.