# AuthEngine — Technical Reference

← **[Back to README](README.md)**

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Request Lifecycle](#request-lifecycle)
3. [Project Structure](#project-structure)
4. [Authentication Strategies](#authentication-strategies)
5. [Magic Links](#magic-links)
6. [TOTP / MFA](#totp--mfa)
7. [Authorization Model (PBAC)](#authorization-model-pbac)
8. [Multi-Tenancy Design](#multi-tenancy-design)
9. [API Overview](#api-overview)
10. [Roles](#roles)
11. [Data Models](#data-models)
12. [Token Introspection](#token-introspection)
13. [Service API Keys](#service-api-keys)
14. [Session Management](#session-management)
15. [Database Layer](#database-layer)
16. [Configuration Reference](#configuration-reference)
17. [Infrastructure Setup](#infrastructure-setup)
18. [Extension Guide](#extension-guide)

---

## Architecture Overview

AuthEngine is built around three core principles:

**Strategy Pattern** — every auth method is an isolated class implementing `BaseAuthStrategy`. Adding a new provider never touches existing code.

**PBAC with Level Hierarchy** — guards check permission strings, not role names. Roles are containers of permissions. Numeric levels (0–100) prevent privilege escalation.

**Repository Pattern** — services own business logic, repositories own all DB access. Services never import SQLAlchemy, Motor, or Redis directly.

```
  ┌─────────────────────────────────────────────────────────────────────────────────────┐
  │                                EXTERNAL WORLD                                       │
  │   Browser / Mobile App          YourCompany Backend          ServiceA               │
  │        │                               │                        │                   │
  │        │  HTTP (login/auth)            │  POST /introspect      │  POST /introspect │
  │        │                               │  + X-API-Key           │  + X-API-Key      │
  └────────┼───────────────────────────────┼────────────────────────┼───────────────────┘
           │                               │                        │
           ▼                               ▼                        ▼
  ╔══════════════════════════════════════════════════════════════════════════════════════╗
  ║                            AUTHENGINE  (FastAPI)                                     ║
  ║                                                                                      ║
  ║  ┌─────────────────────────────────────────────────────────────────────────────┐     ║
  ║  │  API LAYER  (/auth/*  /auth/oauth/*  /auth/introspect  /platform/*  /me/*)  │     ║
  ║  └─────────────────────────────────────────────────────────────────────────────┘     ║
  ║                                                                                      ║
  ║  ┌─────────────────────────────────────────────────────────────────────────────┐     ║
  ║  │  DEPENDENCY INJECTION  (get_current_user · require_permission · get_db)     │     ║
  ║  └─────────────────────────────────────────────────────────────────────────────┘     ║
  ║                                                                                      ║
  ║  ┌─────────────────────────────────────────────────────────────────────────────┐     ║
  ║  │  SERVICE LAYER                                                              │     ║
  ║  │  AuthService · OAuthService · IntrospectService · SessionService            │     ║
  ║  │  TOTPService · MagicLinkService · RoleService · TenantService · AuditService│     ║
  ║  └─────────────────────────────────────────────────────────────────────────────┘     ║
  ║                                                                                      ║
  ║  ┌─────────────────────────────────────────────────────────────────────────────┐     ║
  ║  │  AUTH STRATEGIES                                                            │     ║
  ║  │  EmailPasswordStrategy · GoogleOAuth · GitHubOAuth · MicrosoftOAuth         │     ║
  ║  │  MagicLinkStrategy · TOTPStrategy                                           │     ║
  ║  └─────────────────────────────────────────────────────────────────────────────┘     ║
  ║                                                                                      ║
  ║  ┌─────────────────────────────────────────────────────────────────────────────┐     ║
  ║  │  REPOSITORY LAYER  (UserRepo · OAuthRepo · ServiceApiKeyRepo · MongoRepo)   │     ║
  ║  └─────────────────────────────────────────────────────────────────────────────┘     ║
  ║                                                                                      ║
  ╚══════════════════════════════════════╪═══════════════════════════════════════════════╝
           ┌───────────────────────────┬─┴─────────────────────---┐
           ▼                           ▼                          ▼
  ┌─────────────────┐       ┌──────────────────┐       ┌──────────────────┐
  │  POSTGRESQL     │       │  MONGODB         │       │  REDIS           │
  │  (Supabase)     │       │  (Atlas)         │       │  (Upstash)       │
  │─────────────────│       │──────────────────│       │──────────────────│
  │  users          │       │  audit_logs      │       │  sessions        │
  │  roles          │       │  · actor_id      │       │  token blacklist │
  │  permissions    │       │  · action        │       │  OAuth state     │
  │  tenants        │       │  · resource      │       │  MFA pending     │
  │  oauth_accounts │       │  · tenant_id     │       │  magic link keys │
  │  service_keys   │       │  · metadata      │       │  rate limits     │
  └─────────────────┘       └──────────────────┘       └──────────────────┘
```

---

## Request Lifecycle

```
HTTP Request
     │
     ▼
FastAPI Router          ← matches path + method
     │
     ▼
Dependency Injection    ← resolves: DB session, Redis, current user, permission guard
     │
     ▼
Endpoint Function       ← thin layer, wires deps into service call
     │
     ▼
Service Layer           ← all business logic lives here
     │
     ▼
Repository Layer        ← translates to DB queries
     │
     ├──► PostgreSQL    (users, roles, tenants, permissions)
     ├──► MongoDB       (audit log write — fire and forget)
     └──► Redis         (session read/write, blacklist check)
```

---

## Project Structure

```
auth-engine/
├── alembic/
│   └── versions/
│       ├── e0f528e68aa9_add_all_tables.py
│       ├── 03efaee5723b_add_sms_model.py
│       ├── a48f25e886fa_include_utc_in_date_time.py
│       └── b1c2d3e4f5a6_add_mfa_fields.py
├── src/
│   └── auth_engine/
│       ├── api/
│       │   ├── dependencies/
│       │   │   ├── auth_deps.py           # get_current_user, get_current_active_user
│       │   │   ├── deps.py                # get_db, get_audit_service
│       │   │   └── rbac.py                # require_permission, check_platform_permission
│       │   └── v1/
│       │       ├── me/
│       │       │   ├── endpoints.py       # /me, /me/tenants, /me/tenants/{id}/permissions
│       │       │   └── mfa.py             # /me/mfa/enroll, /verify, /disable, /status
│       │       ├── public/
│       │       │   ├── auth.py            # register, login, logout, refresh, verify, reset
│       │       │   ├── oauth.py           # OAuth login/callback/link/accounts
│       │       │   ├── magic_link.py      # /auth/magic-link/request, /verify
│       │       │   ├── mfa.py             # /auth/mfa/complete
│       │       │   └── introspect.py      # POST /auth/introspect
│       │       ├── platform/
│       │       │   ├── tenant.py
│       │       │   ├── user.py
│       │       │   ├── roles.py
│       │       │   ├── audit.py
│       │       │   └── service_keys.py
│       │       ├── tenants/
│       │       │   ├── users.py
│       │       │   ├── roles.py
│       │       │   └── audit.py
│       │       ├── system/
│       │       │   └── system.py          # /health
│       │       └── router.py
│       ├── auth_strategies/
│       │   ├── base.py                    # BaseAuthStrategy, TokenBasedStrategy, PasswordBasedStrategy
│       │   ├── email_password.py
│       │   ├── magic_link.py
│       │   ├── totp.py
│       │   └── oauth/
│       │       ├── base_oauth.py
│       │       ├── google.py
│       │       ├── github.py              # handles private emails
│       │       ├── microsoft.py           # personal + Azure AD
│       │       └── factory.py
│       ├── core/
│       │   ├── config.py                  # Pydantic Settings — all env vars typed
│       │   ├── exceptions.py
│       │   ├── health.py
│       │   ├── mongodb.py
│       │   ├── postgres.py
│       │   ├── rbac_seed.py
│       │   ├── redis.py
│       │   └── security.py                # SecurityUtils (Argon2, Fernet), TokenManager (JWT)
│       ├── models/
│       │   ├── user.py                    # includes mfa_enabled, mfa_secret
│       │   ├── oauth_account.py
│       │   ├── role.py
│       │   ├── permission.py
│       │   ├── role_permission.py
│       │   ├── user_role.py
│       │   ├── tenant.py
│       │   ├── service_api_key.py
│       │   └── email_config.py
│       ├── repositories/
│       │   ├── postgres_repo.py           # Generic async SQLAlchemy CRUD
│       │   ├── user_repo.py
│       │   ├── oauth_repo.py
│       │   ├── service_api_key_repo.py
│       │   ├── mongo_repo.py
│       │   └── redis_repo.py
│       ├── schemas/
│       │   ├── user.py
│       │   ├── mfa.py
│       │   ├── magic_link.py
│       │   ├── oauth.py
│       │   ├── rbac.py
│       │   ├── tenant.py
│       │   └── introspect.py
│       ├── services/
│       │   ├── auth_service.py
│       │   ├── oauth_service.py
│       │   ├── introspect_service.py
│       │   ├── totp_service.py
│       │   ├── magic_link_service.py
│       │   ├── session_service.py
│       │   ├── role_service.py
│       │   ├── permission_service.py
│       │   ├── tenant_service.py
│       │   ├── user_service.py
│       │   └── audit_service.py
│       └── main.py
└── tests/
```

---

## Authentication Strategies

All strategies inherit from `BaseAuthStrategy`:

```python
class BaseAuthStrategy(ABC):
    async def authenticate(self, credentials: dict) -> dict: ...  # required
    async def validate(self, token: str) -> dict: ...             # required
    async def prepare_credentials(self, raw: dict) -> dict: ...   # optional hook
    async def post_authenticate(self, user_data: dict) -> dict:   # optional hook
```

Two abstract base variants:

- `PasswordBasedStrategy` — for email/password. `requires_password()` returns `True`.
- `TokenBasedStrategy` — for OAuth, magic links, TOTP. `requires_password()` returns `False`.

### Email/Password

`EmailPasswordStrategy` validates credentials against an Argon2 hash, checks account status, and issues JWTs via `TokenManager`.

### OAuth (Google / GitHub / Microsoft)

`BaseOAuthStrategy` defines a three-step flow:

1. `get_authorization_url(state)` — builds the provider redirect URL, stores CSRF state in Redis
2. `exchange_code_for_tokens(code)` — server-side authorization code exchange
3. `fetch_user_profile(access_token)` — calls provider userinfo endpoint

Each subclass overrides only `normalize_profile(raw)` to map provider-specific fields to a common format: `{provider_user_id, email, first_name, last_name, avatar_url, provider_name}`.

**GitHub special case:** GitHub emails can be private. `GitHubOAuthStrategy` makes a second call to `GET /user/emails` to find the primary verified address when the main profile returns null.

**OAuth users setting a password:** Call `POST /auth/set-password` to add a password to an OAuth-only account. This appends `email_password` to `auth_strategies`, enabling both login paths going forward.

**User identity resolution on OAuth callback:**

| Case | What happens |
|------|-------------|
| Known OAuth account | Update provider tokens, return existing user |
| Known email, new provider | Link new provider to existing account, return existing user |
| Brand new user | Create user (status=ACTIVE, email pre-verified), create OAuth account |

---

## Magic Links

Passwordless login via a signed, short-lived, single-use URL.

### Flow

```
POST /auth/magic-link/request  { email }
  1. Look up user — silently return 202 if not found (prevents enumeration)
  2. Generate JWT  (type=magic_link, jti=uuid4, TTL=15 min)
  3. redis.setex("magic:jti:{jti}", 900, "pending")   ← written BEFORE email is sent
  4. Send email with link: /auth/magic-link/verify?token=<jwt>
     If email fails → redis.delete(key)   ← rollback so token can't be replayed

GET /auth/magic-link/verify?token=<jwt>
  1. Decode + verify JWT signature and expiry
  2. Assert payload.type == "magic_link"
  3. redis.get("magic:jti:{jti}") → must be "pending"
  4. redis.delete(key) → returns 0 if race condition → 401
  5. Load user, create session, issue tokens
```

### Security Properties

| Property | Mechanism |
|----------|-----------|
| Signed | HS256 JWT via `JWT_SECRET_KEY` |
| Short TTL | 15 min (`exp` claim) |
| One-time use | Redis key consumed on first click |
| Race-safe | `redis.delete()` returns count — 0 means already used → 401 |
| Enumeration-safe | `/request` always returns 202 regardless of whether email exists |
| Rollback on failure | Redis key deleted if email dispatch fails |

---

## TOTP / MFA

Time-based One-Time Password second factor using `pyotp`.

### Enrollment

```
POST /me/mfa/enroll
  1. Generate TOTP secret via pyotp.random_base32()
  2. Encrypt with Fernet(SECRET_KEY) → store in users.mfa_secret
  3. Return provisioning_uri (for QR scan) + raw secret
     mfa_enabled stays False until confirmed

POST /me/mfa/verify  { code }
  1. Decrypt mfa_secret → verify code with pyotp (valid_window=1)
  2. Set users.mfa_enabled = True
```

### Login with MFA Enabled

```
POST /auth/login  { email, password }
  → credentials valid, user.mfa_enabled == True
  → store "mfa:pending:{user_id}" in Redis (5 min TTL)
  → return 202  { mfa_pending_token }   ← not a real session yet

POST /auth/mfa/complete  { mfa_pending_token, code }
  1. Decode mfa_pending_token (type=mfa_pending, not expired)
  2. redis.get("mfa:pending:{user_id}") → must exist
  3. redis.delete(key) → one-time, prevents replay
  4. Verify TOTP code against decrypted secret
  5. create_session() + issue tokens → 200
```

The login endpoint returns `Union[LoginResponse, MFAChallengeResponse]`:

- **200** — MFA not enabled, full tokens returned immediately
- **202** — MFA enabled, challenge token returned, second step required
- **401** — bad credentials

### Secret Storage

TOTP secrets are encrypted at rest via `SecurityUtils.encrypt_data()` (Fernet keyed from `SECRET_KEY`). The raw secret is never persisted — only the Fernet ciphertext in `users.mfa_secret`.

### MFA Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /me/mfa/enroll` | Begin setup — returns QR URI and raw secret |
| `POST /me/mfa/verify` | Confirm first code → activates MFA |
| `DELETE /me/mfa/disable` | Disable MFA (requires valid TOTP code) |
| `GET /me/mfa/status` | Check if MFA is currently enabled |

---

## Authorization Model (PBAC)

Guards check **permission strings**, not role names. Roles are just containers of permissions.

### Permissions

```
platform.users.view         platform.users.manage
platform.tenants.view       platform.tenants.manage
platform.roles.assign       platform.audit.view

tenant.view                 tenant.update           tenant.delete
tenant.users.view           tenant.users.manage
tenant.roles.view           tenant.roles.assign

auth.tokens.request         auth.tokens.refresh
auth.password.reset         auth.email.verify       auth.phone.verify
```

### Guards

```python
@require_permission("tenant.users.manage")
async def invite_user(...): ...

@check_platform_permission("platform.tenants.manage")
async def create_tenant(...): ...
```

`require_permission` extracts `tenant_id` from the URL path automatically and scopes the check to that tenant. Platform routes have no `tenant_id`, so they check global permissions.

### Level Hierarchy

```
SUPER_ADMIN    100  →  can act on levels 0–99
PLATFORM_ADMIN  80  →  can act on levels 0–79
TENANT_OWNER    60  →  can act on levels 0–59
TENANT_ADMIN    50  →  can act on levels 0–49
TENANT_MANAGER  30  →  can act on levels 0–29
TENANT_USER     10  →  can act on levels 0–9
```

A `TENANT_ADMIN` (50) cannot assign or remove another `TENANT_ADMIN` (50) — lateral attacks are impossible by design.

---

## Multi-Tenancy Design

```
UserORM  ←──────  UserRoleORM  ──────►  RoleORM
                       │
                       ▼
                  TenantORM
```

The link between a user and a tenant is `UserRoleORM` — a three-way join: `(user_id, role_id, tenant_id)`. One user can have multiple rows — one per (role, tenant) pair. The same user can be `TENANT_USER` in OrgA and `TENANT_ADMIN` in OrgB simultaneously.

All tenant-scoped endpoints include `tenant_id` in the URL path, and all permission checks evaluate within that specific tenant context.

---

## API Overview

**Base URL:** `https://authengine-1-0-0.onrender.com/api/v1`
**Interactive docs:** `https://authengine-1-0-0.onrender.com/docs`

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/register` | Register with email + password |
| `POST` | `/auth/login` | Login — returns tokens or MFA challenge (202) |
| `POST` | `/auth/logout` | Revoke session and blacklist token |
| `POST` | `/auth/refresh` | Refresh access token |
| `POST` | `/auth/password-reset/request` | Send password reset email |
| `POST` | `/auth/password-reset/confirm` | Set new password |
| `GET`  | `/auth/verify-email` | Verify email address |
| `POST` | `/auth/magic-link/request` | Send passwordless login link |
| `GET`  | `/auth/magic-link/verify` | Exchange magic link for tokens |
| `POST` | `/auth/mfa/complete` | Complete MFA step after primary login |

### OAuth Social Login

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/auth/oauth/{provider}/login` | Start OAuth flow — `provider`: google / github / microsoft |
| `GET` | `/auth/oauth/{provider}/callback` | OAuth callback — issues AuthEngine JWT |
| `GET` | `/auth/oauth/{provider}/link` | Link a provider to an existing account |
| `GET` | `/auth/oauth/accounts` | List my linked OAuth providers |

### MFA

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST`   | `/me/mfa/enroll` | Begin TOTP setup — returns QR URI + secret |
| `POST`   | `/me/mfa/verify` | Confirm first code → activates MFA |
| `DELETE` | `/me/mfa/disable` | Disable MFA (requires valid TOTP code) |
| `GET`    | `/me/mfa/status` | Check if MFA is enabled |

### Token Introspection

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/auth/introspect` | `X-API-Key` | Validate user token — returns identity + permissions |

### Current User

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/me` | My profile |
| `GET` | `/me/tenants` | Organizations I belong to |
| `GET` | `/me/tenants/{id}/permissions` | My permissions in a specific organization |

### Platform Admin

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET/POST` | `/platform/tenants` | List or create organizations |
| `GET/PUT/DELETE` | `/platform/tenants/{id}` | Manage an organization |
| `GET` | `/platform/users` | List all users across the platform |
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

| Role | Level | Scope | Description |
|------|-------|-------|-------------|
| `SUPER_ADMIN` | 100 | Platform | Full control. Auto-created on first run. Cannot be manually assigned. |
| `PLATFORM_ADMIN` | 80 | Platform | Manage all tenants, users, and service keys |
| `TENANT_OWNER` | 60 | Tenant | Full control of their organization |
| `TENANT_ADMIN` | 50 | Tenant | Manage members and roles within tenant |
| `TENANT_MANAGER` | 30 | Tenant | Day-to-day operational management |
| `TENANT_USER` | 10 | Tenant | Standard authenticated tenant member |

---

## Data Models

All models use SQLAlchemy 2.0 `Mapped` + `mapped_column`.

### UserORM

```
id                    : UUID (PK)
email                 : str (unique, indexed)
username              : str | None (unique)
phone_number          : str | None (unique)
password_hash         : str | None           ← null for OAuth-only users
first_name            : str | None
last_name             : str | None
avatar_url            : str | None
status                : UserStatus           ← ACTIVE | INACTIVE | SUSPENDED | PENDING_VERIFICATION
is_email_verified     : bool
is_phone_verified     : bool
mfa_enabled           : bool                 ← default False
mfa_secret            : str | None           ← Fernet-encrypted TOTP secret
auth_strategies       : list[str] (JSON)     ← ["email_password", "google", "magic_link"]
failed_login_attempts : int
last_login_at         : datetime | None
last_login_ip         : str | None
password_changed_at   : datetime | None
created_at            : datetime
updated_at            : datetime
deleted_at            : datetime | None      ← soft delete
```

### OAuthAccountORM

```
id                  : UUID (PK)
user_id             : UUID (FK → users.id, CASCADE DELETE)
provider            : str                    ← "google" | "github" | "microsoft"
provider_user_id    : str
access_token        : str | None
refresh_token       : str | None
token_expires_at    : datetime | None
provider_email      : str | None
provider_avatar_url : str | None
provider_name       : str | None
created_at          : datetime
updated_at          : datetime
UNIQUE (provider, provider_user_id)
```

### ServiceApiKeyORM

```
id            : UUID (PK)
service_name  : str
key_hash      : str (unique)    ← SHA-256 of raw key — never plaintext
key_prefix    : str             ← first 12 chars, safe to display in UI
tenant_id     : UUID | None (FK)
is_active     : bool
created_by    : UUID | None (FK → users.id)
last_used_at  : datetime | None
expires_at    : datetime | None
created_at    : datetime
updated_at    : datetime
```

### UserRoleORM

```
user_id   : UUID (PK, FK → users.id)
role_id   : UUID (PK, FK → roles.id)
tenant_id : UUID (PK, FK → tenants.id)
```

### RoleORM

```
id          : UUID (PK)
name        : str (unique)
description : str | None
scope       : RoleScope     ← PLATFORM | TENANT
level       : int           ← 0–100, prevents privilege escalation
created_at  : datetime
```

---

## Token Introspection

External services call `POST /auth/introspect` to validate a user JWT without holding the JWT secret. When a user logs out, their Redis session is deleted and the next introspect call instantly returns `active: false` — revocation is immediate across all services.

### 6-Step Validation

`IntrospectService.introspect()` runs these in order, returning `active: false` at the first failure. Never throws exceptions.

```
1. JWT decode        — verify signature + expiry (python-jose)
2. Blacklist check   — redis.exists("blacklist:{jti}")
3. Session check     — redis.exists("session:{user_id}:{session_id}")
4. User load         — fetch from PostgreSQL, must exist
5. Status check      — user.status must be ACTIVE
6. Permissions       — collect from user.roles, scoped to requested tenant_id
```

### Request / Response

```
POST /api/v1/auth/introspect
X-API-Key: ae_sk_...

{ "token": "<access_token>", "tenant_id": "<optional uuid>" }
```

```json
{
  "active": true,
  "user_id": "550e8400-...",
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "is_email_verified": true,
  "auth_strategy": "google",
  "permissions": ["tenant.view", "tenant.users.view"],
  "tenant_ids": ["..."],
  "issued_at": "2026-02-19T10:00:00Z",
  "expires_at": "2026-02-19T10:30:00Z"
}
```

On failure (any step): `{ "active": false }`

---

## Service API Keys

### Security Design

- Raw keys are **never stored** — only the SHA-256 hash is persisted
- Raw key shown exactly once in the create response — store it securely
- Keys can be **tenant-scoped** — a key bound to `tenant_id=X` cannot return data for other tenants regardless of what the caller sends
- Keys support `expires_at` for time-limited integrations
- Revocation (`DELETE /platform/service-keys/{id}`) takes effect on the next request with zero propagation delay

### Key Format

`ae_sk_{64 hex chars}` — the first 12 characters are stored as `key_prefix` for display in the platform UI.

---

## Session Management

Sessions stored in Redis as JSON under `session:{user_id}:{session_id}`.

Each session holds: `session_id`, `user_id`, `ip_address`, `user_agent`, `created_at`, `expires_at`.

The refresh token JWT contains a `sid` claim. On refresh, the session is verified in Redis before new tokens are issued. On logout, the session key is deleted immediately — the next introspect call returns `active: false`.

`MAX_CONCURRENT_SESSIONS` (default: 5) — when exceeded, the oldest session is evicted automatically.

Token blacklisting via `blacklist:{jti}` — used to invalidate a specific token without destroying the whole session.

---

## Database Layer

### PostgreSQL

All relational data: users, roles, permissions, tenants, oauth_accounts, service_api_keys, email_configs.

Async SQLAlchemy 2.0 with `asyncpg`. Connection pool controlled by `POSTGRES_POOL_SIZE` and `POSTGRES_MAX_OVERFLOW`. Migrations via Alembic — `auth-engine migrate`.

### MongoDB

Audit logs only. Append-only, schema-flexible. Collection: `audit_logs`.

Fields: `action`, `resource`, `resource_id`, `actor_id`, `tenant_id`, `metadata`, `timestamp`, `ip_address`, `user_agent`.

Indexes: `actor_id`, `tenant_id`, `created_at`, `(tenant_id, created_at DESC)`.

### Redis

| Key pattern | TTL | Purpose |
|-------------|-----|---------|
| `session:{user_id}:{session_id}` | Session lifetime | Active login sessions |
| `blacklist:{jti}` | Token remaining lifetime | Revoked tokens |
| `oauth:state:{token}` | 10 min | OAuth CSRF state |
| `magic:jti:{jti}` | 15 min | Magic link one-time flags |
| `mfa:pending:{user_id}` | 5 min | Pending MFA after primary auth |
| `ratelimit:{ip}:{minute}` | 60 sec | Rate limiting |
| `otp:phone:{user_id}` | 10 min | Phone verification OTPs |

---

## Configuration Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECRET_KEY` | Yes | — | App secret, min 32 chars. Also used for Fernet encryption (MFA secrets, magic link tokens) |
| `JWT_SECRET_KEY` | Yes | — | JWT signing key, min 32 chars |
| `POSTGRES_URL` | Yes | — | `postgresql+asyncpg://<user>:<pass>@host/db` |
| `MONGODB_URL` | Yes | — | `mongodb://<user>:<pass>@host:27017/db` |
| `REDIS_URL` | Yes | — | `redis://localhost:6379/0` or `rediss://` for TLS |
| `APP_URL` | — | `http://localhost:8000` | Public base URL — used in magic link emails |
| `APP_NAME` | — | `AuthEngine` | Shown in TOTP provisioning URIs |
| `SUPERADMIN_EMAIL` | — | `admin@authengine.com` | Bootstrap super admin email |
| `SUPERADMIN_PASSWORD` | — | `ChangeThis!` | Bootstrap super admin password |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | — | `30` | JWT access token TTL |
| `REFRESH_TOKEN_EXPIRE_DAYS` | — | `7` | JWT refresh token TTL |
| `MAGIC_LINK_TTL_SECONDS` | — | `900` | Magic link JWT TTL (15 min) |
| `MAX_CONCURRENT_SESSIONS` | — | `5` | Active sessions per user |
| `RATE_LIMIT_PER_MINUTE` | — | `10` | Max requests per IP per minute |
| `POSTGRES_POOL_SIZE` | — | `20` | SQLAlchemy connection pool size |
| `EMAIL_PROVIDER` | — | `sendgrid` | Email provider |
| `EMAIL_PROVIDER_API_KEY` | — | `""` | Email provider API key |
| `EMAIL_SENDER` | — | `noreply@authengine.com` | From address for all emails |
| `GOOGLE_CLIENT_ID` | — | `""` | Leave empty to disable Google OAuth |
| `GOOGLE_CLIENT_SECRET` | — | `""` | |
| `GITHUB_CLIENT_ID` | — | `""` | Leave empty to disable GitHub OAuth |
| `GITHUB_CLIENT_SECRET` | — | `""` | |
| `MICROSOFT_CLIENT_ID` | — | `""` | Leave empty to disable Microsoft OAuth |
| `MICROSOFT_CLIENT_SECRET` | — | `""` | |

---

## Infrastructure Setup

### Docker Compose (Full Stack)

```bash
docker compose up -d
docker compose exec app auth-engine migrate
```

All services start with health checks. The app waits for PostgreSQL, MongoDB, and Redis to be healthy before accepting requests.

### Manual (Individual Containers)

```bash
# PostgreSQL
docker run -d --name authengine-postgres -p 5432:5432 \
  -e POSTGRES_USER=authengine \
  -e POSTGRES_PASSWORD=strongpassword \
  -e POSTGRES_DB=authengine \
  -v authengine_pg_data:/var/lib/postgresql/data \
  postgres:16

# MongoDB
docker run -d --name authengine-mongo -p 27017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=admin \
  -e MONGO_INITDB_ROOT_PASSWORD=strongpassword \
  -v authengine_mongo_data:/data/db \
  mongo:latest

# Redis
docker run -d --name authengine-redis -p 6379:6379 \
  -v authengine_redis_data:/data \
  redis:7-alpine
```

---

## Extension Guide

### Adding an OAuth Provider

1. Add authorization, token, and userinfo URLs to `auth_strategies/constants.py`
2. Create `auth_strategies/oauth/yourprovider.py` — subclass `BaseOAuthStrategy`, implement `normalize_profile(raw)`
3. Register in `auth_strategies/oauth/factory.py`
4. Add config fields to `core/config.py` and `.env.example`

### Adding a New Auth Strategy

1. Subclass `TokenBasedStrategy` or `PasswordBasedStrategy` from `auth_strategies/base.py`
2. Implement `authenticate(credentials)` and `validate(token)`
3. Add the strategy name to the `AuthStrategy` enum in `schemas/user.py`
4. Wire up endpoints in `api/v1/public/`