# AuthEngine — Technical Reference

← **[Back to README](README.md)**

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Project Structure](#project-structure)
3. [Authentication Strategies](#authentication-strategies)
4. [Magic Links](#magic-links)
5. [TOTP / MFA](#totp--mfa)
6. [Authorization Model (PBAC)](#authorization-model-pbac)
7. [Multi-Tenancy Design](#multi-tenancy-design)
8. [Data Models](#data-models)
9. [Token Introspection](#token-introspection)
10. [Service API Keys](#service-api-keys)
11. [Session Management](#session-management)
12. [Database Layer](#database-layer)
13. [Configuration Reference](#configuration-reference)
14. [Infrastructure Setup](#infrastructure-setup)
15. [Extension Guide](#extension-guide)

---

## Architecture Overview

Three core principles drive every design decision:

**Strategy Pattern for Auth** — every authentication method is an isolated class implementing `BaseAuthStrategy`. Adding a new method never touches existing code.

**PBAC with Level Hierarchy** — authorization checks permissions, not role names. Roles are containers of permissions. A numeric level (0–100) prevents privilege escalation — a role can only assign roles with a strictly lower level than its own.

**Repository Pattern** — all DB access goes through typed repositories. Services never import ORM models directly, keeping business logic testable and clean.

```
HTTP Request
    ↓
FastAPI Router
    ↓
Dependency Injection  (JWT auth, DB session, Redis, API key validation)
    ↓
Service Layer         (auth, oauth, totp, magic_link, introspect, roles, tenants...)
    ↓
Repository Layer      (PostgreSQL, MongoDB, Redis)
    ↓
Databases
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
│       │       │   ├── auth.py            # register, login (MFA-aware), logout, refresh, verify, reset
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
│       │   ├── magic_link.py              # MagicLinkStrategy
│       │   ├── totp.py                    # TOTPStrategy
│       │   └── oauth/
│       │       ├── base_oauth.py
│       │       ├── google.py
│       │       ├── github.py
│       │       ├── microsoft.py
│       │       └── factory.py
│       ├── core/
│       │   ├── config.py                  # Pydantic Settings
│       │   ├── exceptions.py
│       │   ├── health.py
│       │   ├── mongodb.py
│       │   ├── postgres.py
│       │   ├── rbac_seed.py
│       │   ├── redis.py
│       │   └── security.py                # SecurityUtils (Argon2, Fernet), TokenManager (JWT)
│       ├── models/
│       │   ├── email_config.py
│       │   ├── oauth_account.py
│       │   ├── permission.py
│       │   ├── role.py
│       │   ├── role_permission.py
│       │   ├── service_api_key.py
│       │   ├── tenant.py
│       │   ├── user.py                    # includes mfa_enabled, mfa_secret
│       │   └── user_role.py
│       ├── repositories/
│       │   ├── mongo_repo.py
│       │   ├── oauth_repo.py
│       │   ├── postgres_repo.py           # Generic async SQLAlchemy CRUD
│       │   ├── redis_repo.py
│       │   ├── service_api_key_repo.py
│       │   └── user_repo.py
│       ├── schemas/
│       │   ├── introspect.py
│       │   ├── mfa.py                     # MFAEnrollResponse, MFAChallengeResponse, etc.
│       │   ├── magic_link.py              # MagicLinkRequest, MagicLinkVerifyResponse
│       │   ├── oauth.py
│       │   ├── rbac.py
│       │   ├── tenant.py
│       │   └── user.py
│       ├── services/
│       │   ├── audit_service.py
│       │   ├── auth_service.py
│       │   ├── introspect_service.py
│       │   ├── magic_link_service.py      # request + verify lifecycle
│       │   ├── oauth_service.py
│       │   ├── permission_service.py
│       │   ├── role_service.py
│       │   ├── session_service.py
│       │   ├── tenant_service.py
│       │   ├── totp_service.py            # enrollment + MFA completion
│       │   └── user_service.py
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

- `PasswordBasedStrategy` — email/password. `requires_password()` → `True`.
- `TokenBasedStrategy` — OAuth, magic links, TOTP. `requires_password()` → `False`.

### Email/Password Strategy

`EmailPasswordStrategy(PasswordBasedStrategy)` — validates against an Argon2 hash, checks account status, issues JWTs via `TokenManager`.

### OAuth Strategies

`BaseOAuthStrategy(TokenBasedStrategy)` defines a three-step flow:

1. `get_authorization_url(state)` — builds the provider redirect URL with CSRF state stored in Redis
2. `exchange_code_for_tokens(code)` — server-side authorization code exchange
3. `fetch_user_profile(access_token)` — calls provider userinfo endpoint

Each provider subclass overrides only `normalize_profile(raw)` to map provider fields to a common format: `{provider_user_id, email, first_name, last_name, avatar_url, provider_name}`.

**GitHub special case:** GitHub emails can be private. `GitHubOAuthStrategy` makes a second call to `GET /user/emails` to find the primary verified address when the main profile returns null.

**Set Password:** OAuth-only users can call `POST /auth/set-password` to establish a password. This appends `email_password` to their `auth_strategies`, enabling both login methods going forward.

---

## Magic Links

Passwordless login via a signed, short-lived, single-use URL.

### Flow

```
POST /auth/magic-link/request  { email }
  1. Look up user — silently return if not found (prevents enumeration)
  2. MagicLinkStrategy.generate_token()  →  JWT (type=magic_link, jti=uuid4, TTL=15 min)
  3. redis.setex("magic:jti:{jti}", 900, "pending")   ← written BEFORE email is sent
  4. Send email with link: /auth/magic-link/verify?token=<jwt>
     If email fails → redis.delete(key)  (rollback so token can't be replayed)

GET /auth/magic-link/verify?token=<jwt>
  1. Decode + verify JWT signature and exp
  2. Assert payload.type == "magic_link"
  3. redis.get("magic:jti:{jti}")  →  must be "pending" (not expired or already used)
  4. redis.delete(key)  →  returns 0 if race condition → 401
  5. user_repo.get_by_email(email)
  6. create_session() + create_tokens()  →  return access + refresh tokens
```

### Security Properties

| Property | Mechanism |
|----------|-----------|
| Signed | HS256 JWT via `JWT_SECRET_KEY` |
| Short TTL | 15 min (`exp` claim) |
| One-time use | Redis flag consumed on first click |
| Race-safe | `redis.delete()` returns count; 0 = already consumed → 401 |
| Enumeration-safe | `/request` always returns 202 |
| Rollback on failure | Flag deleted if email dispatch fails |

### Redis Key

| Key | TTL | Value |
|-----|-----|-------|
| `magic:jti:{jti}` | 900s | `"pending"` |

---

## TOTP / MFA

Time-based One-Time Password second factor using the `pyotp` library.

### Enrollment Flow

```
POST /me/mfa/enroll
  1. Generate raw TOTP secret via pyotp.random_base32()
  2. Encrypt with Fernet(SECRET_KEY) → store in users.mfa_secret
  3. Return provisioning_uri (for QR code) + raw secret
     users.mfa_enabled stays False until confirmed

POST /me/mfa/verify  { code: "123456" }
  1. Decrypt mfa_secret → verify code with pyotp (valid_window=1)
  2. Set users.mfa_enabled = True
```

### Login Flow with MFA Enabled

```
POST /auth/login  { email, password }
  → primary auth succeeds
  → user.mfa_enabled == True
       store  mfa:pending:{user_id}  in Redis (5 min TTL)
       return 202 { mfa_pending_token, message }   ← NOT a real session

POST /auth/mfa/complete  { mfa_pending_token, code }
  1. Decode mfa_pending_token (type=mfa_pending, not expired)
  2. redis.get("mfa:pending:{user_id}") → must exist
  3. redis.delete(key)  ← one-time, prevents replay
  4. Verify TOTP code against stored secret
  5. create_session() + create_tokens()
  6. return 200 { access_token, refresh_token, ... }
```

### Login Flow without MFA

```
POST /auth/login  →  200  { access_token, refresh_token, ... }
```

The login endpoint returns `Union[UserLoginResponse, MFAChallengeResponse]`:
- **200** — MFA not enabled, full tokens returned immediately
- **202** — MFA enabled, challenge token returned, second step required
- **401** — bad credentials

### Secret Storage

TOTP secrets are encrypted at rest using `SecurityUtils.encrypt_data()` (Fernet keyed from `SECRET_KEY`). The raw secret is never persisted — only the Fernet ciphertext in `users.mfa_secret`.

### Redis Key

| Key | TTL | Value |
|-----|-----|-------|
| `mfa:pending:{user_id}` | 300s | JSON session context |

### Management Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /me/mfa/status` | Check if MFA is enabled |
| `POST /me/mfa/enroll` | Begin setup — returns QR URI + raw secret |
| `POST /me/mfa/verify` | Confirm first code → activates MFA |
| `DELETE /me/mfa/disable` | Disable MFA (requires valid TOTP code) |

---

## Authorization Model (PBAC)

### Permissions

Permissions use dot notation: `resource.subresource.action`

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

`require_permission("permission.name")` — checks if the current user has the permission across any of their roles. `check_platform_permission("permission.name")` — same but scoped to platform-level roles only.

---

## Multi-Tenancy Design

```
UserORM  ←──────  UserRoleORM  ──────►  RoleORM
                       │
                       ▼
                  TenantORM
```

One user can have multiple `UserRoleORM` rows — one per (role, tenant) pair. `TENANT_USER` in OrgA and `TENANT_ADMIN` in OrgB are valid simultaneously for the same user. All tenant-scoped endpoints include `tenant_id` in the URL path, and all permission checks are evaluated within that specific tenant context.

---

## Data Models

All models use SQLAlchemy 2.0 `Mapped` + `mapped_column`.

### UserORM

```
id                    : UUID (PK)
email                 : str  (unique, indexed)
username              : str | None  (unique)
phone_number          : str | None  (unique)
password_hash         : str | None       ← null for OAuth-only users
first_name            : str | None
last_name             : str | None
avatar_url            : str | None
status                : UserStatus       ← ACTIVE | INACTIVE | SUSPENDED | PENDING_VERIFICATION
is_email_verified     : bool
is_phone_verified     : bool
mfa_enabled           : bool             ← default False
mfa_secret            : str | None       ← Fernet-encrypted TOTP secret
auth_strategies       : list[str] (JSON) ← ["email_password", "google", "magic_link"]
failed_login_attempts : int
last_login_at         : datetime | None
last_login_ip         : str | None
password_changed_at   : datetime | None
created_at            : datetime
updated_at            : datetime
deleted_at            : datetime | None  ← soft delete
```

### OAuthAccountORM

```
id                  : UUID (PK)
user_id             : UUID (FK → users.id, CASCADE DELETE)
provider            : str              ← "google" | "github" | "microsoft"
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
key_hash      : str (unique)     ← SHA-256 of raw key, never plaintext
key_prefix    : str              ← "ae_sk_a1b2c3..." safe to display in UI
tenant_id     : UUID | None (FK)
is_active     : bool
created_by    : UUID | None (FK → users.id)
last_used_at  : datetime | None
expires_at    : datetime | None
created_at    : datetime
updated_at    : datetime
```

### UserRoleORM (composite PK)

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
scope       : RoleScope  ← PLATFORM | TENANT
level       : int        ← 0–100, prevents privilege escalation
created_at  : datetime
```

---

## Token Introspection

External services call `/auth/introspect` to validate a user JWT without holding the JWT secret. Revocation is instant — deleting a Redis session immediately returns `active: false` on the next introspect call.

### 6-Step Validation

`IntrospectService.introspect()` runs these in order, returning `active: false` at the first failure:

```
1. JWT decode        — verify signature + expiry (python-jose)
2. Blacklist check   — redis.exists("blacklist:{jti}")
3. Session check     — redis.exists("session:{user_id}:{session_id}")
4. User load         — fetch from PostgreSQL, must exist
5. Status check      — user.status must be ACTIVE
6. Permissions       — collect from user.roles, scoped to requested tenant_id
```

### Usage

```
POST /api/v1/auth/introspect
X-API-Key: ae_sk_...

{ "token": "<access_token>", "tenant_id": "<optional>" }
```

Response when active:
```json
{
  "active": true,
  "user_id": "...",
  "email": "user@example.com",
  "permissions": ["tenant.view", "tenant.users.view"],
  "tenant_ids": ["..."],
  "auth_strategy": "google",
  "issued_at": "...",
  "expires_at": "..."
}
```

---

## Service API Keys

### Security Design

- Raw keys are **never stored** — only the SHA-256 hash is persisted
- Raw key shown exactly once in the create response
- Keys can be **tenant-scoped** — a key bound to a specific tenant cannot access data for other tenants regardless of what the caller sends
- Keys can have `expires_at` for time-limited integrations
- Revocation (`DELETE /platform/service-keys/{id}`) takes effect on the next request

### Key Format

`ae_sk_{64 hex chars}` — first 12 chars stored as `key_prefix` for UI display.

---

## Session Management

Sessions stored in Redis as JSON under `session:{user_id}:{session_id}`.

Each session holds: `session_id`, `user_id`, `ip_address`, `user_agent`, `created_at`, `expires_at`.

The refresh token JWT contains a `sid` claim. On refresh, the session is verified in Redis before new tokens are issued. On logout, the session key is deleted immediately.

`MAX_CONCURRENT_SESSIONS` (default: 5) — when exceeded, the oldest session is evicted.

Token blacklisting via `blacklist:{jti}` keys — used when a specific token (not the whole session) must be invalidated.

---

## Database Layer

### PostgreSQL

All relational data: users, roles, permissions, tenants, oauth_accounts, service_api_keys, email_configs.

Async SQLAlchemy 2.0 with `asyncpg`. Pool: `POSTGRES_POOL_SIZE` (default 20), `POSTGRES_MAX_OVERFLOW` (default 10).

Migrations: Alembic — `auth-engine migrate`.

### MongoDB

Audit logs only. Append-only, schema-flexible. Collection: `audit_logs`.

Fields: `action`, `resource`, `resource_id`, `actor_id`, `tenant_id`, `metadata`, `timestamp`, `ip_address`, `user_agent`.

### Redis

| Key pattern | TTL | Purpose |
|---|---|---|
| `session:{user_id}:{session_id}` | Session lifetime | Active login sessions |
| `oauth:state:{token}` | 10 min | OAuth CSRF state |
| `blacklist:{jti}` | Token remaining lifetime | Revoked tokens |
| `ratelimit:{ip}:{minute}` | 60 sec | Rate limiting |
| `otp:phone:{user_id}` | 10 min | Phone verification OTPs |
| `magic:jti:{jti}` | 15 min | Magic link one-time flags |
| `mfa:pending:{user_id}` | 5 min | Pending MFA sessions after primary auth |

---

## Configuration Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECRET_KEY` | Yes | — | App secret key, min 32 chars (also used for Fernet encryption) |
| `JWT_SECRET_KEY` | Yes | — | JWT signing key, min 32 chars |
| `POSTGRES_URL` | Yes | — | `postgresql+asyncpg://<user>:<pass>@host/db` |
| `MONGODB_URL` | Yes | — | `mongodb://<user>:<pass>@host:27017` |
| `REDIS_URL` | Yes | — | `redis://localhost:6379` |
| `APP_URL` | — | `http://localhost:8000` | Public base URL (used in email links) |
| `APP_NAME` | — | `AuthEngine` | Shown in TOTP provisioning URIs |
| `SUPERADMIN_EMAIL` | — | `admin@authengine.com` | Bootstrap super admin |
| `SUPERADMIN_PASSWORD` | — | `ChangeThisStrongPassword123!` | Bootstrap super admin |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | — | `30` | JWT access token TTL |
| `REFRESH_TOKEN_EXPIRE_DAYS` | — | `7` | JWT refresh token TTL |
| `MAGIC_LINK_TTL_SECONDS` | — | `900` | Magic link JWT TTL (15 min) |
| `MAX_CONCURRENT_SESSIONS` | — | `5` | Active sessions per user |
| `RATE_LIMIT_PER_MINUTE` | — | `10` | Max requests per IP per minute |
| `EMAIL_PROVIDER` | — | `sendgrid` | Email provider |
| `EMAIL_PROVIDER_API_KEY` | — | `""` | Email provider API key |
| `EMAIL_SENDER` | — | `noreply@authengine.com` | From address |
| `GOOGLE_CLIENT_ID` | — | `""` | Leave empty to disable Google OAuth |
| `GITHUB_CLIENT_ID` | — | `""` | Leave empty to disable GitHub OAuth |
| `MICROSOFT_CLIENT_ID` | — | `""` | Leave empty to disable Microsoft OAuth |

---

## Infrastructure Setup

### Docker Compose (Full Stack)

```bash
docker compose up -d
docker compose exec app auth-engine migrate
```

All services start with health checks. The app waits for PostgreSQL, MongoDB, and Redis before accepting requests.

### Manual (Individual Containers)

```bash
# PostgreSQL
docker run -d --name authengine-postgres -p 5432:5432 \
  -e POSTGRES_USER=authengine -e POSTGRES_PASSWORD=strongpassword -e POSTGRES_DB=authengine \
  -v authengine_pg_data:/var/lib/postgresql/data postgres:16

# MongoDB
docker run -d --name authengine-mongo -p 27017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=admin -e MONGO_INITDB_ROOT_PASSWORD=strongpassword \
  -v authengine_mongo_data:/data/db mongo:latest

# Redis
docker run -d --name authengine-redis -p 6379:6379 \
  -v authengine_redis_data:/data redis:7-alpine
```

---

## Extension Guide

### Adding an OAuth Provider

1. Add URLs to `auth_strategies/constants.py`
2. Create `auth_strategies/oauth/yourprovider.py` subclassing `BaseOAuthStrategy`, implement `normalize_profile(raw)`
3. Register in `auth_strategies/oauth/factory.py`
4. Add config fields to `core/config.py` and `.env.example`

### Adding a New Auth Strategy

1. Subclass `TokenBasedStrategy` or `PasswordBasedStrategy`
2. Implement `authenticate(credentials)` and `validate(token)`
3. Add the strategy name to `AuthStrategy` enum in `schemas/user.py`
4. Wire up endpoints in `api/v1/public/`
