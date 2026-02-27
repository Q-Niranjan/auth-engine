# AuthEngine — Technical Reference

Deep architecture documentation for developers working on or integrating with AuthEngine.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Project Structure](#project-structure)
3. [Authentication Strategies](#authentication-strategies)
4. [Authorization Model (PBAC)](#authorization-model-pbac)
5. [Multi-Tenancy Design](#multi-tenancy-design)
6. [Data Models](#data-models)
7. [OAuth 2.0 Social Login](#oauth-20-social-login)
8. [Token Introspection](#token-introspection)
9. [Service API Keys](#service-api-keys)
10. [Session Management](#session-management)
11. [Database Layer](#database-layer)
12. [Configuration Reference](#configuration-reference)
13. [Infrastructure Setup](#infrastructure-setup)
14. [Extension Guide](#extension-guide)

---

## Architecture Overview

AuthEngine is built around three core principles:

**Strategy Pattern for Auth** — every authentication method is an isolated class implementing a common interface. Adding a new provider never touches existing code.

**PBAC with Level Hierarchy** — authorization is permission-based, not role-name-based. Roles are containers of permissions. The system checks permissions, not role names. A numeric level hierarchy prevents privilege escalation.

**Repository Pattern** — all DB access goes through typed repositories. Services never touch the ORM directly, keeping business logic testable and clean.

```
HTTP Request
    ↓
FastAPI Router
    ↓
Dependency Injection (JWT auth, DB session, Redis, API key validation)
    ↓
Service Layer  (business logic — auth, oauth, introspect, roles, tenants...)
    ↓
Repository Layer  (data access — PostgreSQL, MongoDB, Redis)
    ↓
Databases
```

---

## Project Structure

```
auth-engine/
├── alembic/
│   └── versions/
│       ├── 0001_initial.py              # users, roles, permissions, tenants
│       ├── 0002_oauth_accounts.py       # oauth_accounts table
│       └── 0003_service_api_keys.py     # service_api_keys table
├── src/
│   └── auth_engine/
│       ├── api/
│       │   ├── dependencies/
│       │   │   ├── auth_deps.py         # get_current_user, get_current_active_user
│       │   │   ├── deps.py              # get_db, get_audit_service
│       │   │   └── rbac.py              # require_permission, check_platform_permission
│       │   └── v1/
│       │       ├── me/
│       │       │   └── endpoints.py     # /me, /me/tenants, /me/tenants/{id}/permissions
│       │       ├── public/
│       │       │   ├── auth.py          # register, login, logout, refresh, verify, reset
│       │       │   ├── oauth.py         # OAuth login/callback/link/accounts
│       │       │   └── introspect.py    # POST /auth/introspect
│       │       ├── platform/
│       │       │   ├── tenant.py        # CRUD tenants
│       │       │   ├── user.py          # platform user management
│       │       │   ├── roles.py         # platform role assignment
│       │       │   ├── audit.py         # platform audit logs
│       │       │   └── service_keys.py  # CRUD service API keys
│       │       ├── tenants/
│       │       │   ├── users.py         # tenant user management + invites
│       │       │   ├── roles.py         # tenant role assignment
│       │       │   └── audit.py         # tenant audit logs
│       │       ├── system/
│       │       │   └── system.py        # /health
│       │       └── router.py            # central router wiring
│       ├── auth_strategies/
│       │   ├── base.py                  # BaseAuthStrategy, TokenBasedStrategy, PasswordBasedStrategy
│       │   ├── email_password.py        # email + password strategy
│       │   └── oauth/
│       │       ├── base_oauth.py        # BaseOAuthStrategy (TokenBasedStrategy subclass)
│       │       ├── google.py            # Google provider
│       │       ├── github.py            # GitHub provider (handles private emails)
│       │       ├── microsoft.py         # Microsoft provider (personal + Azure AD)
│       │       └── factory.py           # get_oauth_strategy("google") factory function
│       ├── core/
│       │   ├── config.py                # Pydantic Settings — all env vars typed
│       │   ├── exceptions.py            # AuthenticationError, InvalidCredentialsError, etc.
│       │   ├── health.py                # Postgres + MongoDB + Redis health checks
│       │   ├── mongodb.py               # Motor async client setup
│       │   ├── postgres.py              # SQLAlchemy async engine + session factory
│       │   ├── rbac_seed.py             # default roles/permissions bootstrap on startup
│       │   ├── redis.py                 # Redis async client setup
│       │   └── security.py             # SecurityUtils (Argon2 hashing), TokenManager (JWT)
│       ├── models/
│       │   ├── email_config.py          # TenantEmailConfigORM
│       │   ├── oauth_account.py         # OAuthAccountORM — links user to social provider
│       │   ├── permission.py            # PermissionORM
│       │   ├── role.py                  # RoleORM (name, scope, level)
│       │   ├── role_permission.py       # RolePermissionORM (join table)
│       │   ├── service_api_key.py       # ServiceApiKeyORM — for introspect callers
│       │   ├── tenant.py                # TenantORM
│       │   ├── user.py                  # UserORM (all Mapped columns)
│       │   └── user_role.py             # UserRoleORM (user ↔ role ↔ tenant join)
│       ├── repositories/
│       │   ├── mongo_repo.py            # MongoDB base (audit logs)
│       │   ├── oauth_repo.py            # OAuthAccountRepository
│       │   ├── postgres_repo.py         # Generic async SQLAlchemy CRUD
│       │   ├── redis_repo.py            # Redis key/value helpers
│       │   ├── service_api_key_repo.py  # ServiceApiKeyRepository
│       │   └── user_repo.py             # UserRepository (extended queries)
│       ├── schemas/
│       │   ├── introspect.py            # IntrospectRequest, IntrospectResponse
│       │   ├── oauth.py                 # OAuth schemas
│       │   ├── rbac.py                  # Role/permission schemas
│       │   ├── tenant.py                # Tenant schemas
│       │   └── user.py                  # User schemas
│       ├── services/
│       │   ├── audit_service.py         # MongoDB audit log writer
│       │   ├── auth_service.py          # register, login, verify, reset password
│       │   ├── introspect_service.py    # 6-step token validation
│       │   ├── oauth_service.py         # state/CSRF, find-or-create user
│       │   ├── permission_service.py    # has_permission() check logic
│       │   ├── role_service.py          # role assignment/removal with level check
│       │   ├── session_service.py       # Redis session CRUD, blacklist
│       │   ├── tenant_service.py        # tenant CRUD, user invites
│       │   └── user_service.py          # user status, deletion
│       └── main.py                      # FastAPI app factory, lifespan events
└── tests/
```

---

## Authentication Strategies

All strategies inherit from `BaseAuthStrategy` in `auth_strategies/base.py`:

```python
class BaseAuthStrategy(ABC):
    async def authenticate(self, credentials: dict) -> dict: ...  # required
    async def validate(self, token: str) -> dict: ...             # required
    async def prepare_credentials(self, raw: dict) -> dict: ...   # optional hook
    async def post_authenticate(self, user_data: dict) -> dict:   # optional hook
```

Two abstract base variants exist:

- `PasswordBasedStrategy` — for email/password. `requires_password()` returns `True`.
- `TokenBasedStrategy` — for OAuth, magic links, WebAuthn. `requires_password()` returns `False`.

### Email/Password Strategy

`EmailPasswordStrategy(PasswordBasedStrategy)` — validates credentials against an Argon2 hash, enforces account status check, issues JWTs via `TokenManager`.

### OAuth Strategies

`BaseOAuthStrategy(TokenBasedStrategy)` defines a three-step flow:

1. `get_authorization_url(state)` — builds the provider's redirect URL with CSRF state
2. `exchange_code_for_tokens(code)` — server-side authorization code exchange
3. `fetch_user_profile(access_token)` — calls provider userinfo endpoint

Each provider subclass only overrides `normalize_profile(raw)` to map its field names to a common format: `{provider_user_id, email, first_name, last_name, avatar_url, provider_name}`.

**GitHub special handling:** GitHub users can set their email to private. `GitHubOAuthStrategy.fetch_user_profile()` makes a second call to `GET /user/emails` to find the primary verified email when the main profile returns null.

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

### How Guards Work

Guards check if the actor **has the permission**, regardless of which role it came from. Role names are irrelevant to the check:

```python
# Endpoint uses permission string, never a role name
@require_permission("tenant.users.manage")
async def invite_user(...): ...

@check_platform_permission("platform.tenants.manage")
async def create_tenant(...): ...
```

### Level Hierarchy

Every role has a numeric level (0–100). An actor can only assign or remove roles with a **strictly lower** level than their own maximum:

```
SUPER_ADMIN    100  →  can act on levels 0–99
PLATFORM_ADMIN  80  →  can act on levels 0–79
TENANT_OWNER    60  →  can act on levels 0–59
TENANT_ADMIN    50  →  can act on levels 0–49
TENANT_MANAGER  30  →  can act on levels 0–29
TENANT_USER     10  →  can act on levels 0–9
```

This prevents lateral attacks: a `TENANT_ADMIN` cannot assign or remove another `TENANT_ADMIN`.

### Scoped Context

`require_permission` extracts `tenant_id` from URL path params automatically. If `tenant_id` is in the path, the permission check is scoped to that tenant. Platform routes have no `tenant_id`, so they check global permissions.

`PLATFORM_ADMIN` and `SUPER_ADMIN` have global scope — their permissions apply in all tenant contexts automatically.

---

## Multi-Tenancy Design

A `TenantORM` represents an isolated organization. The link between users and tenants is `UserRoleORM` — a three-way join: `(user_id, role_id, tenant_id)`.

```
UserORM  ←──────  UserRoleORM  ──────►  RoleORM
                       │
                       ▼
                  TenantORM
```

One user can have multiple `UserRoleORM` rows — one for each (role, tenant) pair. `TENANT_USER` in YourComapny and `TENANT_ADMIN` in ServiceA are both valid simultaneously for the same user.

All tenant-scoped endpoints include `tenant_id` in the URL path, and all permission checks are evaluated within that specific tenant context.

---

## Data Models

All models use SQLAlchemy 2.0 `Mapped` + `mapped_column` throughout — no legacy `Column()` style.

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
auth_strategies       : list[str] (JSON) ← ["email_password", "google", "github"]
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
provider_user_id    : str              ← unique ID on the provider side
access_token        : str | None       ← refreshed on every login
refresh_token       : str | None
token_expires_at    : datetime | None
provider_email      : str | None       ← snapshot at last login
provider_avatar_url : str | None
provider_name       : str | None
created_at          : datetime
updated_at          : datetime

UNIQUE (provider, provider_user_id)
```

### ServiceApiKeyORM

```
id            : UUID (PK)
service_name  : str              ← "YourComapny", "ServiceA", etc.
key_hash      : str (unique)     ← SHA-256 of the raw key, never plaintext
key_prefix    : str              ← "ae_sk_a1b2c3..." safe to display in UI
tenant_id     : UUID | None (FK) ← if set, key can only see this tenant's data
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
name        : str (unique)   ← "SUPER_ADMIN", "TENANT_ADMIN", etc.
description : str | None
scope       : RoleScope      ← PLATFORM | TENANT
level       : int            ← 0–100
```

---

## OAuth 2.0 Social Login

### Full Flow

```
1. Frontend:   GET /api/v1/auth/oauth/google/login?tenant_id=<uuid>
2. AuthEngine: generate state → store in Redis (TTL 10 min) → build Google URL
3. AuthEngine: 302 redirect → Google login page
4. User:       logs in on Google, approves consent
5. Google:     302 redirect → /api/v1/auth/oauth/google/callback?code=...&state=...
6. AuthEngine: validate state (consume from Redis — one-time use)
7. AuthEngine: exchange code → provider access token
8. AuthEngine: call provider userinfo → normalize profile
9. AuthEngine: find-or-create user + upsert oauth_account row
10. AuthEngine: issue AuthEngine JWT → return to frontend
```

### CSRF State Protection

State tokens are 32-byte random URL-safe strings (`secrets.token_urlsafe(32)`). Stored in Redis under key `oauth:state:{token}` with 10-minute TTL. The callback **deletes** the key on first use — replay attacks with the same state are rejected.

Optional tenant context is encoded in the state value stored in Redis.

### User Identity Resolution (`find_or_create_user`)

Three cases handled in priority order:

**Case 1 — Known OAuth account:** `oauth_accounts` row exists for `(provider, provider_user_id)` → update provider tokens, return existing user. No DB write to users table.

**Case 2 — Known email, new provider:** User exists by email but hasn't linked this provider yet → create `oauth_accounts` row, append strategy name to `auth_strategies` JSON list, return existing user. This automatically merges accounts for users who registered with email/password then later clicked "Login with Google" using the same address.

**Case 3 — Brand new user:** No user, no OAuth account → create `UserORM` (status=ACTIVE, is_email_verified=True — email is already verified by the provider), create `oauth_accounts` row.
<truncated 57 bytes>
### Password Transition for Social Users

OAuth-only users do not have a `password_hash`. 

1. **Forgot Password:** If a social user attempts a password reset, the system rejects it with a specific message directing them to their social provider.
2. **Set Password:** Authenticated OAuth users can call `POST /auth/set-password` to establish their first password. This appends `email_password` to their `auth_strategies`, allowing them to login via both social and email/password methods in the future.

---

## Token Introspection

### Purpose

External services (YourComapny, ServiceA, etc.) call `/auth/introspect` to validate a user's JWT without holding the JWT secret. This centralizes revocation — when a session is deleted from Redis, the next introspect call instantly returns `active: false`.

### The 6 Validation Steps

`IntrospectService.introspect()` runs these checks in order, returning `active: false` at the first failure — never raising exceptions:

```
Step 1  JWT decode       — verify signature + expiry (python-jose)
Step 2  Blacklist check  — check Redis for blacklist:{jti} (explicit logout)
Step 3  Session check    — check Redis for session:{user_id}:{session_id}
Step 4  User load        — fetch from PostgreSQL, must exist
Step 5  Status check     — user.status must be ACTIVE
Step 6  Permissions      — collect from user.roles, scoped to requested tenant_id
```

### Request / Response

```
POST /api/v1/auth/introspect
X-API-Key: ae_sk_...
Content-Type: application/json

{
  "token": "<user access token>",
  "tenant_id": "<optional — scope permissions to this tenant>"
}
```

**Active token response:**
```json
{
  "active": true,
  "user_id": "550e8400-...",
  "email": "john@YourComapny.com",
  "first_name": "John",
  "last_name": "Doe",
  "avatar_url": "https://...",
  "is_email_verified": true,
  "auth_strategy": "google",
  "issued_at": "2026-02-19T10:00:00Z",
  "expires_at": "2026-02-19T10:30:00Z",
  "permissions": ["tenant.view", "tenant.users.view"],
  "tenant_ids": ["YourComapny-uuid"]
}
```

**Inactive/invalid token response:**
```json
{ "active": false }
```

---

## Service API Keys

### Why

Without API key authentication on the introspect endpoint, any party with a valid user JWT could probe user identity and permissions. The `X-API-Key` header ensures only registered services can call introspect.

### Key Security Design

- Raw keys are **never stored** — only the SHA-256 hash is persisted in the DB
- The raw key is shown exactly once in the `POST /platform/service-keys` response
- Even a full DB dump cannot recover raw keys
- Keys can be **tenant-scoped** — a key with `tenant_id=your_comapany` can only return data scoped to YourCompany, regardless of what `tenant_id` the caller sends in the request body
- Keys can have an `expires_at` for time-limited integrations
- Revoking a key (`DELETE /platform/service-keys/{id}`) takes effect on the next request — no propagation delay

### Key Format

`ae_sk_{64 hex chars}` — e.g. `ae_sk_a1b2c3d4e5f6...`

The first 12 characters are stored as `key_prefix` for display in the platform UI.

---

## Session Management

Sessions are stored in Redis as JSON under key `session:{user_id}:{session_id}`.

Each session contains: `session_id`, `user_id`, `ip_address`, `user_agent`, `created_at`, `expires_at`.

The refresh token JWT contains a `sid` (session ID) claim. On token refresh, the session is verified in Redis before new tokens are issued. On logout, the session key is deleted immediately.

`MAX_CONCURRENT_SESSIONS` (default: 5) limits active sessions per user. When the limit is hit, the oldest session is evicted.

Token blacklisting is handled via `blacklist:{jti}` keys in Redis — used when a specific token (not the whole session) needs to be invalidated.

---

## Database Layer

### PostgreSQL (Primary)

All relational data: users, roles, permissions, tenants, oauth_accounts, service_api_keys, email_configs.

Connection: async SQLAlchemy 2.0 with `asyncpg` driver. Pool configured via `POSTGRES_POOL_SIZE` (default 20) and `POSTGRES_MAX_OVERFLOW` (default 10).

Migrations: Alembic. Run with `auth-engine migrate`.

### MongoDB (Audit Logs)

Exclusively for audit logs. Chosen because audit records are append-only, schema-flexible, and the document model handles arbitrary `metadata` payloads cleanly.

Collection: `audit_logs`. Document fields: `action`, `resource`, `resource_id`, `actor_id`, `tenant_id`, `metadata`, `timestamp`, `ip_address`, `user_agent`.

### Redis (Cache + Sessions)

Used for:

| Key pattern | TTL | Purpose |
|---|---|---|
| `session:{user_id}:{session_id}` | Session lifetime | Active login sessions |
| `oauth:state:{token}` | 10 min | CSRF protection for OAuth flows |
| `blacklist:{jti}` | Token remaining lifetime | Explicitly invalidated tokens |
| `ratelimit:{ip}:{minute}` | 60 sec | Rate limiting counters |
| `otp:phone:{user_id}` | 10 min | Phone verification OTPs |

**Local development:** no password — `REDIS_URL=redis://localhost:6379`

**Production:** `redis://:password@host:6379` or `rediss://` for TLS

---

## Configuration Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECRET_KEY` | Yes | — | App secret key, min 32 chars |
| `JWT_SECRET_KEY` | Yes | — | JWT signing key, min 32 chars |
| `POSTGRES_URL` | Yes | — | `postgresql+asyncpg://<user>:<pass>@host/db` |
| `MONGODB_URL` | Yes | — | `mongodb://<user>:<pass>@host:27017` |
| `REDIS_URL` | Yes | — | `redis://localhost:6379` (no password locally) |
| `SUPERADMIN_EMAIL` | — | `<admin@authengine.com>` | Bootstrap super admin email |
| `SUPERADMIN_PASSWORD` | — | `<ChangeThis!>` | Bootstrap super admin password |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | — | `30` | JWT access token TTL |
| `REFRESH_TOKEN_EXPIRE_DAYS` | — | `7` | JWT refresh token TTL |
| `RATE_LIMIT_PER_MINUTE` | — | `10` | Max requests per IP per minute |
| `MAX_CONCURRENT_SESSIONS` | — | `5` | Max active sessions per user |
| `POSTGRES_POOL_SIZE` | — | `20` | SQLAlchemy connection pool size |
| `GOOGLE_CLIENT_ID` | — | `""` | Leave empty to disable Google OAuth |
| `GOOGLE_CLIENT_SECRET` | — | `""` | |
| `GOOGLE_REDIRECT_URI` | — | localhost callback | |
| `SMS_PROVIDER` | — | `"twilio"` | |
| `SMS_PROVIDER_API_KEY` | — | `""` | |
| `SMS_PROVIDER_ACCOUNT_SID`| — | `""` | |
| `SMS_SENDER` | — | `"+1234567890"` | |
| `GITHUB_CLIENT_ID` | — | `""` | Leave empty to disable GitHub OAuth |
| `GITHUB_CLIENT_SECRET` | — | `""` | |
| `MICROSOFT_CLIENT_ID` | — | `""` | Leave empty to disable Microsoft OAuth |
| `MICROSOFT_CLIENT_SECRET` | — | `""` | |

---

## Infrastructure Setup

### Local Development (Individual Docker Containers)

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

# MongoDB — requires credentials even locally
docker run -d \
  --name authengine-mongo \
  -p 27017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=admin \
  -e MONGO_INITDB_ROOT_PASSWORD=strongpassword \
  -v authengine_mongo_data:/data/db \
  --restart unless-stopped \
  mongo:latest

# Redis — no password for local dev
docker run -d \
  --name authengine-redis \
  -p 6379:6379 \
  -v authengine_redis_data:/data \
  --restart unless-stopped \
  redis:7-alpine
```

Corresponding `.env` values:

```env
POSTGRES_URL=postgresql+asyncpg://<authengine>:<strongpassword>@localhost:5432/authengine
MONGODB_URL=mongodb://<admin>:<strongpassword>@localhost:27017
REDIS_URL=redis://localhost:6379
```

### Full Stack with Docker Compose

```bash
docker compose up -d
docker compose exec app auth-engine migrate
```

All services (app + postgres + mongo + redis) start with health checks. The app waits for all three databases to be ready before starting.

---

## Extension Guide

1. Add provider identifier and URLs to `src/auth_engine/auth_strategies/constants.py`:

```python
YOU_AUTHORIZATION_URL = "..."
YOU_TOKEN_URL = "..."
YOU_USERINFO_URL = "..."
```

2. Create `src/auth_engine/auth_strategies/oauth/yourprovider.py`:

```python
from auth_engine.auth_strategies.oauth.base_oauth import BaseOAuthStrategy
from auth_engine.auth_strategies.constants import (
    YOU_AUTHORIZATION_URL, YOU_TOKEN_URL, YOU_USERINFO_URL
)

class YourProviderStrategy(BaseOAuthStrategy):
    AUTHORIZATION_URL = YOU_AUTHORIZATION_URL
    TOKEN_URL = YOU_TOKEN_URL
    USERINFO_URL = YOU_USERINFO_URL
    DEFAULT_SCOPES = ["read:user", "email"]

    def __init__(self, client_id, client_secret, redirect_uri):
        super().__init__("yourprovider", client_id, client_secret, redirect_uri)

    def normalize_profile(self, raw_profile: dict) -> dict:
        return {
            "provider_user_id": str(raw_profile["id"]),
            "email": raw_profile["email"],
            "first_name": raw_profile.get("first_name"),
            "last_name": raw_profile.get("last_name"),
            "avatar_url": raw_profile.get("avatar"),
            "provider_name": raw_profile.get("name"),
        }
```

3. Register in `factory.py`:

```python
if provider == "yourprovider":
    return YourProviderStrategy(
        client_id=settings.YOURPROVIDER_CLIENT_ID,
        client_secret=settings.YOURPROVIDER_CLIENT_SECRET,
        redirect_uri=settings.YOURPROVIDER_REDIRECT_URI,
    )
```

4. Add config fields to `core/config.py` and `.env.example`.

### Adding a New Auth Strategy

1. Subclass `TokenBasedStrategy` or `PasswordBasedStrategy` from `auth_strategies/base.py`
2. Implement `authenticate(credentials)` and `validate(token)`
3. Add the strategy name to `AuthStrategy` enum in `schemas/user.py`
4. Wire up new endpoints in `api/v1/public/`

---

## Technology Stack

| Layer | Technology | Reason |
|-------|-----------|--------|
| Framework | FastAPI | Async-native, automatic OpenAPI docs, DI system |
| ORM | SQLAlchemy 2.0 async | Typed `Mapped` columns, async support, mature |
| Primary DB | PostgreSQL + asyncpg | ACID, relational integrity, fast async driver |
| Audit DB | MongoDB + Motor | Schema-flexible documents, append-only, async |
| Cache | Redis async | Sub-millisecond session lookups, atomic ops |
| Migrations | Alembic | Integrates with SQLAlchemy, battle-tested |
| OAuth Client | Authlib | RFC-compliant OAuth 2.0 / OIDC async client |
| Password Hash | Argon2 (argon2-cffi) | Memory-hard, GPU-resistant, OWASP recommended |
| JWT | python-jose | HS256/RS256, standard claims, well maintained |
| Config | Pydantic Settings | Typed env vars, validated at startup |
| Package Mgr | uv | Fast, reproducible, modern Python packaging |
