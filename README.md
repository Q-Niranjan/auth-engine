# AuthEngine - An Identity & Access Management System

A high-performance, scalable, and secure authentication platform built with FastAPI, designed to handle millions of users. This project demonstrates advanced system design patterns, secure architecture, and production-ready code suitable for modern distributed systems.

## Key Features

### Multi-Strategy Authentication
The core of AuthEngine is its extensible Strategy Pattern implementation, allowing seamless integration of various authentication methods:

- **Email/Password**: Robust implementation with Argon2 hashing offering superior resistance to GPU cracking.
- **OAuth 2.0 / OIDC**: Standardized social login (Google, GitHub, Microsoft) and enterprise SSO integration.
- **Magic Links**: Passwordless authentication flow using secure, short-lived signed URLs.
- **MFA (Multi-Factor Authentication)**: Time-based One-Time Password (TOTP) support compatible with Google Authenticator/Authy.
- **Biometric WebAuthn**: (Planned) FIDO2 support for hardware keys and biometric passkeys.

### Advanced Security Architecture
- **Permission-Based Access Control (PBAC)**: Decoupled authorization logic using granular permissions (e.g., `tenant.roles.assign`) rather than fixed role names.
- **Context-Aware Multi-Tenancy**: Built-in organizational isolation with hierarchical role management and tenant-aware guards.
- **Session & Device Management**: Redis-backed session tracking, allowing users to view active devices and revoke sessions instantly.
- **Rate Limiting**: Distributed rate limiting using Redis to prevent DDoS and brute-force attacks.
- **Auto-Bootstrap**: Automatic seeding of Roles, Permissions, and a `SUPER_ADMIN` user on first application startup.

### Technical Excellence
- **Async First**: Fully asynchronous I/O using `asyncio` for high throughput.
- **Database sharding ready**: Modular repository pattern supporting horizontal scaling.
- **Type Safety**: Strict type checking with Pydantic v2 and Mypy.
- **12-Factor App**: Fully configurable via environment variables.

## Project Structure

```text
auth-engine/
├── alembic/             # Database migrations
├── src/
│   └── auth_engine/
│       ├── api/
│       │   ├── dependencies/    # Dependency Injection (Auth, RBAC, DB)
│       │   └── v1/             # API v1 Routes
│       │       ├── me/         # User Context Endpoints (/me)
│       │       ├── public/     # Public Auth Endpoints (/auth)
│       │       ├── platform/   # Platform Management (users, tenants, roles, audit)
│       │       ├── tenants/    # Tenant Management (users, roles, audit)
│       │       ├── system/     # System Health & Status
│       │       └── router.py   # API Router Configuration
│       ├── auth_strategies/    # Auth Strategy implementations (Email, OAuth, etc.)
│       ├── core/               # Core Infrastructure (Security, Config, DB init)
│       ├── models/             # Data Models (SQLAlchemy ORM)
│       ├── repositories/       # Data Access Layer (Postgres, Mongo)
│       ├── schemas/            # Pydantic Models (Request/Response)
│       ├── services/           # Business Logic (Auth, Email, Roles, Tenants, Sessions)
│       └── main.py             # Application Entrypoint
├── tests/               # Complete Test Suite
└── README.md            # Documentation
```

## Authorization Model: Scoped PBAC + Level Hierarchy

AuthEngine implements a sophisticated dual-layered authorization system that combines Permission-Based Access Control (PBAC) with a Strict Numerical Hierarchy.

### 1. Granular Permissions (PBAC)
Authorization is decoupled from role names. The system checks if an actor possesses a specific permission required for an action within a given context.
- **Scoped Context**: Permissions are evaluated within a `tenant_id` context.
- **Platform Overrides**: Platform-level roles (e.g., `SUPER_ADMIN`) possess global scope.
- **Action-Oriented**: Permissions like `tenant.roles.assign` provide clear audit trails and flexible role composition.

### 2. Strict Numerical Level Hierarchy
To prevent privilege escalation, every role is assigned a `level` weight (0-100).
- **Rule of Strict Superiority**: An actor can only assign or remove roles that have a level strictly lower than their own max level.
- **Lateral Protection**: A `TENANT_ADMIN` (level 50) cannot manage another `TENANT_ADMIN`, even with the correct permissions.
- **System Role Protection**: Foundational roles like `SUPER_ADMIN` are protected at the service layer.

| Role | Level | Scope | Description |
| :--- | :--- | :--- | :--- |
| **SUPER_ADMIN** | 100 | PLATFORM | Full platform control, bootstrap-only. |
| **PLATFORM_ADMIN** | 80 | PLATFORM | Manage organizations and platform users. |
| **TENANT_OWNER** | 60 | TENANT | Full control over a specific organization. |
| **TENANT_ADMIN** | 50 | TENANT | Administrative access within a tenant. |
| **TENANT_MANAGER** | 30 | TENANT | Operational management within a tenant. |
| **TENANT_USER** | 10 | TENANT | Standard authenticated tenant member. |

### 3. Context-Aware Middleware
The `require_permission` decorator automatically extracts the `tenant_id` from API path parameters and validates the user's permissions for that specific organization.

## Technology Stack

- **Runtime**: Python 3.12+
- **Web Framework**: FastAPI
- **Primary Database**: PostgreSQL (Async SQLAlchemy + asyncpg)
- **Cache/Session Store**: Redis (redis-py async)
- **NoSQL Store**: MongoDB (Motor) - For audit logs
- **Migrations**: Alembic
- **Package Manager**: uv

## Quick Start

### Prerequisites
- Python 3.12+
- PostgreSQL
- Redis
- MongoDB

### Installation

1. **Install Dependencies**
   ```bash
   pip install uv
   uv sync
   ```

2. **Environment Setup**
   ```bash
   cp .env.example .env
   ```

3. **Database Setup**
   ```bash
   auth-engine migrate
   ```

4. **Run Server**
   ```bash
   auth-engine run
   ```

## API Endpoints (v1)

### Public Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/auth/register` | Register new user |
| `POST` | `/api/v1/auth/login` | Login with session creation |
| `POST` | `/api/v1/auth/logout` | Logout and revoke session |
| `POST` | `/api/v1/auth/refresh` | Refresh access token |
| `POST` | `/api/v1/auth/reset-password` | Initiate password reset |
| `GET`  | `/api/v1/auth/verify-email` | Verify email with token |
| `POST` | `/api/v1/auth/verify-phone` | Verify phone with OTP |
| `POST` | `/api/v1/auth/request-token` | Request action token |

### User Context (Me)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/me` | Get current user profile |
| `GET` | `/api/v1/me/tenants` | List user's tenants |
| `GET` | `/api/v1/me/tenants/{tenant_id}/permissions` | Get user permissions in tenant |

### Platform — Tenants
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`    | `/api/v1/platform/tenants` | List all tenants |
| `POST`   | `/api/v1/platform/tenants` | Create tenant |
| `GET`    | `/api/v1/platform/tenants/{tenant_id}` | Get tenant |
| `PUT`    | `/api/v1/platform/tenants/{tenant_id}` | Update tenant |
| `DELETE` | `/api/v1/platform/tenants/{tenant_id}` | Delete tenant |

### Platform — Roles
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`    | `/api/v1/platform/roles` | List platform roles |
| `POST`   | `/api/v1/platform/users/{user_id}/roles` | Assign role to user |
| `DELETE` | `/api/v1/platform/users/{user_id}/roles/{role_name}` | Remove role from user |

### Platform — Audit
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/platform/audit-logs` | Get platform audit logs |
| `GET` | `/api/v1/platform/tenants/{tenant_id}/audit-logs` | Get tenant audit logs (platform scope) |

### Tenant — Users
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`    | `/api/v1/tenants/{tenant_id}/users` | List tenant users |
| `POST`   | `/api/v1/tenants/{tenant_id}/users` | Invite user to tenant |
| `GET`    | `/api/v1/tenants/{tenant_id}/users/{user_id}` | Get tenant user |
| `DELETE` | `/api/v1/tenants/{tenant_id}/users/{user_id}` | Remove user from tenant |

### Tenant — Roles
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`    | `/api/v1/tenants/{tenant_id}/roles` | List tenant roles |
| `GET`    | `/api/v1/tenants/{tenant_id}/users/{user_id}/roles` | Get user's roles in tenant |
| `POST`   | `/api/v1/tenants/{tenant_id}/users/{user_id}/roles` | Assign role to user in tenant |
| `DELETE` | `/api/v1/tenants/{tenant_id}/users/{user_id}/roles/{role_name}` | Remove role from user in tenant |

### Tenant — Audit
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/tenants/{tenant_id}/audit-logs` | Get tenant audit logs |

### System
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/` | Root |
| `GET` | `/api/v1/health` | Health check (DB/Redis status) |

## Testing

```bash
pytest
```

## License

MIT License
