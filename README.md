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

## API Endpoints (v1 Highlights)

### Public Authentication
| Method   | Endpoint                              | Description                              |
|----------|---------------------------------------|------------------------------------------|
| `POST`   | `/api/v1/auth/register`               | User Registration                        |
| `POST`   | `/api/v1/auth/login`                  | Login with Session Creation              |
| `POST`   | `/api/v1/auth/logout`                 | Global Session Revocation                |
| `POST`   | `/api/v1/auth/refresh`                | Refresh Access Token                     |
| `POST`   | `/api/v1/auth/reset-password`         | Initiate Password Reset                  |
| `GET`    | `/api/v1/auth/verify-email`           | Verify Email with Token                  |
| `POST`   | `/api/v1/auth/verify-phone`           | Verify Phone with OTP                    |

### User Context (Me)
| Method   | Endpoint                              | Description                              |
|----------|---------------------------------------|------------------------------------------|
| `GET`    | `/api/v1/me`                          | Get Current User Profile                 |
| `GET`    | `/api/v1/me/tenants`                  | List User's Tenants                      |
| `GET`    | `/api/v1/me/tenants/{tenant_id}/permissions` | Get User Permissions in Tenant    |

### Platform Management
| Method   | Endpoint                              | Description                              |
|----------|---------------------------------------|------------------------------------------|
| `GET`    | `/api/v1/platform/users`              | List All Users (Platform)                |
| `GET`    | `/api/v1/platform/users/{user_id}`    | Get User Details                         |
| `GET`    | `/api/v1/platform/tenants`            | List All Tenants                         |
| `POST`   | `/api/v1/platform/tenants`            | Create Tenant                            |
| `GET`    | `/api/v1/platform/tenants/{tenant_id}`| Get Tenant Details                       |
| `GET`    | `/api/v1/platform/roles`              | List Platform Roles                      |
| `GET`    | `/api/v1/platform/audit-logs`         | Platform Audit Logs                      |

### Tenant Management
| Method   | Endpoint                              | Description                              |
|----------|---------------------------------------|------------------------------------------|
| `GET`    | `/api/v1/tenants/{tenant_id}/users`   | List Tenant Users                        |
| `POST`   | `/api/v1/tenants/{tenant_id}/users`   | Add User to Tenant                       |
| `GET`    | `/api/v1/tenants/{tenant_id}/roles`   | List Tenant Roles                        |
| `POST`   | `/api/v1/tenants/{tenant_id}/roles`   | Create Tenant Role                       |
| `GET`    | `/api/v1/tenants/{tenant_id}/audit-logs` | Tenant Audit Logs                    |

### System
| Method   | Endpoint                              | Description                              |
|----------|---------------------------------------|------------------------------------------|
| `GET`    | `/api/v1/health`                      | System health (DB/Redis status)          |

## Testing

```bash
pytest
```

## License

MIT License
