# AuthEngine - Enterprise-Grade Identity & Access Management System

A high-performance, scalable, and secure authentication platform built with FastAPI, designed to handle millions of users. This project demonstrates advanced system design patterns, secure architecture, and production-ready code suitable for modern distributed systems.

## 🚀 Key Features

### 🔐 Multi-Strategy Authentication
The core of AuthEngine is its extensible **Strategy Pattern** implementation, allowing seamless integration of various authentication methods:

- **Email/Password**: Robust implementation with **Argon2** hashing (winner of the Password Hashing Competition), offering superior resistance to GPU cracking compared to bcrypt.
- **OAuth 2.0 / OIDC**: Standardized social login (Google, GitHub, LinkedIn) and enterprise SSO integration.
- **Magic Links**: Passwordless authentication flow using secure, short-lived signed URLs.
- **MFA (Multi-Factor Authentication)**: Time-based One-Time Password (TOTP) support compatible with Google Authenticator/Authy.
- **Biometric WebAuthn**: (Planned) FIDO2 support for hardware keys and biometric passkeys.

### 🛡️ Advanced Security Architecture
- **Permission-Based Access Control (PBAC)**: Granular permission system (e.g., `tenant.update`, `platform.users.manage`) for flexible authorization.
- **Multi-Tenancy**: Built-in organizational isolation with hierarchical role management and tenant-aware guards.
- **Session & Device Management**: Redis-backed session tracking, allowing users to view active devices and revoke sessions instantly.
- **Rate Limiting**: Distributed rate limiting using Redis to prevent DDoS and brute-force attacks.
- **Auto-Bootstrap**: Automatic seeding of Roles, Permissions, and a `SUPER_ADMIN` user on first application startup.

### 🏗️ Technical Excellence
- **Async First**: Fully asynchronous I/O using `asyncio` for high throughput.
- **Database sharding ready**: Modular repository pattern supporting horizontal scaling.
- **Type Safety**: strict type checking with **Pydantic v2** and **Mypy**.
- **12-Factor App**: Fully configurable via environment variables.

## 📐 Project Structure

```
auth-engine/
├── alembic/                 # Database migrations
├── src/
│   └── auth_engine/
│       ├── api/             # API Layer
│       │   ├── v1/          
│       │   │   ├── endpoints/ # Platform, Tenant, Auth, User routers
│       │   │   └── router.py  # v1 Router assembly
│       │   ├── auth_deps.py # Auth & Session-validation dependencies
│       │   ├── deps.py      # Core store dependencies
│       │   └── rbac.py      # PBAC Guards & Tenant Isolation
│       ├── core/            # Core Infrastructure
│       │   ├── bootstrap.py # System Auto-seeder
│       │   ├── rbac_seed.py # PBAC/RBAC definitions
│       │   └── config.py    # Application settings
│       ├── models/          # Data Models (ORM)
│       ├── repositories/    # Data Access Layer
│       ├── schemas/         # Pydantic Models (Request/Response)
│       ├── services/        # Business Logic (Separated by Concern)
│       │   ├── auth_service.py    # Auth Lifecycle
│       │   ├── session_service.py # Redis Session logic
│       │   ├── tenant_service.py  # Organizational Logic
│       │   └── role_service.py    # PBAC & Hierarchy logic
│       ├── strategies/      # Auth Strategy Implementations
│       └── main.py          # Application Entrypoint
├── tests/                   # Complete Test Suite
└── README.md                # Documentation
```

## 🛠️ Technology Stack

- **Runtime**: Python 3.12+
- **Web Framework**: FastAPI (High performance, easy to use)
- **Primary Database**: PostgreSQL (Async SQLAlchemy + asyncpg)
- **Cache/Session Store**: Redis (redis-py async)
- **NoSQL Store**: MongoDB (Motor) - *For audit logs/flexible data*
- **Migrations**: Alembic
- **Package Manager**: uv (Fastest Python package installer)

## ⚡ Quick Start

### Prerequisites
- Python 3.12+
- PostgreSQL
- Redis

### Installation

1. **Install Dependencies**
   ```bash
   pip install uv
   uv sync
   ```

2. **Environment Setup**
   Copy `.env.example` to `.env` and configure your database credentials.
   ```bash
   cp .env.example .env
   ```

3. **Database Setup**
   Use the built-in CLI to run migrations.
   ```bash
   auth-engine migrate
   ```

4. **Run Server**
   ```bash
   auth-engine run
   ```
   Access Swagger UI at `http://localhost:8000/docs`

## 🔌 API Endpoints (v1 Highlights)

| Method   | Endpoint                          | Description                              |
|----------|-----------------------------------|------------------------------------------|
| `POST`   | `/api/v1/auth/login`             | Login with Session Creation              |
| `POST`   | `/api/v1/auth/logout`            | Global Session Revocation                |
| `GET`    | `/api/v1/users/me/sessions`      | List active devices/sessions             |
| `GET`    | `/api/v1/tenants/{id}/users`     | Manage Tenant Context (Isolated)         |
| `GET`    | `/api/v1/platform/tenants`       | Platform-wide Administration             |
| `GET`    | `/api/v1/health`                 | System health (DB/Redis status)          |

## 🧪 Testing

```bash
pytest
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

MIT License
