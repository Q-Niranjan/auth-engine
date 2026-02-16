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
- **JWT Architecture**: Stateless authentication using short-lived Access Tokens and secure, rotation-ready Refresh Tokens.
- **Role-Based Access Control (RBAC)**: Fine-grained permission system for authorization.
- **Session Management**: Redis-backed session storage for high-speed validity checks and instant revocation capability.
- **Rate Limiting**: Distributed rate limiting using Redis to prevent DDoS and brute-force attacks.
- **Audit Logging**: Comprehensive immutable logs for all security events.

### 🏗️ Technical Excellence (FAANG Ready)
- **Async First**: Fully asynchronous I/O using `asyncio` for high throughput.
- **Database sharding ready**: Modular repository pattern supporting horizontal scaling.
- **Type Safety**: strict type checking with **Pydantic v2** and **Mypy**.
- **12-Factor App**: Fully configurable via environment variables.

## 📐 Project Structure

```
auth-engine/
├── alembic/                 # Database migrations (Alembic)
│   └── versions/            # Migration scripts
├── src/
│   └── auth_engine/
│       ├── api/             # API Layer
│       │   ├── v1/          # Versioned endpoints
│       │   ├── auth_deps.py # Authentication dependencies
│       │   └── deps.py      # Core dependencies (DB, Redis)
│       ├── core/            # Core Infrastructure
│       │   ├── config.py    # Pydantic Settings
│       │   ├── security.py  # Security utils (Argon2, JWT)
│       │   └── database.py  # SQLAlchemy Async Engine
│       ├── models/          # Data Models
│       │   ├── user.py      # User & Profile models
│       │   └── token.py     # Token definitions
│       ├── repositories/    # Data Access Layer (Repository Pattern)
│       │   ├── user_repo.py # User persistence logic
│       │   └── redis_repo.py# Cache/Session logic
│       ├── services/        # Business Logic Layer
│       │   └── auth_service.py # Auth flows orchestration
│       ├── strategies/      # Auth Strategy Implementations
│       │   ├── base.py      # Abstract Strategy Interface
│       │   └── email_password.py
│       ├── cli.py           # CLI Management Tool
│       └── main.py          # Application Entrypoint
├── tests/                   # Test Suite
├── alembic.ini              # Migration Configuration
├── pyproject.toml           # Dependency Management (uv)
├── uv.lock                  # Locked Dependencies
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

## 🔌 API Endpoints (v1)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/auth/register` | Register new user |
| `POST` | `/api/v1/auth/login` | Login (returns Access + Refresh tokens) |
| `GET`  | `/api/v1/users/me` | Get current user profile (Protected) |
| `GET`  | `/api/v1/health` | System health check (DB/Cache status) |

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
