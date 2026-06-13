# auth-engine

Backend API for **AuthEngine** — FastAPI IAM, multi-tenancy, OIDC provider, and token introspection.

**Documentation:** [auth-engine-docs](https://github.com/auth-engine/auth-engine-docs) · published at [docs.authengine.org](https://docs.authengine.org)

| Guide | Link |
|-------|------|
| Quick Start | [quick-start.md](https://docs.authengine.org/quick-start/) |
| OAuth2 / OIDC | [oauth2-oidc-guides.md](https://docs.authengine.org/oauth2-oidc-guides/) |
| API Reference | [api-reference.md](https://docs.authengine.org/api-reference/) |
| Architecture | [architecture.md](https://docs.authengine.org/architecture/) |
| Deployment | [deployment.md](https://docs.authengine.org/deployment/) |
| Security | [security-overview.md](https://docs.authengine.org/security-overview/) |

## What this repository is

FastAPI service that owns the REST API, database migrations (Alembic), and the OIDC provider. It does **not** seed RBAC or the super admin on startup — run **[auth-engine-data](https://github.com/auth-engine/auth-engine-data)** after migrations. Docker Compose manifests live in **[auth-engine-infra](https://github.com/auth-engine/auth-engine-infra)**.

## Local development

Requires Python **3.12+** and [uv](https://docs.astral.sh/uv/). Postgres, MongoDB, and Redis must be running (or use Compose from `auth-engine-infra`).

```bash
cd auth-engine
uv sync
cp .env.example .env.local
auth-engine migrate
auth-engine run              # optional: --reload
```

After migrations, seed roles and the super admin:

```bash
cd ../auth-engine-data
uv sync && cp .env.example .env.local
uv run auth-engine-data all
```

### Lint & format

Install dev tools once, then run checks before pushing:

```bash
uv sync --extra dev
uv run ruff check src              # lint
uv run ruff format src             # auto-fix formatting
uv run ruff format --check src     # CI-style check (no file changes)
uv run pre-commit install          # optional: run checks on every commit
```

If `ruff format --check` fails, it only reports which files need changes. Run `uv run ruff format src` to fix them, then commit again.

## Production

| Host | Role |
|------|------|
| [api.authengine.org](https://api.authengine.org) | API + Swagger |
| [auth.authengine.org](https://auth.authengine.org) | OIDC / login UI |
| [app.authengine.org](https://app.authengine.org) | Admin dashboard |
| [docs.authengine.org](https://docs.authengine.org) | Documentation |

## Docker

Dockerfile only — compose files live in **[auth-engine-infra/compose](https://github.com/auth-engine/auth-engine-infra/tree/main/compose)**.

```bash
cd auth-engine-infra/compose
docker compose up -d --build
```

After migrations, seed roles and the super admin with **[auth-engine-data](https://github.com/auth-engine/auth-engine-data)** (`auth-engine-data all`). The API does not seed on startup.

Pre-built production images and CI/CD: [Deployment guide](https://docs.authengine.org/deployment/).

## Contributing

See [Contributing](https://docs.authengine.org/contributing/) or [CONTRIBUTING.md](CONTRIBUTING.md). Report security issues per [Security Policy](https://docs.authengine.org/security-policy/) — not via public issues.

## Related repositories

| Repository | Role |
|------------|------|
| [auth-engine-dashboard](https://github.com/auth-engine/auth-engine-dashboard) | Next.js admin dashboard |
| [auth-engine-data](https://github.com/auth-engine/auth-engine-data) | Roles, permissions & super-admin seeding |
| [auth-engine-docs](https://github.com/auth-engine/auth-engine-docs) | Platform documentation |
| [auth-engine-infra](https://github.com/auth-engine/auth-engine-infra) | Terraform & Docker Compose |
| [.github](https://github.com/auth-engine/.github) | Org profile, contributing & security policy |
