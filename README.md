# auth-engine

Production-ready backend API for **AuthEngine** — multi-tenant IAM, RBAC, OIDC provider, social login, MFA, passkeys, and token introspection.

Built with FastAPI and PostgreSQL. Migrations via Alembic; seeding is handled separately by [auth-engine-data](https://github.com/auth-engine/auth-engine-data).

## Development

### 1. Local

Requires Python **3.12+**, [uv](https://docs.astral.sh/uv/), and running Postgres, MongoDB, and Redis.

```bash
cd auth-engine
uv sync
cp .env.example .env.local
auth-engine migrate
auth-engine run              # add --reload for hot reload
```

Seed once (after migrate):

```bash
cd ../auth-engine-data
uv sync && cp .env.example .env.local
uv run auth-engine-data all
```

### 2. Compose

Full stack (API + dashboard + databases) from **[auth-engine-infra/compose](https://github.com/auth-engine/auth-engine-infra/tree/main/compose)**:

```bash
cd auth-engine-infra/compose
cp env.local.example .env
docker compose up -d
docker exec authengine-api auth-engine migrate
```

Then seed from **auth-engine-data** (see [auth-engine-data README](https://github.com/auth-engine/auth-engine-data)).

## Production

| Path | Guide |
|------|-------|
| Local VM + Cloudflare Tunnel | [deploy-local-vm.sh](https://github.com/auth-engine/auth-engine-infra/blob/main/scripts/deploy-local-vm.sh) |
| AWS EC2 or any cloud VM | [deploy-aws.sh](https://github.com/auth-engine/auth-engine-infra/blob/main/scripts/deploy-aws.sh) |

Docker image: `qniranjan01/authengine:latest`

## Documentation

| Guide | Link |
|-------|------|
| Quick Start | [docs.authengine.org/quick-start](https://docs.authengine.org/quick-start/) |
| Deployment | [docs.authengine.org/deployment](https://docs.authengine.org/deployment/) |
| API Reference | [docs.authengine.org/api-reference](https://docs.authengine.org/api-reference/) |
| OAuth2 / OIDC | [docs.authengine.org/oauth2-oidc-guides](https://docs.authengine.org/oauth2-oidc-guides/) |
| Architecture | [docs.authengine.org/architecture](https://docs.authengine.org/architecture/) |
| Security | [docs.authengine.org/security-overview](https://docs.authengine.org/security-overview/) |

## Related repositories

[auth-engine-dashboard](https://github.com/auth-engine/auth-engine-dashboard) · [auth-engine-data](https://github.com/auth-engine/auth-engine-data) · [auth-engine-infra](https://github.com/auth-engine/auth-engine-infra) · [auth-engine-docs](https://github.com/auth-engine/auth-engine-docs)
