# auth-engine

Backend API for **AuthEngine** — FastAPI IAM, multi-tenancy, OIDC provider, and token introspection.

**Documentation:** [auth-engine-infra/docs](https://github.com/auth-engine/auth-engine-infra/tree/main/docs) · published at [docs.authengine.org](https://docs.authengine.org)

| Guide | Link |
|-------|------|
| Quick Start | [quick-start.md](https://github.com/auth-engine/auth-engine-infra/blob/main/docs/quick-start.md) |
| OAuth2 / OIDC | [oauth2-oidc-guides.md](https://github.com/auth-engine/auth-engine-infra/blob/main/docs/oauth2-oidc-guides.md) |
| API Reference | [api-reference.md](https://github.com/auth-engine/auth-engine-infra/blob/main/docs/api-reference.md) |
| Architecture | [architecture.md](https://github.com/auth-engine/auth-engine-infra/blob/main/docs/architecture.md) |
| Deployment | [deployment.md](https://github.com/auth-engine/auth-engine-infra/blob/main/docs/deployment.md) |
| Security | [security-overview.md](https://github.com/auth-engine/auth-engine-infra/blob/main/docs/security-overview.md) |

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

Image: `qniranjan01/authengine` on Docker Hub (set `DOCKERHUB_USERNAME=qniranjan01` in GitHub Actions secrets).

## Related repositories

| Repository | Role |
|------------|------|
| [auth-engine-dashboard](https://github.com/auth-engine/auth-engine-dashboard) | Admin dashboard |
| [auth-engine-infra](https://github.com/auth-engine/auth-engine-infra) | Terraform, Docker Compose, docs |
