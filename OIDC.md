# AuthEngine — OIDC Integration Guide

AuthEngine acts as a fully featured OpenID Connect (OIDC) Provider. This enables third-party applications or internal microservices to authenticate users via AuthEngine using standard OIDC flows (like Authorization Code flow).

## API Overview

AuthEngine implements the standard OIDC endpoints, prefixed with `/api/v1/oidc`:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/.well-known/openid-configuration` | OIDC Discovery document |
| `GET` | `/jwks.json` | JSON Web Key Set (public keys for verifying JWTs) |
| `POST` | `/register` | OIDC Dynamic Client Registration |
| `GET/POST` | `/authorize` | OIDC Authorization Endpoint (handles login/consent) |
| `POST` | `/token` | OIDC Token Endpoint (code exchange, refresh tokens) |
| `GET` | `/userinfo` | Returns profile information about the authenticated user |

---

## OIDC Discovery

Applications can auto-configure themselves by requesting the discovery document:

```http
GET /api/v1/oidc/.well-known/openid-configuration
```

This returns all supported endpoints, scopes, response types, and signing algorithms (typically `RS256`).

---

## Client Registration

Before an application can use AuthEngine for OIDC, it must be registered to obtain a `client_id` and configure its authentication method.

```http
POST /api/v1/oidc/register
Content-Type: application/json

{
  "client_name": "My Client App",
  "redirect_uris": ["https://my-app.example.com/callback"],
  "token_endpoint_auth_method": "client_secret_post"
}
```

### Supported Client Authentication Methods

AuthEngine supports multiple ways for the client to authenticate at the `/token` endpoint:
- **`client_secret_basic`**: (Default) The client sends `client_id` and `client_secret` via an HTTP Basic Auth header.
- **`client_secret_post`**: The client includes `client_id` and `client_secret` in the POST body.
- **`private_key_jwt`**: High security. The client signs a JWT with its own private key and sends it as a client assertion. The client must register a `jwks_uri` during registration to provide its public keys.

---

## Authorization Code Flow

This is the most common and secure flow for web applications.

### 1. Authorization Request
The application redirects the user to AuthEngine to log in:

```http
GET /api/v1/oidc/authorize?
  response_type=code
  &client_id=<YOUR_CLIENT_ID>
  &redirect_uri=https://my-app.example.com/callback
  &scope=openid profile email
  &state=1234wxyz
```

If the user is not logged in, they will be prompted to authenticate (via password, OAuth, Magic Link, WebAuthn, etc.) and consent.

### 2. Authorization Callback
AuthEngine redirects back to your application with a `code`:

```http
GET https://my-app.example.com/callback?code=SplxlOBeZQQYbYS6WxSbIA&state=1234wxyz
```

### 3. Token Exchange
Your application exchanges the authorization `code` for an `access_token` and `id_token`.

```http
POST /api/v1/oidc/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <base64(client_id:client_secret)>

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https://my-app.example.com/callback
```

AuthEngine responds with the tokens:

```json
{
  "access_token": "eyJhbG...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
  "id_token": "eyJhbG..."
}
```

---

## Key Rotation and Security

AuthEngine signs all OIDC `id_token`s using `RS256` (RSA Signature with SHA-256). The public keys needed to verify these signatures are exposed at the JWKS endpoint:

```http
GET /api/v1/oidc/jwks.json
```

It's recommended that Relying Parties (your apps) cache the JWKS response and automatically fetch it again if they encounter an unknown `kid` (Key ID) in a token header.

---
