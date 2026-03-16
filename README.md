# scoutid-oidc-provider

Small OpenID Connect provider for ScoutID-style authentication.

This project is a FastAPI application that authenticates users against the Scoutnet API and exposes a minimal OIDC-compatible flow for a single trusted client. It is intended for self-hosted deployments where you control both the provider and the relying party.

## What it does

- Implements a login flow with a custom HTML login page.
- Authenticates credentials against the Scoutnet API.
- Issues authorization codes, ID tokens, access tokens, and userinfo responses.
- Supports logout and OIDC discovery endpoints.
- Uses server-side sessions with optional "remember me" behavior.
- Passes Scoutnet roles through as OIDC claims.

## Project scope

This is not a general-purpose OIDC provider.

- It is designed for a single configured client.
- Client registration is static through environment variables.
- Tokens and authorization requests are stored in process memory.
- Kubernetes manifests and deployment-specific files are intentionally excluded from the public repository.

## Endpoints

- `GET /auth/authorize`
- `GET /auth/login`
- `POST /auth/login`
- `GET /auth/logout`
- `POST /api/token`
- `GET /api/userinfo`
- `GET /.well-known/openid-configuration`
- `GET /.well-known/jwks.json`

## Required environment variables

The application expects configuration through environment variables.

| Variable                       | Required | Description                                                                                         |
| ------------------------------ | -------- | --------------------------------------------------------------------------------------------------- |
| `SESSION_SECRET_KEY`           | Yes      | Secret used by the session middleware.                                                              |
| `IDP_CLIENT_ID`                | Yes      | OIDC client ID accepted by the provider.                                                            |
| `IDP_CLIENT_SECRET`            | Yes      | OIDC client secret and current HS256 signing key.                                                   |
| `IDP_REDIRECT_URI`             | Yes      | Exact redirect URI accepted during code exchange.                                                   |
| `IDP_ISSUER`                   | No       | External issuer URL. Defaults to `http://localhost:5000`.                                           |
| `IDP_INTERNAL_URL`             | No       | Internal URL used in discovery metadata for token and userinfo endpoints. Defaults to `IDP_ISSUER`. |
| `IDP_POST_LOGOUT_REDIRECT_URI` | No       | Allowed base URI for post-logout redirects.                                                         |
| `SESSION_COOKIE_NAME`          | No       | Session cookie name. Defaults to `scoutid-oidc-server`.                                             |
| `LOGIN_TIMEOUT`                | No       | Authorization/login timeout in seconds. Defaults to `300`.                                          |
| `JWT_EXP_DELTA_SECONDS`        | No       | Token lifetime in seconds. Defaults to `3600`.                                                      |
| `HTTP_SERVER_PORT`             | No       | HTTP port. Defaults to `5000`.                                                                      |
| `SCOUTNET_API`                 | No       | Base URL for the Scoutnet API. Defaults to `https://scoutnet.se/api`.                               |
| `SCOUTNET_APP_ID`              | No       | If 10 characters or more, identifies the app to Scoutnet. Defaults to `change_me`.                  |
| `SCOUTNET_APP_NAME`            | No       | Supplying an app name will make it easier to identify the app. Defaults to `scoutid-oidc-provider`. |
| `SCOUTNET_APP_DEVICE_NAME`     | No       | Aids token management . Defaults to `My ScoutID`.                                                   |
| `DEBUG`                        | No       | Enables debug logging when set to `true`. Defaults to `false`.                                      |

## Local development

### Run with Python

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

### Run with Docker

```bash
docker build -t scoutid-oidc-provider .
docker run --rm -p 5000:5000 \
	-e SESSION_SECRET_KEY=change-me \
	-e IDP_CLIENT_ID=example-client \
	-e IDP_CLIENT_SECRET=change-me-too \
	-e IDP_REDIRECT_URI=http://localhost/callback \
	scoutid-oidc-provider
```

## Security notes

- Do not commit secrets, client credentials, or deployment manifests with real infrastructure details.
- The current implementation signs ID tokens with HS256 using `IDP_CLIENT_SECRET`. That is acceptable for a single confidential client, but RS256 would provide better key separation if the project grows.
- Session state, authorization codes, and access tokens are stored in memory. Running multiple replicas requires shared state or sticky sessions.

## Repository hygiene

- Deployment-specific files belong outside the public repository.
- Secret manifests are ignored through `.gitignore`.
- Public documentation should use placeholder domains and credentials only.
