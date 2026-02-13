# Traefik OIDC Plugin

A Traefik middleware plugin that implements OAuth 2.0 Authorization Code flow with PKCE for authenticating requests to backend services. The plugin acts as a **public client** (no client secret required), storing session state in encrypted cookies.

## Features

- PKCE (Proof Key for Code Exchange) for secure public client authentication
- AES-256-GCM encrypted session cookies
- Automatic token refresh
- Configurable token forwarding (access token or ID token)
- Path exclusion for health checks and public endpoints

## Installation

Add the plugin to your Traefik static configuration:

```yaml
experimental:
  plugins:
    oidc:
      moduleName: github.com/jacobdam/traefik-oidc
      version: v1.0.0
```

## Configuration

### Required Fields

| Field | Description |
|-------|-------------|
| `providerURL` | OIDC provider base URL (e.g., `https://accounts.google.com`) |
| `clientID` | OAuth 2.0 Client ID from your provider |
| `sessionEncryptionKey` | Exactly 32 ASCII characters for AES-256 encryption |

### Optional Fields

| Field | Default | Description |
|-------|---------|-------------|
| `audience` | (empty) | OAuth audience parameter (required for some providers like Auth0) |
| `scopes` | `[openid, profile, email]` | OAuth scopes to request |
| `callbackPath` | `/oauth2/callback` | OAuth callback endpoint path |
| `logoutPath` | `/oauth2/logout` | Logout endpoint path |
| `cookieName` | `oidc_session` | Name of the session cookie |
| `cookieSecure` | `true` | Set to `true` for HTTPS (required in production) |
| `cookieSameSite` | `Lax` | Cookie SameSite policy: `Strict`, `Lax`, or `None` |
| `excludedPaths` | `[]` | Paths to exclude from authentication |
| `forwardAccessToken` | `true` | Forward access token in `Authorization` header |
| `forwardIDToken` | `false` | Forward ID token instead of access token |

### Example Configuration

```yaml
http:
  middlewares:
    oidc-auth:
      plugin:
        oidc:
          providerURL: "https://your-provider.com"
          clientID: "your-client-id"
          sessionEncryptionKey: "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
          audience: "https://your-api.example.com"
          scopes:
            - openid
            - profile
            - email
          cookieSecure: true
          cookieSameSite: "Strict"
          excludedPaths:
            - "/health"
            - "/metrics"
          forwardAccessToken: true
```

## Security Configuration

### Generating a Secure Encryption Key

The `sessionEncryptionKey` must be exactly 32 ASCII characters for AES-256 encryption.

```bash
# Option 1: Using openssl (recommended)
openssl rand -base64 32 | head -c 32

# Option 2: Using /dev/urandom
head -c 32 /dev/urandom | base64 | head -c 32
```

**Important:**
- The key must be exactly 32 ASCII characters
- Store the key securely (environment variable or secrets manager)
- Key rotation requires all users to re-authenticate
- Do not commit the key to version control

### Cookie Security Settings

For production deployments:

```yaml
cookieSecure: true      # Required for HTTPS
cookieSameSite: "Strict" # Recommended for same-site applications
```

Use `cookieSameSite: "Lax"` if your application requires cross-site navigation (e.g., links from emails).

### Path Exclusions

Excluded paths bypass authentication entirely. Use with caution:

```yaml
excludedPaths:
  - "/health"      # Also excludes /health/ready, /healthcheck
  - "/metrics"     # Also excludes /metrics/prometheus
  - "/.well-known" # Excludes all well-known paths
```

**Note:** Exclusions are prefix-based. `/health` will also exclude `/healthcheck`.

## Traefik Configuration Requirements

### Trusted Proxies

Configure Traefik to validate `X-Forwarded-*` headers from trusted sources only:

```yaml
entryPoints:
  websecure:
    address: ":443"
    forwardedHeaders:
      trustedIPs:
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"
```

This prevents external attackers from spoofing the `X-Forwarded-Host` and `X-Forwarded-Proto` headers.

### Rate Limiting

Add rate limiting before the OIDC middleware to prevent brute-force attacks:

```yaml
http:
  middlewares:
    rate-limit:
      rateLimit:
        average: 100
        burst: 50

    oidc-auth:
      plugin:
        oidc:
          # ... config ...

  routers:
    my-router:
      middlewares:
        - rate-limit
        - oidc-auth
      # ...
```

## Backend Service Considerations

### Token Forwarding

The plugin forwards tokens to backend services via the `Authorization: Bearer <token>` header. Configure which token to forward:

- `forwardAccessToken: true` (default) - Forward the access token
- `forwardIDToken: true` - Forward the ID token instead

### JWT Signature Validation

**Important:** This plugin does NOT validate JWT signatures. It extracts claims from tokens received directly from the IdP's token endpoint over HTTPS, which is considered a trusted server-to-server exchange.

Backend services should choose one of these approaches:

#### Option A: Trust the Middleware

If your network is fully trusted (e.g., internal Kubernetes cluster with network policies), backend services can accept tokens without additional validation. The middleware guarantees:

- Tokens were obtained through a valid OIDC flow
- Session cookies are encrypted and tamper-proof
- CSRF protection via state parameter validation

#### Option B: Validate Tokens (Recommended for Zero-Trust)

For zero-trust environments, backend services should validate JWT signatures:

```go
// Example: Validate JWT using provider's JWKS
import "github.com/golang-jwt/jwt/v5"

func validateToken(tokenString, jwksURL string) (*jwt.Token, error) {
    // Fetch JWKS from provider
    keySet, err := fetchJWKS(jwksURL)
    if err != nil {
        return nil, err
    }

    // Parse and validate token
    return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        kid := token.Header["kid"].(string)
        return keySet.LookupKey(kid)
    })
}
```

### Default Token Expiry

If the token response doesn't include `expires_in`, the plugin defaults to a 1-hour expiry. Backend services should handle expired tokens gracefully.

## OIDC Provider Setup

### Auth0

1. Create a **Regular Web Application** in Auth0
2. Set Application Type to **Single Page Application** (for PKCE without client secret)
3. Configure Allowed Callback URLs: `https://your-app.com/oauth2/callback`
4. Configure Allowed Logout URLs: `https://your-app.com/`
5. Enable "Authorization Code" grant with PKCE
6. Note: Set `audience` in the plugin config to receive access tokens for your API

### Google

1. Create OAuth 2.0 credentials in Google Cloud Console
2. Add authorized redirect URI: `https://your-app.com/oauth2/callback`
3. Use `https://accounts.google.com` as `providerURL`

### Keycloak

1. Create a public client in your realm
2. Enable "Standard Flow" (Authorization Code)
3. Set valid redirect URIs
4. Use `https://your-keycloak.com/realms/your-realm` as `providerURL`

## Security Checklist

Before deploying to production:

- [ ] Use HTTPS (`cookieSecure: true`)
- [ ] Generate a cryptographically random 32-byte encryption key
- [ ] Store encryption key in secrets manager (not in config files)
- [ ] Configure Traefik to validate `X-Forwarded-*` headers
- [ ] Add rate limiting middleware before OIDC middleware
- [ ] Register callback URL in OIDC provider's allowlist
- [ ] Backend services validate tokens OR network is fully trusted
- [ ] Review `excludedPaths` - these bypass authentication entirely
- [ ] Set appropriate `cookieSameSite` policy for your use case

## Endpoints

| Path | Description |
|------|-------------|
| `{callbackPath}` | OAuth callback endpoint (default: `/oauth2/callback`) |
| `{logoutPath}` | Logout endpoint (default: `/oauth2/logout`) |

### Logout

To log out a user, redirect them to the logout path:

```
/oauth2/logout?redirect_uri=/goodbye
```

The `redirect_uri` parameter must be a same-origin URL (relative path or matching host). External URLs are rejected to prevent open redirect vulnerabilities.

## License

MIT License
