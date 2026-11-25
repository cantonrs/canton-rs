# Security Policy

## Supported Versions

During the pre-1.0 preview cycle, security fixes are provided for the latest `0.8.x` release:

| Version | Supported |
|---|---|
| `0.8.x` (latest) | Yes |
| `< 0.8.0` | No |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, send a report directly to:

- **Email**: `hello@getcantonrs.dev`
- **Subject prefix**: `[SECURITY] canton-rs: <short summary>`

Please include as much of the following as possible:
- `canton-rs --version` and OS / architecture
- Affected subcommand, crate, or API endpoint
- Minimal reproduction steps (or a redacted `.simrun` bundle / test vector)
- Potential impact (e.g., sub-transaction privacy leak, authentication bypass, denial of service, state corruption)

## Response Process

1. **Acknowledgement**: We aim to acknowledge receipt within **48 hours**.
2. **Triage & Fix**: We will confirm reproducibility, assess severity, and coordinate a fix and disclosure timeline with you.
3. **Disclosure**: Once a patched release is published on GitHub Releases, we will publish a security advisory crediting the reporter (unless anonymity is requested).

## Scope Notes

- `canton-rs` binds local observability endpoints (`--metrics-bind`) to `127.0.0.1` by default. Exposing unauthenticated metrics or development flags (`--dev-auth`) on public interfaces is out of scope.
- Experimental Labs repositories (such as ZK PoC prototypes) are tracked separately from the core `canton-rs` runtime.
