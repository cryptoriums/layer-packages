# layer-packages

Shared Go packages for the Tellor Layer ecosystem.

## Packages

### `webunlock`

A lightweight HTTP unlock server for decrypting secrets at startup.  
Accepts a pluggable `validateFn` callback — works with any backend (cosmos keyring, GPG, etc.).

**Features:**
- Rate limiting (configurable max failures + lockout duration)
- Clean shutdown after successful unlock
- Context cancellation support
- Used by `bridge-remote-signer`, `layer-daemons`, and `layer`
