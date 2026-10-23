# Provider adapter notes

The current `/api/provider/refresh` implementation is intentionally a guarded scaffold. The route path and response fields (`reference`, `transactionId`, `confirmedUsd`) are illustrative and **must not be treated as PROXIES.SX's real API contract**. Keep `PROVIDER_ENABLED=false` until the company supplies written authorization and current official docs.

When implementing the real adapter, require authenticated TLS, validate response schema and currency, verify signed webhooks if available, use idempotent settlement references, handle refunds/reversals, and never trust client-supplied earnings. Add integration tests against the provider's sandbox before production.
