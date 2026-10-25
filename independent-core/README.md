# RoarNet Independent Core

Independent local control plane using Node.js and SQLite, with no third-party
bandwidth provider dependency.

Includes:
- Node registration and per-node bearer credentials
- Idempotent usage-event accounting
- Unique references for verified net-revenue records
- 80/20 accounting calculation
- Admin-protected reporting

Important:
- This is not a traffic relay or a revenue-generating service by itself.
- Usage events are reported by nodes and are not independently verified.
- Net revenue must only be recorded after actual customer payment and costs
  have been reconciled.
- There is no automatic USDT transfer, customer billing, or live proxy delivery.
- Keep the admin token secret. Before public deployment, use HTTPS, rate limits,
  abuse controls, privacy notices, customer contracts, and independent metering.
