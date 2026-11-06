# RoarNet Relay V1 — Complete Architecture

Version: 1.0
Status: Design specification — implementation not yet enabled.

## 1. Project objective

Build an independently maintainable relay system that allows explicitly
consenting participant devices to provide authorized network egress
capacity to contracted traffic buyers.

The relay must integrate with the existing RoarNet server, node identity,
participant accounts, consent records, traffic accounting and settlement
system.

The relay is not an open public proxy.

## 2. Main components

### A. Android Relay Agent

Responsibilities:
- Register and authenticate the device.
- Bind the device to its existing RoarNet node and participant.
- Display explicit sharing consent and current sharing status.
- Maintain an outbound authenticated connection to the Relay Gateway.
- Receive authorized relay session assignments.
- Open permitted destination connections.
- Forward data only for approved sessions.
- Count transmitted and received bytes per session.
- Report session lifecycle and usage counters.
- Stop new sessions immediately after consent revocation.
- Close active sessions when the participant pauses sharing.
- Respect Android foreground-service and battery restrictions.
- Reconnect safely after network interruptions.

Android implementation:
- Kotlin foreground service.
- Persistent notification while sharing is active.
- Android VPNService only if a later approved routing design requires it.
- No root requirement.
- No public listening port on participant devices.
- No collection or inspection of unrelated personal device traffic.

### B. Relay Gateway

Responsibilities:
- Authenticate relay agents and traffic buyers.
- Maintain active relay connections.
- Assign sessions to eligible devices.
- Enforce per-session and per-device limits.
- Enforce destination and port policies.
- Track session state and byte counters.
- Reject expired, duplicated or unauthorized assignments.
- Terminate sessions on consent revocation or policy violation.
- Send signed usage reports to the RoarNet control plane.

The Gateway must never operate as an unrestricted open proxy.

### C. RoarNet Control Plane

Existing server responsibilities remain authoritative for:
- Participant identity.
- Node identity.
- Account linking.
- Consent records.
- Device registration.
- Relay authorization.
- Traffic event ingestion.
- Customer prepaid balances.
- Usage limits.
- Provider revenue batches.
- Participant accounting.
- Monthly settlement.
- Withdrawal records.

The relay must not independently create payable earnings.

### D. Traffic Buyer Connector

Each buyer integration must have:
- A unique provider identifier.
- Contract and country eligibility information.
- Authentication credentials stored server-side.
- Agreed traffic measurement units.
- Agreed billing rules.
- Provider-side usage reports.
- Reconciliation rules.
- Dispute and refund handling.
- Payment confirmation records.

No provider should be marked as active until its contract,
technical integration and payment terms are verified.

## 3. Network architecture

V1 uses outbound connections initiated by the participant device.

Connection flow:

1. Agent authenticates with RoarNet.
2. Agent establishes a secure outbound connection to Gateway.
3. Gateway validates the device and its active consent.
4. A contracted buyer submits an authorized session request.
5. Gateway selects an eligible device.
6. Gateway sends a short-lived session assignment.
7. Agent validates the assignment and destination policy.
8. Agent opens the destination connection.
9. Data is forwarded through the authenticated session.
10. Agent and Gateway maintain independent byte counters.
11. Gateway closes the session and produces a usage record.
12. RoarNet reconciles the record before financial recognition.

V1 transport:
- TLS protected control connection.
- Short-lived session credentials.
- Per-session identifiers.
- Explicit connection and idle timeouts.
- Bounded queues and backpressure.
- TCP support first.
- UDP support requires a separate security and accounting review.

## 4. Destination security policy

The Relay Gateway and Agent must enforce destination restrictions.

Reject:
- Loopback destinations.
- Private IPv4 and IPv6 networks.
- Link-local addresses.
- Cloud metadata addresses.
- Multicast and reserved address ranges.
- Destinations prohibited by the buyer contract.
- Disallowed ports and protocols.
- DNS results that resolve to prohibited address ranges.

DNS must be resolved and validated at connection time.
The validated address must be the address actually connected to.
Revalidate after DNS changes and redirects.

Prevent:
- DNS rebinding.
- Access to participant LAN devices.
- Access to router administration interfaces.
- Access to Android local services.
- Unrestricted scanning.
- Arbitrary port forwarding.
- Session reuse across different buyers.

V1 does not provide unrestricted HTTP CONNECT access to the public.

## 5. Device authentication

Each registered device receives:
- Device identifier.
- Participant identifier.
- Node identifier.
- Rotatable device credential.
- Credential creation and expiry timestamps.
- Revocation status.

Requirements:
- Store credentials in Android Keystore where supported.
- Never embed a shared permanent relay secret in the APK.
- Never expose buyer secrets to participant devices.
- Support credential rotation and immediate revocation.
- Bind every session to a participant, node and device.
- Require fresh authorization after account relinking.

A device credential must not be treated as proof that reported traffic is truthful.

## 6. Session state machine

Allowed states:

PENDING
AUTHORIZED
CONNECTING
ACTIVE
CLOSING
COMPLETED
REJECTED
EXPIRED
FAILED

Rules:
- Only AUTHORIZED sessions can connect.
- Only ACTIVE sessions can transfer bytes.
- A session can be finalized once.
- Repeated finalization must be idempotent.
- Expired sessions cannot be reopened.
- Revoked consent blocks new sessions and terminates active sessions.
- A failed session must not create payable usage.

## 7. Proposed session record

Logical fields:

- session_id
- provider_id
- buyer_request_id
- participant_id
- node_id
- device_id
- customer_id
- destination_host
- destination_port
- protocol
- status
- started_at
- ended_at
- bytes_sent
- bytes_received
- total_bytes
- sequence_number
- agent_report_hash
- gateway_report_hash
- provider_report_reference
- reconciliation_status

These are design fields, not an instruction to create a database table
before checking the existing schema.

## 8. Traffic measurement and reconciliation

Three measurement sources:

A. Agent measurement:
Bytes sent and received by the Android Relay Agent.

B. Gateway measurement:
Bytes observed at the Relay Gateway.

C. Buyer measurement:
Bytes accepted and reported by the contracted traffic buyer.

Rules:
- Use integer byte counters.
- Use monotonically increasing sequence numbers.
- Use unique session identifiers.
- Make event ingestion idempotent.
- Reject negative, malformed or impossible counters.
- Detect duplicate and out-of-order reports.
- Preserve raw reports for audit.
- Reconcile provider reports against gateway records.
- Keep disputed traffic separate from confirmed traffic.
- Never create earnings from unverified usage.

The Android agent is not a trusted financial authority.
Agent-reported counters alone cannot establish payable revenue.

## 9. Integration with current RoarNet accounting

Existing accounting remains authoritative.

The integration must preserve:
- Existing nodes and node credentials.
- Existing participant linking.
- Existing consent routes.
- Existing customer prepaid balances.
- Existing traffic_events reference uniqueness.
- Existing provider_revenue_batches.
- Existing provider_revenue_settlements.
- Existing participant wallet records.
- Existing monthly settlement logic.

Revenue allocation policy:
- 80% project owner.
- 15% participants.
- 5% operating reserve.

Calculate these shares only from confirmed net revenue after agreed costs.

Never count the same earning twice through both wallet entries and
provider settlement rows.

Do not treat measured traffic bytes as cash revenue.

Do not treat USD cents as USDT units.

## 10. Consent and participant controls

The participant interface must show:
- Sharing status.
- Active session count.
- Uploaded and downloaded bytes.
- Daily and monthly usage.
- Current provider identity where disclosure is permitted.
- Estimated earnings only when supported by confirmed accounting records.
- Pause sharing control.
- Revoke consent control.
- Device disconnect control.
- Usage history.

Consent must be explicit, versioned and revocable.

A revoked device must stop accepting new work immediately.

## 11. Abuse prevention

Required controls:
- Per-device connection limits.
- Per-participant traffic limits.
- Per-customer traffic limits.
- Per-session byte limits.
- Connection and idle timeouts.
- Destination allow/deny policies.
- Rate limits.
- Duplicate event protection.
- Anomaly detection.
- Abuse reports and account suspension.
- Audit logs for administrative actions.
- Emergency provider and relay shutdown.

No relay session may access private networks or participant devices.

## 12. Privacy

- Do not capture unrelated device traffic.
- Do not store payload contents.
- Do not log passwords, tokens or private headers.
- Store only the metadata required for security, accounting and contractual
  reconciliation.
- Restrict access to session records.
- Define retention and deletion periods.
- Provide participant disclosure before enabling sharing.
- Separate buyer identity data from participant-facing public data.

## 13. Operational monitoring

Monitor:
- Connected relay devices.
- Active sessions.
- Session success and failure rates.
- Bytes sent and received.
- Reconnection frequency.
- Gateway latency.
- Provider reconciliation differences.
- Rejected destinations.
- Consent revocations.
- Device battery and service interruptions.
- Queue depth and backpressure.
- Unconfirmed and disputed traffic.

Provide an emergency switch to stop all new relay sessions.

## 14. Failure handling

If the Gateway disconnects:
- Stop accepting new sessions.
- Close or safely expire affected sessions.
- Preserve the last acknowledged sequence number.
- Reconnect with backoff.
- Never replay finalized usage as a new event.

If the device disconnects:
- Mark active sessions interrupted.
- Preserve partial measurements.
- Await reconciliation.
- Do not automatically mark them payable.

If provider reconciliation fails:
- Keep the batch pending or disputed.
- Do not allocate unconfirmed revenue.
- Preserve the provider report for review.

## 15. Testing requirements

Unit tests:
- Session state transitions.
- Authentication expiry.
- Destination restrictions.
- Byte counter arithmetic.
- Sequence handling.
- Idempotent event ingestion.
- Consent revocation.
- Session timeout.
- Revenue reconciliation.

Integration tests:
- Android Agent to Gateway.
- Gateway to RoarNet.
- Buyer connector to Gateway.
- Traffic event ingestion.
- Provider batch creation.
- Participant allocation.
- Monthly settlement.

Security tests:
- DNS rebinding.
- Private network access attempts.
- Metadata address access.
- Duplicate requests.
- Replay attacks.
- Expired credentials.
- Revoked devices.
- Concurrent session limits.
- Malformed reports.

Financial tests:
- Confirmed revenue only.
- Correct 80/15/5 allocation.
- No duplicate earnings.
- Correct USD cents.
- Explicit FX conversion for USDT payouts.
- Failed payment does not become paid.

## 16. Implementation phases

Phase 1 — Architecture and compatibility:
Inspect existing database schema, authentication, consent, relay route,
accounting and Android service structure.

Phase 2 — Relay Gateway:
Create an independent gateway service with authenticated control channels,
session lifecycle, destination policy and audit logs.

Phase 3 — Android Agent:
Implement device enrollment, foreground service, consent controls,
outbound connection and session management.

Phase 4 — Measurement:
Implement gateway-side byte measurement, sequence numbers, signed reports
and idempotent ingestion.

Phase 5 — RoarNet integration:
Connect verified usage to existing traffic and accounting structures
without replacing existing node or participant systems.

Phase 6 — Buyer connector:
Integrate only a contracted buyer with verified reporting and payment terms.

Phase 7 — Security and controlled pilot:
Test with explicitly consenting devices and a limited approved destination
policy before increasing capacity.

Phase 8 — Production readiness:
Independent security review, operational monitoring, incident response,
provider reconciliation and payment verification.

## 17. Strict implementation constraints

- Do not replace the existing Android server with independent-core.
- Do not delete or redesign the existing node system.
- Do not modify nodes.token_hash or customers.token_hash.
- Do not run production services during development tests.
- Do not enable real traffic forwarding before destination security review.
- Do not create new accounting tables before schema inspection.
- Do not mark unconfirmed provider revenue as payable.
- Back up every modified file.
- Run node --check after JavaScript changes.
- Restore the backup if syntax validation fails.
- Keep secrets outside source code and APK assets.

## 18. V1 completion criteria

V1 is considered technically complete only when:
- A participant can explicitly enroll a device.
- The device can authenticate and connect securely.
- The Gateway can assign and terminate authorized sessions.
- Destination policies are enforced.
- Gateway-side byte counts are recorded.
- Duplicate and replayed reports are rejected.
- Revoked consent stops relay activity.
- RoarNet receives reconciled usage records.
- Financial records derive only from confirmed provider revenue.
- Security and integration tests pass.

A running API or a successful node syntax check alone does not
constitute a working or production-ready relay.
