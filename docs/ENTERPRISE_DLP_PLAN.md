# VAULT-X Enterprise DLP Plan

## Target Model

VAULT-X is moving from a single-user personal vault toward an organization-run
DLP platform.

The intended deployment has:

```text
Admin Console / Control Plane
  Runs on a server controlled by IT/security admins.

Endpoint Agent
  Runs on each managed employee laptop.

Policy Channel
  Admin defines rules centrally. Agents fetch and enforce/report.

Event Channel
  Agents report DLP events, heartbeats, and security state.
```

## Backend Flow

The enterprise backend follows this shape:

```text
Normal Windows user activity
  |
  v
Endpoint Agent on laptop
  |
  +-- file activity metadata
  +-- process observations
  +-- heartbeat and device status
  +-- policy violation events
  |
  v
Admin Server API
  |
  +-- authentication and enrollment checks
  +-- policy lookup
  +-- event normalization
  +-- AI/ML malicious activity scoring
  |
  v
Enterprise Store + Audit Events
  |
  v
Admin Console UI
```

The employee does not use a VAULT-X interface. They continue using Windows
normally. The laptop agent runs in the background and reports allowed security
metadata to the admin-controlled backend.

## Important Scope Decision

Fingerprint and face-recognition checks are not part of the enterprise path.
They are difficult to test consistently and many laptops do not have reliable
hardware support. Enterprise identity should instead come from:

```text
device enrollment
admin-issued tokens
OS account/user inventory
central policy assignment
audit logs
future SSO/MDM integration
```

## Admin-Only UI

The browser UI is for administrators only. Employees do not need a VAULT-X UI.
Their laptops run the endpoint agent in the background after enrollment.

The admin console currently supports:

```text
fleet summary
managed laptop inventory
online/offline heartbeat status
recent security events
normal file/process activity logs
malicious activity verdicts
default policy view
endpoint enrollment endpoints
```

## Endpoint Agent

The agent script is:

```text
agent/vaultx_agent.py
```

For local testing:

```powershell
$env:VAULTX_API_KEY = "vaultx-local-dev-key"
$env:VAULTX_ENROLLMENT_TOKEN = "<token from enterprise_state.json or API>"
python -m agent.vaultx_agent enroll --user alice --department Finance
python -m agent.vaultx_agent heartbeat
python -m agent.vaultx_agent event --event-type sensitive_file_detected --severity medium --details '{"path":"report.xlsx","rule":"sensitive keyword"}'
python -m agent.vaultx_agent scan-once --watch-root C:\Users\alice\Documents
python -m agent.vaultx_agent monitor --watch-root C:\Users\alice\Documents
```

`monitor` is the long-running endpoint mode. In production it should be wrapped
as a Windows service or deployed by MDM/RMM tooling.

## Current Enterprise Endpoints

Admin endpoints:

```text
GET  /v1/enterprise/summary
GET  /v1/agents
GET  /v1/events?limit=100
GET  /v1/policies
POST /v1/policies/default
POST /v1/enrollment-token/rotate
```

Agent endpoints:

```text
POST /v1/agents/register
POST /v1/agents/:agent_id/heartbeat
POST /v1/events
GET  /v1/agent/policy
POST /v1/detect
```

Admin endpoints require:

```text
Authorization: Bearer <VAULTX_API_KEY>
```

Agent enrollment requires the enrollment token. After enrollment, endpoint
agents authenticate with unique laptop credentials:

```text
X-Agent-Id: <agent_id>
X-Agent-Token: <agent_token>
```

The admin API key is for administrators only and should not be placed on
employee laptops.

## Data Collection Policy

The default policy intentionally avoids browser history and file content
collection:

```text
file metadata: enabled
file contents: disabled
network metadata: enabled
browser history: disabled
```

This keeps the first enterprise version focused on auditable DLP signals rather
than invasive employee surveillance.

The current endpoint monitor reports metadata such as path hash, file name,
extension, size, action, process name, and rule names. It does not upload user
file contents.

## Next Engineering Steps

1. Add a Windows service wrapper for the endpoint agent.
2. Add per-department and per-agent policy assignment.
3. Add local file classification rules in the agent.
4. Add network destination classification in the agent.
5. Add tamper detection for agent shutdown/uninstall.
6. Add central database support instead of JSON state for multi-admin use.
7. Add SSO/admin login for the console.
8. Add TLS/reverse proxy deployment configuration.
9. Add signed, downloadable audit bundles to extend the implemented compliance
   readiness dashboard with formal auditor exports.
10. Replace HMAC policy signing with asymmetric Ed25519 signatures.

## Compliance Readiness

The admin console includes a Compliance page backed by `GET /v1/compliance`.
It evaluates live enterprise evidence against controls mapped to ISO/IEC 27001,
GDPR, and SOC 2. The readiness result is an operational aid and does not itself
constitute certification or legal advice.

## AI/ML Malicious Activity Detection

VAULT-X includes a lightweight model layer:

```text
server/ml_detector.py
```

Current behavior:

```text
extracts features from endpoint event details
scores risk with a weighted logistic model
stores verdict, score, feature values, and reasons
upgrades event severity for high/critical detections
shows ML verdicts in the admin console
```

Example event:

```json
{
  "type": "large_external_upload",
  "severity": "info",
  "agent_id": "agent-123",
  "details": {
    "process": "powershell",
    "destination": "https://unknown-upload.example",
    "upload_mb": 250,
    "path": "C:\\Users\\alice\\Documents\\finance.xlsx",
    "rule": "large upload of sensitive file"
  }
}
```

The model is intentionally replaceable. A future trained model can keep the same
`score_event()` interface and replace the current feature weights.
