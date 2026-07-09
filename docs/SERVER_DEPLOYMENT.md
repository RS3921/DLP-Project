# VAULT-X Server Deployment Guide

## Overview

VAULT-X now includes a lightweight HTTP service for server-style deployments.
It exposes JSON endpoints for health checks, vault status, short-lived service
sessions, file encryption/decryption, in-memory payload encryption/decryption,
and audit viewing.

The service uses Python's standard library HTTP server, so no additional web
framework is required.

## Security Model

The server API is protected by a bearer API key:

```text
Authorization: Bearer <VAULTX_API_KEY>
```

By default the service binds to `127.0.0.1`, which is the safest mode for a
local agent, reverse proxy, or same-host automation. Avoid binding directly to
`0.0.0.0` unless the host firewall, TLS termination, and API key handling are
properly configured.

Server mode creates service sessions using the existing vault owner hash after
the API key is accepted. Treat `VAULTX_API_KEY` like an administrative secret.

## Start The Server

PowerShell:

```powershell
$env:VAULTX_API_KEY = "replace-with-a-long-random-secret"
python vaultx.py serve
```

Equivalent module form:

```powershell
$env:VAULTX_API_KEY = "replace-with-a-long-random-secret"
python -m server.vault_server
```

Custom host and port:

```powershell
python vaultx.py serve --host 127.0.0.1 --port 8765
```

Custom vault and data roots:

```powershell
python vaultx.py serve `
  --vault-dir C:\vaultx\my_vault `
  --data-root C:\vaultx\data
```

## Environment Variables

```text
VAULTX_API_KEY     Required bearer token for API access
VAULTX_HOST        Optional host, default 127.0.0.1
VAULTX_PORT        Optional port, default 8765
VAULTX_VAULT_DIR   Optional vault directory, default ./my_vault
VAULTX_DATA_ROOT   Optional file operation root, default project root
VAULTX_LOG_LEVEL   Optional logging level, default INFO
```

## Health Check

No authentication is required:

```powershell
Invoke-RestMethod http://127.0.0.1:8765/health
```

Response:

```json
{
  "ok": true,
  "service": "vaultx"
}
```

## Authenticated Status

```powershell
$headers = @{ Authorization = "Bearer $env:VAULTX_API_KEY" }
Invoke-RestMethod http://127.0.0.1:8765/v1/status -Headers $headers
```

## Create A Service Session

```powershell
$headers = @{ Authorization = "Bearer $env:VAULTX_API_KEY" }
$session = Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8765/v1/session `
  -Headers $headers `
  -Body '{"scope":["read","write","relocate"]}' `
  -ContentType "application/json"
```

Use the returned `session_id` in the `X-Vault-Session` header.

## Encrypt A File

The input and output paths must stay inside `VAULTX_DATA_ROOT`.

```powershell
$headers = @{
  Authorization = "Bearer $env:VAULTX_API_KEY"
  "X-Vault-Session" = $session.session_id
}

Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8765/v1/encrypt-file `
  -Headers $headers `
  -Body '{"input_path":"secret.txt"}' `
  -ContentType "application/json"
```

This writes `secret.txt.vault`.

## Decrypt A File

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8765/v1/decrypt-file `
  -Headers $headers `
  -Body '{"input_path":"secret.txt.vault"}' `
  -ContentType "application/json"
```

This writes `secret.txt.decrypted`.

## Encrypt An In-Memory Payload

```powershell
$payload = @{
  data_b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("hello vault"))
} | ConvertTo-Json

Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8765/v1/encrypt `
  -Headers $headers `
  -Body $payload `
  -ContentType "application/json"
```

## Decrypt An In-Memory Payload

Send the `blob` object returned by `/v1/encrypt`:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8765/v1/decrypt `
  -Headers $headers `
  -Body '{"blob":{...}}' `
  -ContentType "application/json"
```

The response contains `data_b64`.

## View Audit Events

```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8765/v1/audit?limit=25" `
  -Headers @{ Authorization = "Bearer $env:VAULTX_API_KEY" }
```

## Revoke A Session

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8765/v1/session/revoke `
  -Headers $headers
```

## Recommended Production Shape

For a stronger deployment:

```text
reverse proxy with TLS
host firewall limiting source IPs
long random VAULTX_API_KEY from a secret manager
VAULTX_HOST=127.0.0.1 behind the proxy
dedicated OS user for the service
restricted filesystem permissions on my_vault
regular encrypted backup of my_vault
daemon enabled for protected folder monitoring
central log collection for JSON service logs
```

