# VAULT-X Canonical System Flow

This document is the single canonical architecture for VAULT-X. Product features
and implementation work should follow this sequence.

```mermaid
flowchart TD
    A["User Request"] --> B["Authentication Gateway"]

    B --> C1["Password + TOTP"]
    B --> C2["Biometrics (Fingerprint + Retina)"]
    B --> C3["Behavioral Fingerprinting"]
    B --> C4["Zero Knowledge Proof"]
    B --> C5["Geofence"]

    C1 --> D{"After All 5 Layers Pass"}
    C2 --> D
    C3 --> D
    C4 --> D
    C5 --> D

    D -- "False" --> E["Access Denied: Lockout + Alert"]
    D -- "True" --> F["HSM Issues Session Key: Limited Time, Signed, No Transfer"]

    F --> G["Core: HSM + Key Derivation + All Crypto Operations"]
    G --> H["Encryption Pipeline: 5 Layers"]
    H --> I{"Operation Type"}

    I -- "Write" --> J["Encrypt + Store"]
    I -- "Read" --> K["Decrypt In HSM"]

    J --> L["Database Proxy Adapter: All Databases"]
    K --> L
    L --> M["Copy Detection: Continuous Monitoring"]
    M --> N{"Copy Attempt?"}

    N -- "Yes" --> O["Corruption Engine"]
    O --> P["Alert Generation"]

    N -- "No" --> Q["Data Served To User"]
    Q --> R{"Relocate Data?"}
    R -- "Yes" --> S["Relocation Protocol: Re-encrypt Fresh Key"]
    S --> Q
    R -- "No" --> T["Session Close"]
    T --> U["Immutable Audit Ledger"]

    V["Continuous Monitoring"] --> V1["Behavioral Analysis"]
    V --> V2["Canary Integrity"]
    V --> V3["Copy Detection"]
    V --> V4["Anomaly Alerts"]
    V --> V5["Network Traffic"]
    V --> V6["HSM Health"]
    V --> V7["Rate Limiting"]
    V --> V8["Session Timeout"]

    V1 -.-> D
    V2 -.-> H
    V3 -.-> M
    V4 -.-> P
    V5 -.-> P
    V6 -.-> G
    V7 -.-> B
    V8 -.-> T
```

## Implementation Status

| Flow block | Current status |
|---|---|
| Authentication gateway | Implemented |
| Password + TOTP | Implemented |
| Biometrics | Placeholder/passphrase adapter; real hardware integration required |
| Behavioral fingerprinting | Prototype implemented |
| Zero knowledge proof | Simplified local challenge-response implemented |
| Geofence/device check | Prototype implemented |
| All-five pass gate | Implemented |
| Lockout and alert | Implemented |
| HSM session key | Simulated in software; real HSM integration required |
| Core key derivation/crypto | Implemented in software |
| Five-layer encryption | Not implemented; current pipeline is canary + ChaCha20-Poly1305 + AES-GCM |
| Encrypt/store and decrypt | Implemented |
| Database proxy adapter | Not implemented |
| Continuous copy detection | Implemented for protected filesystem paths |
| Corruption engine | Prototype implemented in daemon response logic |
| Alert generation | Implemented through events/admin console |
| Data served to user | Implemented for vault operations |
| Relocation with fresh key | Implemented |
| Session close/timeout | Implemented |
| Immutable audit ledger | Implemented as append-only hash chain |
| Network traffic monitoring | Partial metadata/event support; real sensor required |
| HSM health monitoring | Not implemented until a real HSM is integrated |
| Rate limiting | Not implemented |

## Rule For Future Changes

New features should attach to one of the blocks above. The endpoint-agent and
admin-console components are operational surfaces around this canonical backend
flow; they do not replace or reorder its security stages.

