# VAULT-X Detailed Technical Report

## 1. Executive Summary

VAULT-X is a Python-based personal Data Loss Prevention (DLP) and secure vault application. Its purpose is to protect sensitive local files through multi-layer authentication, session-bound encryption, audit logging, relocation handling, and optional background folder monitoring.

The system is organized around a central command-line entry point, a GUI application, a core authentication gateway, a cryptographic vault engine, authentication layer implementations, a background daemon, an audit ledger, and a relocation protocol. The design goal is that a user must first pass all configured authentication checks before receiving a signed session token. That token is then required for encryption, decryption, and relocation operations.

At a high level, the project flow is:

```text
User Interface
  CLI: vaultx.py
  GUI: gui/vault_gui.py
        |
        v
Authentication Gateway
  core/auth_gateway.py
        |
        v
Authentication Layers
  layers/auth_layers.py
        |
        v
Vault Engine
  core/vault_engine.py
        |
        v
Encrypted Vault Artifacts
  my_vault/
```

The project also includes a daemon process that watches the vault directory for suspicious file activity and integrity changes:

```text
daemon/vault_daemon.py
        |
        v
my_vault/ monitoring
        |
        v
daemon_alerts.log + .daemon_state.json
```

## 2. Project Structure

```text
DLP/
|-- vaultx.py
|-- README.md
|-- requirements.txt
|-- core/
|   |-- auth_gateway.py
|   |-- vault_engine.py
|   |-- audit_ledger.py
|   |-- __init__.py
|-- layers/
|   |-- auth_layers.py
|   |-- __init__.py
|-- daemon/
|   |-- vault_daemon.py
|   |-- __init__.py
|-- gui/
|   |-- vault_gui.py
|   |-- __init__.py
|-- relocation/
|   |-- relocator.py
|   |-- __init__.py
|-- my_vault/
|   |-- .vault_master.key
|   |-- .vault_signing.key
|-- config/
|-- database/
|-- docs/
|-- monitoring/
|-- scripts/
|-- tests/
|-- ui/
```

Some packages such as `config`, `database`, `docs`, `monitoring`, `scripts`, `tests`, and `ui` currently contain only package initializer files. They appear reserved for future expansion.

## 3. Dependency Breakdown

The declared runtime dependencies are listed in `requirements.txt`:

```text
cryptography>=41.0.0
watchdog>=3.0.0
```

`cryptography` is required by the vault engine and authentication layers for encryption, key derivation, Ed25519 signing, hashing-related operations, AES-GCM, and ChaCha20-Poly1305.

`watchdog` is required by the daemon to subscribe to operating-system file events in the vault directory.

`tkinter` is used by the GUI. It is usually bundled with Python on Windows and is not listed as a pip dependency.

## 4. Main Entry Point: `vaultx.py`

### Responsibility

`vaultx.py` is the command-line interface for VAULT-X. It is the simplest way to set up the vault, log in, encrypt files, decrypt files, and view the audit log.

### Main Constants

```text
VAULT_DIR = "./my_vault"
```

This path is passed into `AuthGateway`, which then uses it for configuration, keys, audit data, and vault storage.

### Commands

`vaultx.py` supports:

```text
python vaultx.py setup
python vaultx.py login
python vaultx.py audit
python vaultx.py help
```

### Function Breakdown

#### `cmd_setup()`

Creates an `AuthGateway` for `./my_vault` and calls `gateway.setup()`.

Flow:

```text
cmd_setup()
  |
  v
AuthGateway("./my_vault")
  |
  v
gateway.setup()
```

#### `cmd_login()`

Starts an authenticated interactive vault session.

Flow:

```text
cmd_login()
  |
  v
AuthGateway("./my_vault")
  |
  v
gateway.login()
  |
  +-- returns None on failure
  |
  +-- returns SessionToken on success
        |
        v
interactive prompt:
  encrypt <file>
  decrypt <file>
  audit
  exit
```

Before each command inside the session, `gateway.vault.validate_session_token(token)` is called. If the token has expired, been revoked, gone idle too long, or fails validation, the session ends.

#### `_encrypt_file(vault, token, filepath)`

Reads the target file as bytes, passes the content to `vault.encrypt()`, and writes a JSON `.vault` file.

Flow:

```text
input file
  |
  v
read bytes
  |
  v
VaultEngine.encrypt(plaintext, token)
  |
  v
VaultBlob dataclass
  |
  v
JSON written to <filepath>.vault
```

#### `_decrypt_file(vault, token, filepath)`

Reads a `.vault` JSON file, rebuilds it as a `VaultBlob`, calls `vault.decrypt()`, and writes a `.decrypted` output file.

Flow:

```text
.vault JSON file
  |
  v
VaultBlob(**json_data)
  |
  v
VaultEngine.decrypt(blob, token)
  |
  v
plaintext bytes
  |
  v
<filepath>.decrypted
```

#### `cmd_audit()`

Creates an `AuthGateway` and prints recent audit entries without requiring a login session.

#### `cmd_help()`

Prints usage information and summarizes the authentication layers.

## 5. Authentication Orchestration: `core/auth_gateway.py`

### Responsibility

`AuthGateway` is the central authentication controller. It coordinates setup, login, lockout handling, audit logging, and issuing a vault session token after successful authentication.

### Configuration File

The gateway stores its configuration in:

```text
my_vault/vault_config.json
```

The default configuration contains:

```text
vault_version
setup_complete
owner_hash
totp_secret
biometric
behavioral
zkp_key
geofence
fail_log
audit_log
```

### Class: `AuthGateway`

#### Key Constants

```text
MAX_FAILURES = 3
LOCKOUT_HOURS = 72
CONFIG_FILENAME = "vault_config.json"
```

The system locks a device for 72 hours after 3 failed authentication attempts.

#### Initialization Flow

```text
AuthGateway(vault_dir)
  |
  v
create vault directory if missing
  |
  v
load or create vault_config.json
  |
  v
initialize VaultEngine
  |
  v
initialize all auth layer classes
  |
  v
if setup_complete:
    load stored layer configs
```

### Setup Flow

`setup()` registers all authentication layers.

```text
setup()
  |
  +-- Layer A: create TOTP secret, show otpauth URI, verify first code
  |
  +-- Layer B: collect passphrase, hash/store password data
  |
  +-- owner_hash: derive identity hash through VaultEngine
  |
  +-- Layer C: optionally calibrate behavioral typing profile
  |
  +-- Layer D: generate ZKP secret key
  |
  +-- Layer E: register current device fingerprint and optional allowed IPs
  |
  +-- mark setup_complete = True
  |
  v
save vault_config.json
```

### Login Flow

`login()` enforces the all-layers-must-pass rule.

```text
login()
  |
  v
check setup_complete
  |
  v
calculate current device fingerprint
  |
  v
check device lockout
  |
  v
Layer A: verify TOTP
  |
  v
Layer B: verify passphrase
  |
  v
Layer C: verify behavioral pattern
  |
  v
Layer D: generate challenge, prove, verify proof
  |
  v
Layer E: verify device and optional geofence
  |
  v
all(results.values())
  |
  +-- false:
  |     record failure
  |     audit LOGIN_FAILURE
  |     maybe trigger lockout
  |     return None
  |
  +-- true:
        reset failure counter
        create session token through VaultEngine
        audit LOGIN_SUCCESS
        return SessionToken
```

### Lockout Handling

The lockout mechanism is per device fingerprint.

```text
fail_log[device_hash] = {
  "count": int,
  "lockout_until": float
}
```

Every failed login increments the count. At 3 failures, `lockout_until` is set to the current time plus 72 hours.

### Audit Handling

`AuthGateway` maintains a simplified audit log directly inside `vault_config.json`. It records login success, login failure, and lockout events. It keeps the last 1000 entries.

## 6. Authentication Layers: `layers/auth_layers.py`

This module implements five authentication factors.

## 6.1 Layer A: `TOTPLayer`

### Purpose

Implements Time-Based One-Time Password authentication. This is the phone-app layer used with Google Authenticator/Authy-style apps.

### Key Methods

```text
__init__(secret=None)
get_code(timestamp=None)
verify(user_code, window=1)
get_qr_uri(account_name="VAULT-X Owner")
export_secret()
from_secret(secret_b64)
```

### Flow

```text
setup:
  generate random secret
  create otpauth URI
  user scans/adds secret to authenticator
  user enters current 6-digit code
  verify code
  store exported secret

login:
  user enters 6-digit code
  verify against current TOTP window
```

The verifier accepts a small time window around the current time to account for clock drift.

## 6.2 Layer B: `BiometricLayer`

### Purpose

Despite the name, this implementation currently acts as a passphrase layer. It is structured so it could later be replaced by a fingerprint reader or hardware biometric device.

### Key Methods

```text
register(password)
load(stored)
verify(password)
```

### Flow

```text
setup:
  collect passphrase twice
  enforce minimum quality rules
  store hash material

login:
  collect passphrase
  verify against stored hash
```

## 6.3 Layer C: `BehavioralLayer`

### Purpose

Implements behavioral fingerprinting based on typing rhythm.

### Key Constants

```text
PASS_THRESHOLD = 0.70
MIN_SAMPLES = 5
```

### Key Methods

```text
collect_timing_sample(prompt)
calibrate(n_samples=5)
load(baseline)
verify(timings=None)
```

### Flow

```text
setup:
  user types fixed phrase several times
  timing samples are collected
  baseline statistics are stored

login:
  user types phrase again
  timings are compared to baseline
  score >= threshold means pass
```

The fixed phrase used by the module is:

```text
vault-x secure personal data system
```

If no behavioral baseline exists, the layer may auto-pass, based on the implementation comments and behavior.

## 6.4 Layer D: `ZKPLayer`

### Purpose

Implements a local challenge-response proof mechanism. It is described as a simplified zero-knowledge proof layer.

### Key Constant

```text
WINDOW_SECONDS = 60
```

### Key Methods

```text
generate_challenge()
prove(challenge)
verify_proof(challenge, proof)
export_key()
from_key(key_b64)
```

### Flow

```text
setup:
  generate secret key
  store exported key

login:
  generate challenge
  compute proof locally
  verify proof
  reject expired challenge
```

## 6.5 Layer E: `GeofenceLayer`

### Purpose

Verifies that login occurs from a registered device and, optionally, an allowed IP address.

### Key Methods

```text
register_device(device_hash)
add_allowed_ip(ip)
get_current_ip()
verify(device_hash)
export()
load(data)
```

### Flow

```text
setup:
  calculate current device fingerprint
  register it as trusted
  optionally collect allowed IP addresses

login:
  calculate current device fingerprint
  verify it is registered
  optionally compare current IP with allowed IP list
```

## 7. Vault Engine: `core/vault_engine.py`

### Responsibility

`VaultEngine` is the cryptographic and session-management core. It handles:

```text
master key creation/loading
signing key creation/loading
device fingerprinting
session key derivation
session token creation and validation
dual-layer encryption
decryption
canary byte injection and verification
active session tracking
```

### Important Constants

```text
KEY_SIZE = 32
SESSION_HOURS = 8
IDLE_MINUTES = 10
VAULT_VERSION = "1.0.0"
```

### Data Structure: `SessionToken`

Represents an authenticated session.

Fields:

```text
session_id
owner_hash
device_hash
issued_at
expires_at
last_active
scope
signature
```

The token is signed with Ed25519 and is stored in the engine's in-memory active session map.

### Data Structure: `VaultBlob`

Represents an encrypted object stored on disk as JSON.

Fields:

```text
blob_id
session_id
chacha_nonce
aes_nonce
chacha_ciphertext
aes_ciphertext
canary_hash
created_at
vault_version
```

### Device Fingerprint

`get_device_fingerprint()` hashes together:

```text
hostname
machine architecture
processor info
MAC address integer
operating system
```

This binds session validation to the current machine.

### Initialization Flow

```text
VaultEngine(vault_dir)
  |
  v
set key file paths
  |
  v
create vault directory if missing
  |
  v
load or create .vault_master.key
  |
  v
load or create .vault_signing.key
  |
  v
initialize active session map
```

### Master Key Handling

The master key is stored as:

```text
my_vault/.vault_master.key
```

If missing, a new 32-byte random key is generated.

### Signing Key Handling

The Ed25519 signing key is stored as:

```text
my_vault/.vault_signing.key
```

If missing, a new Ed25519 private key is generated.

### Session Token Creation

```text
create_session_token(owner_hash, scope=None)
  |
  v
generate random session_id
  |
  v
calculate device_hash
  |
  v
build token payload
  |
  v
sign payload with Ed25519 private key
  |
  v
derive session key
  |
  v
store session token + session key in memory
  |
  v
return SessionToken
```

Default scope:

```text
["read", "write", "relocate"]
```

### Session Validation

`validate_session_token(token)` checks:

```text
1. Token exists in active sessions
2. Token has not expired
3. Token has not exceeded idle timeout
4. Device fingerprint matches current device
5. Ed25519 signature verifies
```

If valid, `last_active` is updated.

### Session Revocation

`revoke_session(session_id)` removes the active session and overwrites the stored session key value with zero bytes before discarding it.

### Encryption Flow

`encrypt(plaintext, token)` performs:

```text
validate session token
  |
  v
retrieve session key
  |
  v
inject canary bytes
  |
  v
encrypt canary data with ChaCha20-Poly1305
  |
  v
derive AES key from session key using HKDF
  |
  v
encrypt ChaCha ciphertext with AES-256-GCM
  |
  v
return VaultBlob
```

Detailed pipeline:

```text
plaintext
  |
  v
canary injection
  |
  v
ChaCha20-Poly1305 encryption
  |
  v
AES-256-GCM encryption
  |
  v
VaultBlob JSON fields
```

### Decryption Flow

`decrypt(blob, token)` performs:

```text
validate session token
  |
  v
retrieve session key
  |
  v
derive AES key
  |
  v
AES-256-GCM decrypt
  |
  v
ChaCha20-Poly1305 decrypt
  |
  v
verify canary fingerprint
  |
  v
remove canary bytes
  |
  v
return plaintext
```

Detailed reverse pipeline:

```text
VaultBlob
  |
  v
AES-GCM decrypt
  |
  v
ChaCha20-Poly1305 decrypt
  |
  v
canary verification
  |
  v
canary removal
  |
  v
plaintext
```

## 8. Audit Ledger: `core/audit_ledger.py`

### Responsibility

This module implements an append-only JSONL audit ledger with hash chaining. It is separate from the simplified audit list stored in `vault_config.json`.

### Class: `LedgerEntry`

Fields:

```text
index
event_type
details
timestamp
unix_ts
prev_hash
entry_hash
signature
```

Each entry computes a SHA-256 hash over its core fields. If a signer function is provided, the entry can also store a signature.

### Class: `AuditLedger`

Important constants:

```text
LEDGER_FILE = "vault_audit.jsonl"
GENESIS_HASH = "0" * 64
```

### Flow

```text
AuditLedger(vault_dir)
  |
  v
load last entry state
  |
  v
log(event_type, details)
  |
  v
append JSON line with prev_hash and entry_hash
```

### Chain Verification

`verify_chain()` checks:

```text
entry indexes are sequential
each prev_hash matches the previous entry hash
each entry hash recomputes correctly
```

### Export

`export_for_audit(output_path)` exports all entries into a structured JSON file with metadata.

## 9. Background Protection Daemon: `daemon/vault_daemon.py`

### Responsibility

The daemon is designed to run continuously and protect the vault directory even when the user is not actively logged in.

It monitors:

```text
.vault files
.vault_master.key
.vault_signing.key
vault_config.json
```

### Important Paths

```text
VAULT_DIR = <project>/my_vault
PID_FILE = my_vault/.daemon.pid
ALERT_LOG = my_vault/daemon_alerts.log
STATE_FILE = my_vault/.daemon_state.json
```

### Timing Constants

```text
POLL_INTERVAL = 300
KEY_CHECK_SECS = 60
```

Blob integrity is polled every 5 minutes. Master/signing key health is checked every 60 seconds.

### Class: `VaultState`

Tracks checksums for protected files.

Responsibilities:

```text
load persisted daemon state
save daemon state
snapshot protected files
hash files
hash key files
check key file integrity
check blob integrity
register authorized file changes
remove deleted file entries
```

State is persisted in:

```text
my_vault/.daemon_state.json
```

### Class: `VaultFolderWatcher`

Extends `FileSystemEventHandler` from `watchdog`.

Handles:

```text
on_created
on_modified
on_moved
```

Its purpose is to detect:

```text
external copy/paste into vault directory
external modification of .vault files
movement of protected files
possible ransomware-style tampering
```

### Function: `secure_wipe(path, passes=3)`

Overwrites a file multiple times and deletes it. The default is 3 passes.

### Class: `VaultDaemon`

Coordinates the monitoring process.

Startup flow:

```text
VaultDaemon.start()
  |
  v
write PID file
  |
  v
take initial VaultState snapshot
  |
  v
start watchdog observer if available
  |
  v
start integrity polling thread
  |
  v
start key health check thread
  |
  v
loop until stopped
```

Thread responsibilities:

```text
watchdog observer:
  live file create/modify/move events

integrity poll thread:
  periodic checksum verification for protected blobs

key health thread:
  periodic combined hash check of master/signing keys
```

### Daemon CLI Commands

```text
python daemon/vault_daemon.py start
python daemon/vault_daemon.py stop
python daemon/vault_daemon.py status
```

## 10. GUI Application: `gui/vault_gui.py`

### Responsibility

The GUI provides a desktop interface for login, dashboard status, file operations, audit viewing, daemon monitoring, and logout.

It is built using `tkinter`.

### Main UI Classes

```text
LoginScreen
DashboardPanel
FileVaultPanel
AuditPanel
ThreatMonitorPanel
VaultXApp
```

### Helper Functions

```text
styled_btn()
_lighten()
card()
sep()
lbl()
entry()
```

These are UI utility functions for styling buttons, labels, entries, cards, and separators.

### Class: `LoginScreen`

Handles GUI authentication input and visual layer progress.

Key methods:

```text
_build()
_set_layer()
_start_login()
_run_auth(totp, pwd)
```

The GUI login flow is similar to CLI login, but it updates the interface as layers pass or fail. It creates an `AuthGateway`, validates setup, and then proceeds through authentication.

### Class: `DashboardPanel`

Displays high-level system and session information.

Key methods:

```text
_build()
_refresh()
```

It refreshes periodically using `after(1000, ...)`.

### Class: `FileVaultPanel`

Handles encrypt, decrypt, relocate, and vault file listing actions.

Key methods:

```text
_browse_encrypt()
_browse_decrypt()
_browse_src()
_browse_dst()
_encrypt()
_decrypt()
_relocate()
_refresh_files()
```

Flow:

```text
select file
  |
  v
call app.gateway.vault.encrypt/decrypt
  |
  v
write output file
  |
  v
refresh file list
```

### Class: `AuditPanel`

Displays and verifies audit information.

Key methods:

```text
_build()
_refresh()
_verify()
_export()
```

### Class: `ThreatMonitorPanel`

Controls and displays daemon status and alerts.

Key methods:

```text
_build()
_update_daemon_status()
_refresh_alerts()
_start_daemon()
_stop_daemon()
_clear_alerts()
_auto_refresh()
```

It uses subprocess calls to start and stop the daemon.

### Class: `VaultXApp`

Main Tk application class.

Key methods:

```text
_show_login()
_run_setup_cmd()
_on_login_success(token, gateway)
_build_main_ui()
_build_sidebar()
show_panel(name)
_logout()
```

Application flow:

```text
start GUI
  |
  v
show login screen
  |
  +-- setup button opens CLI setup command
  |
  +-- successful login stores token + gateway
        |
        v
      build main UI
        |
        v
      dashboard / files / audit / threat monitor
```

## 11. Relocation Protocol: `relocation/relocator.py`

### Responsibility

The relocation module moves an encrypted vault blob from one location to another while attempting to remove correlation between the old and new encrypted versions.

### Class: `RelocationRecord`

Stores metadata for a completed relocation.

Fields:

```text
old_blob_id
new_blob_id
old_path_hash
new_path_hash
wipe_passes
wipe_verified
relocated_at
session_id
```

### Class: `LocationRegistry`

Tracks expected paths for blobs using hashes of absolute paths.

Key methods:

```text
register(blob_id, path)
remove(blob_id)
verify_location(blob_id, path)
```

### Function: `secure_wipe(path, passes=3)`

Overwrites the old file with zeroes, ones, and random data before deleting it.

### Class: `Relocator`

Key method:

```text
relocate(old_path, new_path, token, wipe_passes=3)
```

Relocation flow:

```text
read old VaultBlob
  |
  v
decrypt old blob with current session token
  |
  v
create fresh write-only session token
  |
  v
encrypt plaintext into new VaultBlob
  |
  v
write new blob to new path
  |
  v
register new location
  |
  v
revoke fresh session
  |
  v
secure-wipe old path
  |
  v
remove old registry entry
  |
  v
return RelocationRecord
```

## 12. Vault Data Artifacts

The vault directory stores sensitive operational data.

Expected files include:

```text
my_vault/.vault_master.key
my_vault/.vault_signing.key
my_vault/vault_config.json
my_vault/daemon_alerts.log
my_vault/.daemon_state.json
my_vault/.daemon.pid
my_vault/vault_audit.jsonl
```

Not every file exists at all times. Some are created by setup, some by the daemon, and some by the audit ledger.

### `.vault_master.key`

Root secret used by `VaultEngine` to derive session keys and identity hashes.

### `.vault_signing.key`

Ed25519 private key used to sign session token payloads.

### `vault_config.json`

Main authentication and audit configuration file.

### `.vault` Files

JSON representations of `VaultBlob` objects. They contain ciphertext, nonces, canary hash, blob ID, session ID, and vault version.

## 13. End-to-End Setup Flow

```text
User runs:
  python vaultx.py setup

vaultx.py
  |
  v
AuthGateway.setup()
  |
  +-- creates/loads vault directory
  +-- creates/loads master key
  +-- creates/loads signing key
  +-- registers TOTP
  +-- registers passphrase
  +-- calculates owner hash
  +-- optionally calibrates typing behavior
  +-- generates ZKP key
  +-- registers device fingerprint
  +-- optionally records allowed IPs
  |
  v
write vault_config.json
```

## 14. End-to-End Login Flow

```text
User runs:
  python vaultx.py login

vaultx.py
  |
  v
AuthGateway.login()
  |
  +-- check setup status
  +-- check device lockout
  +-- verify TOTP
  +-- verify passphrase
  +-- verify typing rhythm
  +-- verify ZKP challenge
  +-- verify device/geofence
  |
  v
if all pass:
  VaultEngine.create_session_token()
  return SessionToken

if any fail:
  record failed attempt
  maybe trigger lockout
  return None
```

## 15. End-to-End Encryption Flow

```text
User enters:
  vault> encrypt secret.txt

vaultx.py
  |
  v
_encrypt_file()
  |
  +-- read secret.txt as bytes
  +-- call VaultEngine.encrypt(plaintext, token)
  |
  v
VaultEngine.encrypt()
  |
  +-- validate session token
  +-- inject canary bytes
  +-- ChaCha20-Poly1305 encrypt
  +-- AES-256-GCM encrypt
  +-- create VaultBlob
  |
  v
write:
  secret.txt.vault
```

## 16. End-to-End Decryption Flow

```text
User enters:
  vault> decrypt secret.txt.vault

vaultx.py
  |
  v
_decrypt_file()
  |
  +-- read JSON
  +-- reconstruct VaultBlob
  +-- call VaultEngine.decrypt(blob, token)
  |
  v
VaultEngine.decrypt()
  |
  +-- validate session token
  +-- AES-GCM decrypt
  +-- ChaCha20 decrypt
  +-- verify canary hash
  +-- remove canaries
  |
  v
write:
  secret.txt.decrypted
```

## 17. End-to-End Daemon Flow

```text
User runs:
  python daemon/vault_daemon.py start

VaultDaemon.start()
  |
  +-- write .daemon.pid
  +-- snapshot protected files
  +-- start watchdog observer
  +-- start integrity poll thread
  +-- start key health thread
  |
  v
running protection loop
```

Event handling:

```text
file created/modified/moved
  |
  v
VaultFolderWatcher event method
  |
  v
VaultDaemon.respond()
  |
  v
write alert to daemon_alerts.log
```

## 18. Security Design Summary

The security design combines several ideas:

```text
multi-factor authentication
device-bound login
session-bound encryption
signed session tokens
idle and absolute session expiry
dual authenticated encryption layers
canary-based tamper detection
daemon-based integrity monitoring
append-only audit ledger
secure relocation with wipe
```

### Authentication Strengths

The login flow requires all configured layers to pass. A failure in any layer denies access. The device lockout system adds brute-force resistance.

### Encryption Strengths

The vault uses modern authenticated encryption primitives:

```text
ChaCha20-Poly1305
AES-256-GCM
HKDF
Ed25519
PBKDF2-HMAC-SHA256
```

### Monitoring Strengths

The daemon watches protected files and can detect external changes, key tampering, and suspicious file movements.

## 19. Important Implementation Observations

### 19.1 Session-Derived Encryption Has Operational Consequences

Encrypted blobs include the `session_id` from the session used to create them. The actual session key is stored only in memory in `VaultEngine._active_sessions`. This means decryption of a blob depends on having the right active session context available. If the original session is gone, the implementation must be carefully reviewed to ensure older blobs remain decryptable as intended.

### 19.2 GUI and CLI Share the Same Core

Both interfaces rely on `AuthGateway` and `VaultEngine`. This is a good separation: authentication and encryption logic are not duplicated in the UI.

### 19.3 Two Audit Mechanisms Exist

There is a simplified audit list in `vault_config.json` and a stronger append-only hash-chain ledger in `core/audit_ledger.py`. A future cleanup could unify these so all security-relevant events go through the stronger ledger.

### 19.4 Some Folders Are Placeholders

Several packages are present but currently empty or nearly empty:

```text
config
database
docs
monitoring
scripts
tests
ui
```

These appear to be planned expansion areas.

### 19.5 Encoding Appears Corrupted in Comments/Strings

Several source and documentation files contain mojibake-style characters where box drawing, arrows, checkmarks, or punctuation were likely intended. The code may still run, but documentation and terminal output readability is affected.

## 20. Suggested Future Improvements

1. Add automated tests for setup, login failure, login success, token expiry, encryption, decryption, daemon state, and relocation.
2. Clarify persistence model for encrypted blobs created under session-derived keys.
3. Route all audit events through `AuditLedger` instead of maintaining two audit systems.
4. Add a recovery/export strategy for vault configuration and key backup.
5. Fix text encoding across source comments, banners, and README content.
6. Add structured logging instead of relying mainly on print statements.
7. Add threat-model documentation explaining what the system protects against and what it does not.
8. Validate daemon stop behavior across Windows and Linux.
9. Add clear separation between demo/simplified authentication layers and production-ready replacements.
10. Add integration documentation for real hardware keys, biometric readers, and HSM-backed key storage.

## 21. Final Architecture Summary

VAULT-X is best understood as a layered security application:

```text
Presentation Layer
  vaultx.py
  gui/vault_gui.py

Authentication Orchestration Layer
  core/auth_gateway.py

Authentication Factor Layer
  layers/auth_layers.py

Cryptographic Vault Layer
  core/vault_engine.py

Monitoring and Response Layer
  daemon/vault_daemon.py

Audit and Accountability Layer
  core/audit_ledger.py

Relocation and Secure Movement Layer
  relocation/relocator.py

Vault Storage Layer
  my_vault/
```

The central application process is:

```text
setup security layers
  |
  v
authenticate user and device
  |
  v
issue signed session token
  |
  v
allow vault operations while token is valid
  |
  v
encrypt/decrypt/relocate files
  |
  v
audit and monitor vault activity
```

