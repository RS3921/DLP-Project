# VAULT-X — Personal Data Vault
## Complete Beginner Setup Guide

---

## What Is This?

VAULT-X is a personal data vault that protects your files using
**5 independent layers of authentication** and **dual-layer encryption**.

Even if someone physically steals your computer, they cannot read
your vault files without passing all 5 security layers.

---

## What You Need

| Requirement | Details |
|---|---|
| Python 3.10 or newer | Download from python.org |
| A smartphone | For Google Authenticator |
| Google Authenticator app | Free on iOS and Android |
| 5 minutes | For initial setup |

**Optional hardware upgrades (buy later):**
| Hardware | Cost | Replaces |
|---|---|---|
| YubiKey 5 NFC | ~$50 | TOTP → Real FIDO2 hardware key |
| USB Fingerprint Reader | ~$30 | Password → Real fingerprint scan |

---

## Step 1 — Install Python

1. Go to **https://python.org/downloads**
2. Download Python 3.11 or 3.12
3. Install it (check "Add to PATH" on Windows)
4. Open Terminal (Mac/Linux) or Command Prompt (Windows)
5. Type: `python --version`
   - You should see: `Python 3.11.x` or similar

---

## Step 2 — Download VAULT-X

Save all these files in one folder. For example:
```
C:\Users\YourName\vaultx\          (Windows)
/home/yourname/vaultx/             (Linux/Mac)
```

Your folder should look like:
```
vaultx/
├── vaultx.py              ← main program (run this)
├── requirements.txt       ← list of libraries needed
├── core/
│   ├── vault_engine.py    ← encryption engine
│   └── auth_gateway.py    ← authentication controller
└── layers/
    └── auth_layers.py     ← the 5 security layers
```

---

## Step 3 — Install Libraries

Open Terminal / Command Prompt, go to your folder:

```bash
# Go to your vault folder
cd /path/to/vaultx        # Mac/Linux
cd C:\Users\YourName\vaultx  # Windows

# Install required libraries
pip install -r requirements.txt
```

You should see output like:
```
Installing cryptography...
Successfully installed cryptography-41.0.0
```

---

## Step 4 — First-Time Setup

Run:
```bash
python vaultx.py setup
```

This will guide you through registering all 5 layers:

### Layer A — TOTP Setup
1. Install **Google Authenticator** on your phone (free)
2. The setup will show you a link — paste it into https://www.qr-code-generator.com/
3. Scan the QR code with Google Authenticator
4. Type the 6-digit code shown in the app
5. Done! ✓

### Layer B — Passphrase
1. Choose a strong passphrase (minimum 12 characters)
2. Use a phrase you can remember: `PurpleCloud$Runs9Over`
3. Write it on paper and keep it somewhere safe (NOT on your computer)
4. Type it twice to confirm
5. Done! ✓

### Layer C — Behavioral Fingerprint
1. You will type a short phrase 5 times
2. Type naturally — don't try to be consistent
3. The system records your natural typing rhythm
4. Done! ✓

### Layer D — Zero-Knowledge Proof
- Automatic. A key is generated for you.
- Nothing to do. ✓

### Layer E — Device Binding
- Automatic. Your computer's hardware is registered.
- Optional: enter your home IP address for geofencing.
- Done! ✓

---

## Step 5 — Daily Use

### Log In
```bash
python vaultx.py login
```
You'll be asked for your TOTP code and passphrase.
After all 5 layers pass, you get a vault session.

### Encrypt a File
Inside the vault session, type:
```
vault> encrypt mysecretfile.txt
```
This creates `mysecretfile.txt.vault` — the encrypted version.
The `.vault` file is safe to store anywhere (cloud, USB, etc.)

### Decrypt a File
```
vault> decrypt mysecretfile.txt.vault
```
This creates `mysecretfile.txt.decrypted` with the original content.

### View Audit Log
```
vault> audit
```
Shows who logged in, when, and what happened.

### Exit
```
vault> exit
```

---

## Server Mode

VAULT-X can also run as a local HTTP service for server-side automation:

```bash
set VAULTX_API_KEY=replace-with-a-long-random-secret
python vaultx.py serve
```

Default server URL:
```text
http://127.0.0.1:8765
```

Server mode includes JSON endpoints for health checks, service sessions,
file encryption/decryption, in-memory payload encryption/decryption, and audit
viewing. See:

```text
docs/SERVER_DEPLOYMENT.md
```

---

## Security Rules

| Rule | Why |
|---|---|
| Back up your `my_vault/` folder | This contains your master key — lose it, lose everything |
| Never share your passphrase | Not even with family or tech support |
| Store your passphrase offline | On paper in a safe — not in a notes app |
| Keep your phone safe | Your TOTP codes are on it |
| 3 failed logins = 72-hour lockout | Normal security feature, not a bug |

---

## Troubleshooting

### "Module not found" error
Run: `pip install -r requirements.txt`

### "TOTP code incorrect"
- Make sure your phone's clock is accurate
- You have a 30-second window — try again after the code refreshes

### "Locked out for 72 hours"
- This happens after 3 failed login attempts
- Wait for the lockout to expire
- Check your passphrase is spelled correctly
- Make sure you have the right Google Authenticator entry

### "Setup not complete"
- Run `python vaultx.py setup` first

---

## Upgrade Path (When Ready)

| When | What to Buy | What It Replaces | Difficulty |
|---|---|---|---|
| Month 1 | YubiKey 5 ($50) | Google Authenticator | Easy |
| Month 2 | USB Fingerprint reader ($30) | Password | Medium |
| Month 3 | Add CRYSTALS-Kyber | Current encryption | Hard |
| Month 6 | SoftHSM2 (free) | Software key storage | Hard |

---

## File Structure After Setup

```
my_vault/                          ← your vault folder
├── .vault_master.key              ← MASTER KEY (never share, back up!)
├── .vault_signing.key             ← signing key (never share)
└── vault_config.json              ← layer configs + audit log
```

**IMPORTANT:** Back up the `my_vault/` folder to an encrypted USB drive.
If you lose `.vault_master.key`, all your encrypted files are permanently unreadable.

---

## What Each File Does

| File | What It Does |
|---|---|
| `vaultx.py` | The main program. Run this. |
| `core/vault_engine.py` | Encryption: ChaCha20 + AES-256-GCM pipeline |
| `core/auth_gateway.py` | Login orchestrator: runs all 5 layers |
| `layers/auth_layers.py` | The 5 individual security layers |
| `requirements.txt` | Python libraries to install |

---

*VAULT-X v1.0.0 — Personal Data Vault*
*5-Layer Authentication · Dual-Layer Encryption · Session Binding*
