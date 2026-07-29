# VAULT-X Enterprise Hardening Status

## Implemented in this release

- Credential reset is protected by a one-time-displayed offline recovery key.
- Recovery keys use PBKDF2-HMAC-SHA256 with a random salt and 600,000 iterations.
- Authentication events are written to the forward hash-chained audit ledger.
- Enterprise state uses transactional SQLite persistence with WAL and full-sync commits.
- Existing `enterprise_state.json` data is migrated automatically.
- Policy envelopes use Ed25519 asymmetric signatures and publish only the verification key.
- Compliance readiness includes transactional persistence and asymmetric signing evidence.
- The native application uses a random process-local dashboard credential after successful
  manual five-layer authentication.
- Security regression tests cover reset authorization, migration, signing, manual login,
  and compliance behavior.

## Integration-dependent controls

The following cannot be honestly completed by application code alone:

- Live LDAPS/Entra ID identity synchronization and production RBAC group mapping.
- Hardware-backed WebAuthn/FIDO2 authenticators and TPM device attestation.
- MDM-enforced anti-tamper, protected uninstall, and kernel-level DLP interception.
- HSM/KMS custody and rotation for production signing and encryption keys.
- TLS certificates, reverse proxy/WAF, centralized secrets, SIEM, and backup infrastructure.
- Signed Windows binaries/installers and an enterprise software-update channel.
- Independent ISO 27001, SOC 2, GDPR legal review, penetration testing, and certification.

Until those integrations and independent reviews are complete, describe this build as an
**enterprise-hardening reference implementation**, not a certified enterprise product.
