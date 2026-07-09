# VAULT-X Active Directory Integration Plan

## Core Idea

Windows Server Active Directory should remain the source of truth for:

```text
users
computers
groups
organizational units
enabled/disabled state
department ownership
```

VAULT-X should not replace AD user/computer management. Instead, VAULT-X should
read from AD and use AD data to decide:

```text
which laptop belongs to which user
which OU the laptop belongs to
which department owns the device
which DLP policy should apply
whether the laptop agent should be trusted or revoked
```

## Recommended Architecture

```text
Windows Server / Active Directory
  |
  | LDAP / LDAPS read-only sync
  v
VAULT-X Admin Server
  |
  | policy assignment
  | agent enrollment validation
  | event correlation
  v
Employee Laptop Agent
```

## What AD Should Manage

Use AD for:

```text
creating users
removing users
disabling users
joining computers to domain
moving computers between OUs
assigning security groups
department structure
GPO deployment
```

Use VAULT-X for:

```text
DLP policy assignment
endpoint agent identity
activity monitoring
malicious activity detection
event logging
admin security dashboard
agent revocation
alerts
```

## OU-To-Policy Mapping

Create DLP policies based on OU or AD group.

Example:

```text
OU=Finance,DC=company,DC=local
  -> Finance-DLP-Policy

OU=Engineering,DC=company,DC=local
  -> Engineering-DLP-Policy

OU=HR,DC=company,DC=local
  -> HR-DLP-Policy

CN=Privileged-Users,OU=Groups,DC=company,DC=local
  -> High-Security-DLP-Policy
```

VAULT-X should store this mapping:

```json
{
  "ou_policy_map": {
    "OU=Finance,DC=company,DC=local": "finance_policy",
    "OU=Engineering,DC=company,DC=local": "engineering_policy",
    "OU=HR,DC=company,DC=local": "hr_policy"
  }
}
```

## Laptop Enrollment Flow With AD

```text
1. Admin deploys VAULT-X agent by GPO/Intune/manual installer.
2. Agent starts on employee laptop.
3. Agent sends hostname/domain/device metadata to VAULT-X.
4. VAULT-X queries AD for computer object:
     sAMAccountName = HOSTNAME$
5. VAULT-X reads:
     distinguishedName
     operatingSystem
     memberOf
     managedBy
     enabled/disabled state
6. VAULT-X maps OU/group to DLP policy.
7. VAULT-X issues agent_id + agent_token.
8. Agent stores credentials locally.
9. Agent uses its token for heartbeat/events.
```

## User Mapping

Best options:

```text
Option 1: Map laptop to AD computer object and managedBy user.
Option 2: Agent reports currently logged-in domain user.
Option 3: Combine both for better accuracy.
```

Example agent metadata:

```json
{
  "hostname": "LAPTOP-042",
  "domain": "COMPANY",
  "logged_in_user": "COMPANY\\raveena",
  "user_sid": "S-1-5-21-...",
  "computer_sam": "LAPTOP-042$"
}
```

VAULT-X can then show:

```text
Device: LAPTOP-042
User: raveena@company.local
OU: Finance
Policy: Finance-DLP-Policy
Status: Online
```

## Revocation Flow

If AD disables or removes a computer:

```text
AD computer disabled/deleted
  |
  v
VAULT-X AD sync detects change
  |
  v
VAULT-X revokes agent token
  |
  v
agent heartbeat rejected
  |
  v
admin UI shows revoked/offline device
```

If a user is disabled:

```text
AD user disabled
  |
  v
VAULT-X marks user inactive
  |
  v
devices assigned to that user are flagged
  |
  v
admin reviews or revokes device access
```

## Deployment With GPO

Use Group Policy to deploy:

```text
VAULT-X agent files
agent config
server URL
enrollment token or bootstrap token
Windows service registration
```

Recommended GPO startup script:

```powershell
python -m agent.vaultx_agent enroll --server https://vaultx.company.local --enrollment-token <bootstrap-token>
python -m agent.vaultx_agent install-service
```

The final version should package this as an MSI or signed installer.

## Secure AD Connection

Use LDAPS, not plain LDAP.

```text
LDAP  = port 389, unencrypted unless StartTLS
LDAPS = port 636, encrypted
```

Recommended:

```text
ldaps://dc01.company.local:636
```

Use a read-only service account:

```text
svc-vaultx-ad-reader
```

Permissions:

```text
read users
read computers
read groups
read OUs
no write permission required
```

## Admin Login

For admin login, use AD groups:

```text
CN=VAULTX-Admins,OU=Security Groups,DC=company,DC=local
CN=VAULTX-Analysts,OU=Security Groups,DC=company,DC=local
CN=VAULTX-Auditors,OU=Security Groups,DC=company,DC=local
```

Role mapping:

```text
VAULTX-Admins   -> full access
VAULTX-Analysts -> alerts/events/devices
VAULTX-Auditors -> read-only reports
```

## Database Fields To Add

Agents should store:

```text
agent_id
hostname
domain
computer_sam
computer_dn
computer_ou
logged_in_user
user_sid
user_dn
department
ad_groups
policy_id
agent_token_hash
revoked
last_seen
```

Policies should support:

```text
policy_id
name
assigned_ou
assigned_group
priority
rules
created_at
updated_at
```

## Best Implementation Order

```text
1. Add AD connector module.
2. Add AD config file.
3. Add OU/group-to-policy mapping.
4. Update agent enrollment to send domain/user/computer metadata.
5. Server checks AD computer object during enrollment.
6. Server assigns policy based on OU/group.
7. Add periodic AD sync.
8. Add admin login with AD group mapping.
9. Deploy agent using GPO.
10. Package agent as Windows service/MSI.
```

