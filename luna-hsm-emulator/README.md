# Thales Luna 7 Network HSM Emulator

A **software emulator** of the Thales Luna 7 Network HSM for educational and training purposes. This tool implements a complete PKCS#11 v2.40 API surface with realistic cryptographic operations, two interactive command shells (`lunacm` and `lunash`), partition management, role-based authentication, NTLS/STC connection management, and full appliance management.

> **WARNING**: This is a software emulator. It does NOT provide the physical security guarantees of a real Hardware Security Module. All key material is stored in software and is only as secure as the host system. **Never use this in production environments.**

---

## Table of Contents

- [Key Features](#key-features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Two Shells: lunacm and lunash](#two-shells-lunacm-and-lunash)
- [lunacm Command Reference](#lunacm-command-reference)
- [LunaSH Command Reference](#lunash-command-reference)
- [Training Exercises](#training-exercises)
- [Architecture](#architecture)
- [Supported Algorithms](#supported-algorithms)
- [Testing](#testing)
- [Disclaimer](#disclaimer)

---

## Key Features

### Real Cryptography via PKCS#11 v2.40

Full implementation of `C_Initialize` through `C_DeriveKey` — sessions, slots, objects, crypto, keys. All operations use real cryptographic algorithms through `pyca/cryptography` (OpenSSL) and return accurate `CKR_*` return codes.

### Two Interactive Command Shells

| Shell | Purpose | Access |
|-------|---------|--------|
| **lunacm** | Client-side PKCS#11 configuration manager — keys, crypto, partitions, audit | Local console |
| **lunash** | Server-side appliance shell — users, network, NTLS, STC, clients, services, HA, licenses | SSH-style |

Both shells support tab-completion, command shortnames, and `--explain` mode for educational output.

### NTLS Certificate Management

Full NTLS (Network Trust Link Service) certificate lifecycle matching the real Luna 7:

- **Certificate renewal** via `sysconf regenCert` with customizable subject DN (hostname, organization, country, state, location, org unit, email), key type (RSA/EC), key size, curve, validity period, and SAN
- **CSR generation** with `-csr` flag for external CA signing
- **Interface binding** — bind NTLS to eth0–eth3, bond0, bond1, or all interfaces via `ntls bind`/`ntls unbind`
- **Connection invalidation** — renewing the certificate automatically breaks all existing client trust relationships and reports which connections were affected
- **Service restart** — NTLS service is automatically restarted after certificate renewal
- **Client hostname/IP mapping** — NTLS connections store and display client IP and hostname for certificate exchange

### Client-Partition Connections

| Channel | Description |
|---------|-------------|
| **NTLS** | High-performance, certificate-based mutual authentication for traditional data centers |
| **STC** | Higher-assurance symmetric encryption, HMAC, mutual identity-based authentication for cloud/virtual |

Both channels support full lifecycle: create, connect, disconnect, restore. NTLS connections can be irreversibly converted to STC.

### Partition Management & Policies

- PPSO and legacy partition workflows with uninitialized, roles-pending, ready, and deactivated states
- Separate SO, CO, and CU initialization, activation, lockout, and superior-role reset rules
- HSM SO-authorized deletion and enforced object/persisted-byte quotas
- Comprehensive status via `partition show -partition <name>`
- **30-policy catalog** matching Luna 7 capabilities, including destructive changes and mutual exclusion
- **Partition Policy Templates (PPT)** — predefined sets (FIPS Strict, High Security, Development, Backup Ready) plus custom templates

### Role-Based Authentication

Four-role hierarchy with PIN lockout policies and PED (PIN Entry Device) simulation:

| Role | Capabilities |
|------|-------------|
| **HSO** (HSM Security Officer) | Full HSM administration, factory reset, partition creation |
| **SO** (Partition Security Officer) | Partition initialization, PIN management |
| **CO** (Crypto Officer) | Key generation, deletion, wrapping, attribute management |
| **CU** (Crypto User) | Cryptographic operations only (encrypt, decrypt, sign, verify) |

### Backup HSM

Luna Backup HSM 7 emulation with STM recovery, cloning protocol, backup/restore, firmware management, and factory reset.

### High Availability

HA groups support round-robin and active/standby routing, automatic failover, manual or automatic recovery, retry tracking, simulated network partitions, partial synchronization failures, domain-based persistent-key replication, firmware/policy compatibility checks, and non-replicated session objects.

### Appliance Management (LunaSH)

- Appliance users with RBAC (admin, operator, monitor, audit)
- Network configuration (hostname, interfaces, DNS, routes, bonding)
- NTP server management
- System services (ntls, ssh, stc, webserver, snmp, ntp)
- Syslog configuration with remote hosts
- License management with configurable limits
- Sanitized support-bundle generation (excludes all credentials and key material)
- Firmware upgrade with pre-checks, staged progress, rollback, and history

### Security & Storage

- **Encrypted storage**: All key material encrypted at rest with AES-256-GCM
- **Master password**: PBKDF2-derived master key (100,000 iterations)
- **Hash-chained audit log**: Tamper-evident SHA-256 hash chain with verification
- **Export/Import**: Backup and restore complete HSM state

### Educational Features

- **`--explain` flag**: Shows the underlying PKCS#11 function calls, attributes, mechanisms, and security implications
- **PKCS#11 return codes**: All operations return accurate `CKR_*` codes with human-readable descriptions

---

## Installation

### Prerequisites

- Python 3.10+
- pip (Python package installer)

### Install

```bash
cd luna-hsm-emulator
pip install -r requirements.txt
```

### Verify Installation

```bash
python tests/test_pkcs11.py -v
```

All 298 tests should pass.

---

## Quick Start

### 1. Initialize the HSM

```bash
python hsm_emulator.py --init
```

You will be prompted for:
- A master password (used to encrypt all key material at rest)
- SO (Security Officer) PIN for the default partition
- CO (Crypto Officer) PIN for the default partition

### 2. Start the Interactive Shell

```bash
python hsm_emulator.py
```

### 3. Run a Single Command (Non-Interactive)

```bash
python hsm_emulator.py -c "slot list"
python hsm_emulator.py -c "partition list"
```

---

## Two Shells: lunacm and lunash

The emulator provides two distinct command shells, mirroring the real Luna 7 architecture:

### lunacm — Client-Side PKCS#11 Shell

This is the default shell. It manages cryptographic objects, sessions, and partition configuration from the client's perspective.

```bash
python hsm_emulator.py           # Start lunacm
python hsm_emulator.py -c "..."  # Run single lunacm command
```

### lunash — Server-Side Appliance Shell

LunaSH is the appliance management shell (accessed via SSH on a real Luna 7). It manages appliance users, network, NTLS/STC connections, clients, services, HA, and licenses.

```bash
python hsm_emulator.py --lunash  # Start lunash
```

---

## lunacm Command Reference

### Slot/Partition Management

| Command | Description |
|---------|-------------|
| `slot list` | List all available slots/partitions |
| `slot set -slot <id>` | Set active slot |
| `partition create -name <name>` | Create a new partition |
| `partition delete -name <name>` | Delete a partition |
| `partition list` | List all partitions |
| `partition showinfo` | Show partition details and storage usage |
| `partition showpolicies [-verbose]` | Show partition policies |
| `partition changepolicy -policy <id> -value <value> [-force]` | Change a policy |
| `partition policytemplate list\|show\|apply\|create\|delete` | Manage policy templates |

### Authentication

| Command | Description |
|---------|-------------|
| `role login -name co` | Login as Crypto Officer |
| `role login -name cu` | Login as Crypto User |
| `role login -name so` | Login as Security Officer |
| `role logout` | Logout current role |
| `role changepw -name <role>` | Change role password |

### Key Operations

| Command | Description |
|---------|-------------|
| `key generate -kt aes -ks 256 -label <name>` | Generate AES key |
| `key generate -kt rsa -ks 2048 -label <name>` | Generate RSA key pair |
| `key generate -kt ec -curve P-256 -label <name>` | Generate EC key pair |
| `key generate -kt des3 -ks 192 -label <name>` | Generate 3DES key |
| `key list` | List all key objects |
| `key show -label <name>` | Show key attributes |
| `key delete -label <name>` | Delete a key |
| `key wrap -wrap-key <label> -target-key <label> [-out <file>]` | Wrap a key |
| `key unwrap -wrap-key <label> -file <file> [-label <name>]` | Unwrap a key |

### Cryptographic Operations

| Command | Description |
|---------|-------------|
| `crypto encrypt -key <label> -mech AES_GCM -in <file> [-out <file>]` | Encrypt a file |
| `crypto decrypt -key <label> -mech AES_GCM -in <file> [-out <file>]` | Decrypt a file |
| `crypto sign -key <label> -mech SHA256_RSA_PKCS -in <file> [-out <file>]` | Sign a file |
| `crypto verify -key <label> -mech SHA256_RSA_PKCS -in <file> -sig <file>` | Verify a signature |
| `crypto digest -mech SHA256 -in <file>` | Compute a hash digest |

### Audit & HSM Management

| Command | Description |
|---------|-------------|
| `audit log show` | Display audit log |
| `audit log clear` | Clear audit log |
| `audit log verify` | Verify hash chain integrity |
| `hsm show` | Show HSM firmware/model info |
| `hsm factoryreset` | Reset HSM to factory defaults (with confirmation) |
| `hsm export -file <path>` | Export HSM state for backup |
| `hsm import -file <path>` | Import HSM state for restore |
| `hsm firmware show` | Show current firmware details |
| `hsm firmware list` | List all available firmware versions |
| `hsm firmware upgrade -version <v>` | Upgrade firmware to specified version |
| `hsm firmware rollback` | Roll back to previous firmware |
| `hsm firmware history` | Show firmware upgrade history |
| `hsm supportInfo` | Generate sanitized support bundle |

### Backup HSM

| Command | Description |
|---------|-------------|
| `backup connect` | Connect Luna Backup HSM 7 |
| `backup stm show` | Show Secure Transport Mode status |
| `backup stm recover -string <s>` | Recover from STM |
| `backup init` | Initialize backup HSM (set SO PIN) |
| `backup login` | Login to backup HSM as SO |
| `backup show` | Show backup HSM status |
| `backup backup -slot <id> -domain <d>` | Back up objects |
| `backup restore -slot <id> -domain <d>` | Restore objects |
| `backup list` | List objects on backup HSM |
| `backup firmware show` | Show backup HSM firmware |
| `backup firmware upgrade -version <v>` | Upgrade backup HSM firmware |
| `backup firmware rollback` | Rollback (destructive — erases backups) |
| `backup factoryreset` | Factory reset backup HSM |
| `backup disconnect` | Disconnect backup HSM |

### Available Mechanism Names

Use these with `-mech` flag:

| Category | Mechanisms |
|----------|-----------|
| **AES** | `AES_ECB`, `AES_CBC`, `AES_CBC_PAD`, `AES_CTR`, `AES_GCM`, `AES_CMAC` |
| **RSA** | `RSA_PKCS`, `RSA_PKCS_OAEP`, `RSA_PKCS_PSS`, `SHA256_RSA_PKCS`, `SHA384_RSA_PKCS`, `SHA512_RSA_PKCS`, `SHA256_RSA_PKCS_PSS`, `SHA384_RSA_PKCS_PSS`, `SHA512_RSA_PKCS_PSS` |
| **EC** | `ECDSA`, `ECDH1_DERIVE` |
| **3DES** | `DES3_ECB`, `DES3_CBC`, `DES3_CBC_PAD` |
| **Hash** | `SHA_1`, `SHA256`, `SHA384`, `SHA512` |
| **HMAC** | `SHA1_HMAC`, `SHA256_HMAC`, `SHA384_HMAC`, `SHA512_HMAC` |

> **Tip:** Append `--explain` to any command for educational PKCS#11 output showing the underlying function calls, attributes, mechanisms, and security implications.

---

## LunaSH Command Reference

LunaSH is the server-side appliance shell. Start it with `python hsm_emulator.py --lunash`.

### Appliance Login & Status

| Command | Description |
|---------|-------------|
| `login` | Login to appliance (SSH-style) |
| `logout` | Logout |
| `status cpu\|mem\|disk\|date\|interface` | System status |

### HSM Management

| Command | Description |
|---------|-------------|
| `hsm login` | Login as HSM Security Officer |
| `hsm logout` | Logout of HSM |
| `hsm show` | Show HSM info |
| `hsm init` | Initialize HSM (set SO PIN) |
| `partition create -name <name>` | Create a partition |
| `partition list` | List partitions |

### User Management (RBAC)

| Command | Description |
|---------|-------------|
| `user list` | List appliance users |
| `user add -name <name> -role <role>` | Add user (admin/operator/monitor/audit) |
| `user delete -name <name>` | Delete user |
| `user enable\|disable -name <name>` | Enable/disable user |

### Client Management

| Command | Description |
|---------|-------------|
| `client register -name <name> -ip <ip>` | Register HSM client |
| `client assignPartition -name <name> -partition <id>` | Assign partition to client |
| `client revokePartition -name <name> -partition <id>` | Revoke partition |
| `client list` | List clients |
| `client show -name <name>` | Show client details |
| `client delete -name <name>` | Delete client |

### NTLS Certificate & Connections

| Command | Description |
|---------|-------------|
| `ntls show` | Show NTLS status, bound interfaces, certificate |
| `ntls bind <eth0\|eth1\|eth2\|eth3\|bond0\|bond1\|all>` | Bind NTLS to interface(s) |
| `ntls unbind <interface>` | Unbind NTLS from an interface |
| `ntls certificate show` | Show NTLS server certificate details |
| `ntls certificate regenerate` | Regenerate certificate (breaks all connections) |
| `sysconf regenCert [options]` | Full certificate renewal with customizable DN, key type, CSR |
| `ntls connection create -client <name> -slot <id> [-cert ...] [-ip <ip>] [-hostname <h>]` | Create NTLS connection |
| `ntls connection list` | List NTLS connections |
| `ntls connection connect -client <name> -slot <id>` | Establish trust link |
| `ntls connection disconnect -client <name> -slot <id>` | Disconnect |
| `ntls connection restore -client <name> -slot <id>` | Restore broken connection |
| `ntls connection show -client <name> -slot <id>` | Show connection details |
| `ntls connection delete -client <name> -slot <id>` | Delete connection |

**`sysconf regenCert` options:**

```text
sysconf regenCert [-force] [-csr] [-hostname <h>] [-keytype RSA|EC] [-keysize <n>]
  [-curve <name>] [-days <n>] [-country <c>] [-state <s>] [-location <l>]
  [-organization <o>] [-orgunit <u>] [-email <e>] [-san <san>]
```

### STC (Secure Trusted Channel)

| Command | Description |
|---------|-------------|
| `stc enable\|disable\|show` | Enable/disable/show STC |
| `stc identity create -type client\|partition -name <name>` | Create STC identity |
| `stc identity list\|show\|export\|delete` | Manage STC identities |
| `stc connection create -client <name> -partition <name> -slot <id>` | Create STC connection |
| `stc connection list\|connect\|disconnect\|restore\|delete` | Manage STC connections |
| `stc cipher show\|enable <name>\|disable <name>` | Configure cipher |
| `stc hmac show\|enable\|disable` | Configure HMAC |
| `stc rekeyThreshold set <n>\|show` | Configure rekey threshold |
| `stc activationTimeOut set <n>\|show` | Configure activation timeout |
| `stc convert -client <name> -slot <id>` | Convert NTLS to STC (irreversible) |
| `stc admin show` | Show STC admin channel status |

### Network & System Configuration

| Command | Description |
|---------|-------------|
| `network show` | Show network configuration |
| `network hostname <name>` | Set hostname |
| `network interface static <iface> -ip <ip> -netmask <mask> [-gateway <gw>]` | Static IP |
| `network interface dhcp <iface>` | DHCP |
| `network dns add\|delete <server>` | DNS management |
| `network route add\|delete <destination>` | Route management |
| `sysconf timezone set <tz>` | Set timezone |
| `sysconf banner add <text>\|clear\|show` | Login banner |
| `sysconf ssh port <port>\|show` | SSH configuration |
| `sysconf appliance reboot\|poweroff` | Appliance power control |

### Services & Syslog

| Command | Description |
|---------|-------------|
| `service list\|start\|stop\|restart\|status <name>` | Service management |
| `syslog show` | Show syslog configuration |
| `syslog severity set <level>` | Set severity |
| `syslog remotehost add\|delete\|list <host>` | Remote host management |
| `syslog rotate` | Rotate logs |

### High Availability

| Command | Description |
|---------|-------------|
| `ha create -name <name> -slot <id> [-label <label>]` | Create HA group |
| `ha addmember -name <name> -slot <id>` | Add member |
| `ha removemember -name <name> -slot <id>` | Remove member |
| `ha list` | List HA groups |
| `ha show -name <name>` | Show HA group details |
| `ha status -name <name>` | Show HA group status |
| `ha setretry -name <name> -retry <n>` | Set retry count (-1 for infinite) |
| `ha setinterval -name <name> -interval <n>` | Set polling interval |
| `ha synchronize -name <name>` | Synchronize key material |
| `ha delete -name <name>` | Delete HA group |

### NTP, Bonding, Licenses

| Command | Description |
|---------|-------------|
| `ntp show\|add\|delete\|enable\|disable\|sync` | NTP management |
| `bond show\|configure\|enable\|disable\|delete` | Network bonding |
| `license list\|show\|setlimit\|enable\|disable` | License management |

### Packages & Audit

| Command | Description |
|---------|-------------|
| `package list\|verify\|update\|listfile\|deletefile\|erase` | Package management |
| `audit login\|logout\|show\|log` | Audit commands |
| `my password set` | Change own password |

---

## Training Exercises

These exercises cover common HSM workflows, from basic key generation to advanced NTLS certificate management, HA groups, and audit verification.

### Exercise 1: Initialize and Explore the HSM

**Objective**: Learn the basic HSM initialization and navigation commands.

```bash
# Initialize the HSM
python hsm_emulator.py --init

# Start the shell
python hsm_emulator.py

# At the prompt:
hsm show
slot list
partition list
partition showinfo
help
```

**What you learned**: How to initialize the HSM, view its configuration, and navigate partitions.

---

### Exercise 2: Generate an AES Key with --explain

**Objective**: Understand the PKCS#11 key generation process.

```bash
# Login as Crypto Officer
role login -name co

# Generate a 256-bit AES key with explanation
key generate -kt aes -ks 256 -label my_aes_key --explain

# View the key
key show -label my_aes_key

# List all keys
key list
```

**What you learned**: How AES keys are generated inside an HSM, the meaning of `CKA_SENSITIVE` and `CKA_EXTRACTABLE`, and why keys never leave the HSM boundary.

---

### Exercise 3: Encrypt and Decrypt a File with AES-GCM

**Objective**: Perform symmetric encryption operations through the HSM.

```bash
# Create a test file
echo "Secret message for the HSM" > /tmp/secret.txt

# Encrypt with AES-GCM
crypto encrypt -key my_aes_key -mech AES_GCM -in /tmp/secret.txt -out /tmp/secret.enc

# Decrypt
crypto decrypt -key my_aes_key -mech AES_GCM -in /tmp/secret.enc -out /tmp/secret.dec

# Verify
cat /tmp/secret.dec
```

**What you learned**: How to encrypt and decrypt data using HSM-managed keys, and that the key material never appears in the host process.

---

### Exercise 4: Generate an RSA Key Pair and Sign Data

**Objective**: Perform asymmetric key generation and digital signing.

```bash
# Generate a 2048-bit RSA key pair
key generate -kt rsa -ks 2048 -label my_rsa_key --explain

# Create a document to sign
echo "Important document to sign" > /tmp/document.txt

# Sign with SHA256_RSA_PKCS
crypto sign -key my_rsa_key -mech SHA256_RSA_PKCS -in /tmp/document.txt -out /tmp/document.sig

# Verify the signature
crypto verify -key my_rsa_key -mech SHA256_RSA_PKCS -in /tmp/document.txt -sig /tmp/document.sig
```

**What you learned**: RSA key pair generation, signing with PKCS#1 v1.5 padding, and signature verification.

---

### Exercise 5: Generate an EC Key Pair and Sign

**Objective**: Use elliptic curve cryptography for signing.

```bash
# Generate a P-256 EC key pair
key generate -kt ec -curve P-256 -label my_ec_key --explain

# Sign data with ECDSA
echo "EC signed data" > /tmp/ec_data.txt
crypto sign -key my_ec_key -mech ECDSA -in /tmp/ec_data.txt -out /tmp/ec_data.sig

# Verify
crypto verify -key my_ec_key -mech ECDSA -in /tmp/ec_data.txt -sig /tmp/ec_data.sig
```

**What you learned**: EC key generation with named curves, ECDSA signing, and the performance advantages of EC over RSA.

---

### Exercise 6: Key Wrapping and Unwrapping

**Objective**: Learn how to securely transport keys between HSMs.

```bash
# Generate a wrapping key (must have wrap/unwrap capability)
key generate -kt aes -ks 256 -label wrap_key

# Generate a target key (must be extractable for wrapping)
key generate -kt aes -ks 128 -label target_key

# Wrap the target key
key wrap -wrap-key wrap_key -target-key target_key -out /tmp/wrapped.key

# Delete the original target key
key delete -label target_key

# Unwrap the key back into the HSM
key unwrap -wrap-key wrap_key -file /tmp/wrapped.key -label restored_key

# Verify the restored key works
key show -label restored_key
```

**What you learned**: Key wrapping with AES-GCM, the importance of `CKA_EXTRACTABLE`, and how keys are securely transported between HSMs.

---

### Exercise 7: Hash Digest Operations

**Objective**: Compute hash digests through the PKCS#11 interface.

```bash
# Create a file
echo "Data to hash" > /tmp/hash_input.txt

# Compute SHA-256 digest
crypto digest -mech SHA256 -in /tmp/hash_input.txt

# Compute SHA-512 digest
crypto digest -mech SHA512 -in /tmp/hash_input.txt
```

**What you learned**: How to use PKCS#11 digest mechanisms and the difference between standalone hashing and signed hashing.

---

### Exercise 8: Role Management and PIN Security

**Objective**: Understand HSM role-based access control and PIN lockout.

```bash
# Login as Security Officer
role login -name so

# Logout
role logout

# Try logging in with wrong PIN (as CO)
role login -name co
# Enter wrong PIN repeatedly to see lockout in action

# Change CO PIN (requires being logged in as SO)
role login -name so
role changepw -name co
```

**What you learned**: The four HSM roles, PIN lockout policies, and how to change PINs.

---

### Exercise 9: Audit Log Inspection

**Objective**: Understand tamper-evident audit logging.

```bash
# Perform some operations
role login -name co
key generate -kt aes -ks 256 -label audit_test_key

# View the audit log
audit log show

# Verify the hash chain integrity
audit log verify
```

**What you learned**: How every HSM operation is logged, the hash chain mechanism, and how to verify audit integrity.

---

### Exercise 10: Create and Manage Multiple Partitions

**Objective**: Learn partition management for multi-tenant scenarios.

```bash
# Create additional partitions
partition create -name tenant_a
partition create -name tenant_b

# List all partitions
partition list

# Switch to a different partition
slot set -slot 2

# Generate keys on the new partition
key generate -kt aes -ks 256 -label tenant_a_key

# Switch back
slot set -slot 1
```

**What you learned**: How partitions provide isolation between different applications or tenants, each with independent authentication and key storage.

---

### Exercise 11: Export and Import HSM State

**Objective**: Learn backup and restore operations.

```bash
# Export current HSM state
hsm export -file /tmp/hsm_backup.json

# Perform some operations
key generate -kt aes -ks 256 -label backup_test_key

# Import the backup (restores to previous state)
hsm import -file /tmp/hsm_backup.json

# Verify keys are restored to backup state
key list
```

**What you learned**: How to back up and restore HSM state, and that key material remains encrypted during export.

---

### Exercise 12: Factory Reset

**Objective**: Understand the nuclear option for HSM management.

```bash
# View current state
partition list
key list

# Factory reset (destroys everything)
hsm factoryreset
# Type 'FACTORYRESET' to confirm

# Verify everything is gone
partition list
```

**What you learned**: How to completely reset the HSM, and why this operation requires explicit confirmation.

---

### Exercise 13: Firmware Upgrade and Rollback

**Objective**: Learn the HSM firmware upgrade lifecycle, including pre-checks, staged upgrade, rollback, and history tracking.

```bash
# View current firmware info
hsm firmware show

# List all available firmware versions
hsm firmware list

# Upgrade to a newer firmware version
hsm firmware upgrade -version 7.14.0 --explain
# Pre-checks will run, then you'll be asked to confirm

# Verify the new firmware is active
hsm show

# View the upgrade history
hsm firmware history

# Roll back to the previous firmware
hsm firmware rollback
# Confirm the rollback

# Verify rollback succeeded
hsm firmware show

# Try upgrading to a nonexistent version
hsm firmware upgrade -version 99.99.99
# Pre-check will fail: version not found

# Try upgrading to the same version (already installed)
hsm firmware upgrade -version 7.13.0
# Pre-check will fail: already installed
```

**What you learned**: How HSM firmware upgrades work — pre-checks (version exists, audit chain integrity, no active sessions), staged upgrade process (backup, download, signature verification, flash, reboot, post-verify), rollback to previous versions, and the firmware history trail for compliance.

---

### Exercise 14: Backup HSM Operations

**Objective**: Learn how to use a Luna Backup HSM 7 to back up and restore cryptographic objects via the cloning protocol.

```bash
# Connect a Luna Backup HSM 7 (simulated USB connection)
backup connect --explain

# Check Secure Transport Mode status
backup stm show

# Recover from Secure Transport Mode
backup stm recover -string my_random_string --explain

# Initialize the backup HSM (set SO PIN)
backup init

# Log in to the backup HSM as SO
backup login

# Show backup HSM status
backup show

# Generate a key on your partition (secure cloning does not require extractability)
slot set -slot 1
key generate -kt aes -ks 256 -label backup_test_key --explain
# Non-extractable keys can be backed up when the partition's cloning policy
# permits the key type and the source and backup domains match.

# Back up objects from slot 1 to the backup HSM
backup backup -slot 1 -domain my_domain --explain

# List what's on the backup HSM
backup list

# Delete the key from the source partition
key delete -label backup_test_key

# Restore from backup
backup restore -slot 1 -domain my_domain --explain

# Verify the key is back
key list

# Show backup HSM firmware info
backup firmware show

# Upgrade backup HSM firmware
backup firmware upgrade -version 7.14.0

# Roll back backup HSM firmware (destructive — erases all backups!)
backup firmware rollback

# Factory reset the backup HSM
backup factoryreset

# Disconnect the backup HSM
backup disconnect
```

**What you learned**: The Luna Backup HSM 7 lifecycle — connecting, recovering from Secure Transport Mode, initializing with an SO PIN, backing up objects via secure cloning (which requires cloning policy permission and a shared cloning domain, but not `CKA_EXTRACTABLE=TRUE`), restoring objects back to a partition, firmware management, and the destructive nature of firmware rollback (zeroizes all backup data).

---

### Exercise 15: Partition Capabilities and Policies

**Objective**: Learn how to configure partition security policies, understand destructive changes, and use Partition Policy Templates (PPT) for consistent configuration.

```bash
# View all partition policies (compact mode)
slot set -slot 1
partition showpolicies

# View all policies with full descriptions and destructiveness info
partition showpolicies -verbose

# Change a non-destructive policy (MAX_LOGIN_ATTEMPTS)
partition changepolicy -policy 25 -value 5

# Try to enable private key wrapping (destructive — requires confirmation)
partition changepolicy -policy 1 -value 1
# This will warn: DESTRUCTIVE! Type 'DESTROY' to confirm.

# Mutual exclusion: cloning and wrapping cannot both be On
# First disable cloning, then enable wrapping
partition changepolicy -policy 0 -value 0 -force
partition changepolicy -policy 1 -value 1 -force

# List available policy templates
partition policytemplate list

# Show details of a specific template
partition policytemplate show -name FIPS_STRICT

# Apply a predefined template to the partition
partition policytemplate apply -name FIPS_STRICT -force

# Create a custom template
partition policytemplate create -name MY_CONFIG -desc "My custom policy set" -policies "25=5,19=1,14=0"

# Apply the custom template
partition policytemplate apply -name MY_CONFIG -force

# Delete the custom template
partition policytemplate delete -name MY_CONFIG

# Verify policies after changes
partition showpolicies -verbose
```

**What you learned**: The Luna 7 has 30 partition policies that control security behaviors including key cloning, wrapping, masking, RSA blinding, raw RSA operations, PIN rules, and HA recovery. Some policy changes are destructive (delete all objects on the partition). Policies 0 (cloning) and 1 (wrapping) are mutually exclusive. Partition Policy Templates (PPT) allow consistent policy sets across partitions — predefined templates cover FIPS, High Security, Development, and Backup Ready configurations.

---

### Exercise 16: LunaSH Appliance Management

**Objective**: Learn how to manage the Luna Network HSM 7 appliance using LunaSH, the server-side command shell accessed via SSH.

```bash
# Start LunaSH (server-side appliance shell)
python hsm_emulator.py --lunash

# Login to the appliance as admin
login
# Username: admin
# Password: (set on first login)

# Check system status
status cpu
status mem
status disk
status date

# Show HSM info
hsm show

# Login as HSM Security Officer (separate from appliance login)
hsm login
# SO PIN: ********

# List partitions
partition list

# Create a new partition
partition create -name partition2 -label "Backup Partition"

# List appliance users
user list

# Add a new user
user add -name auditor1 -role audit

# Register an HSM client
client register -name client1 -ip 192.168.1.50

# Assign a partition to the client
client assignPartition -name client1 -partition 1

# List clients
client list

# Show network configuration
network show

# Set hostname
network hostname my-luna7

# Configure a static interface
network interface static eth0 -ip 10.0.0.5 -netmask 255.255.255.0 -gateway 10.0.0.1

# Show NTLS status
ntls show

# List services
service list

# Start the STC service
service start stc

# Set timezone
sysconf timezone set America/New_York

# Set login banner
sysconf banner add "Authorized access only"

# Show syslog configuration
syslog show

# Add a remote syslog server
syslog remotehost add 10.0.0.100

# List available packages
package list

# Verify a package
package verify luna-firmware-7.13.0.pkg

# Show audit summary
audit show

# View recent audit entries
audit log tail

# Change your own password
my password set

# Logout
logout
```

**What you learned**: LunaSH is the server-side appliance shell (accessed via SSH) that manages the Luna Network HSM 7 appliance. It is distinct from lunacm (the client-side PKCS#11 configuration manager). LunaSH manages appliance users with role-based access control (admin, operator, monitor, audit), network configuration, NTLS connections, HSM client registration and partition assignment, system services, syslog, and package management. The HSM SO login is separate from the appliance SSH login — you must authenticate to both. Command shortnames are supported (e.g., `hs` for `hsm`, `par` for `partition`).

---

### Exercise 17: Client-Partition Connections (NTLS and STC)

**Objective**: Learn how to establish and manage client-partition connections using both NTLS and STC channels, including certificate renewal and interface binding.

```bash
# Start LunaSH
python hsm_emulator.py --lunash

# Login
login

# Register a client and assign a partition
client register -name client1 -ip 192.168.1.50
client assignPartition -name client1 -partition 1

# --- NTLS Certificate Management ---

# Show NTLS server certificate
ntls certificate show

# Bind NTLS to additional interfaces
ntls bind eth1
ntls bind all

# Show NTLS status with bound interfaces
ntls show

# Unbind an interface
ntls unbind eth3

# --- NTLS Connection ---

# Create an NTLS connection with client IP and hostname
ntls connection create -client client1 -slot 1 -cert self-signed -ip 192.168.1.50 -hostname client1.local

# List NTLS connections (shows IP and hostname)
ntls connection list

# Establish the NTLS trust link
ntls connection connect -client client1 -slot 1

# Show connection details
ntls connection show -client client1 -slot 1

# Show NTLS status
ntls show

# --- Certificate Renewal ---

# Renew the NTLS certificate with custom options
sysconf regenCert -force -days 730 -organization "My Org" -country CA -hostname my-luna7

# All existing connections are now broken — check the list
ntls connection list

# Restore the broken connection
ntls connection restore -client client1 -slot 1

# Re-establish the trust link
ntls connection connect -client client1 -slot 1

# Generate a CSR for external CA signing
sysconf regenCert -force -csr -days 365 -organization "My Org"

# --- STC Connection ---

# Enable STC on the appliance
stc enable

# Show STC configuration
stc show

# Create STC identities (client and partition)
stc identity create -type client -name stc_client1
stc identity create -type partition -name stc_part1

# List STC identities
stc identity list

# Export the partition identity (.pid file)
stc identity export -type partition -name stc_part1

# Create an STC connection
stc connection create -client stc_client1 -partition stc_part1 -slot 1

# List STC connections
stc connection list

# Establish the STC secure tunnel
stc connection connect -id 1

# Configure STC settings
stc cipher enable AES-128-GCM
stc hmac enable
stc rekeyThreshold set 500000
stc activationTimeOut set 600

# --- NTLS to STC Conversion ---

# Disconnect the NTLS connection first
ntls connection disconnect -client client1 -slot 1

# Convert NTLS to STC (irreversible)
stc convert -client client1 -slot 1

# Verify: NTLS connection is gone, STC connection added
ntls connection list
stc connection list

# --- Connection Summary ---

# Show overall connection status
ntls show
stc show
stc admin show

# Restore a broken connection
ntls connection restore -client client1 -slot 1
stc connection restore -id 1

# Logout
logout
```

**What you learned**: The Luna 7 supports two types of client-partition connections. NTLS (Network Trust Link Service) is high-performance, certificate-based, and suited for traditional data centers. STC (Secure Trusted Channel) provides higher assurance with symmetric encryption, message authentication codes, and mutual identity-based authentication — preferred for cloud and virtual environments. NTLS connections can be converted to STC (one-way, irreversible). Both channels have a full lifecycle: create, connect, disconnect, restore. STC identities (client and partition) must be created and exported before establishing connections. Certificate renewal via `sysconf regenCert` automatically invalidates all existing NTLS connections and restarts the NTLS service — clients must re-register and re-establish trust. NTLS can be bound to specific network interfaces (eth0–eth3, bond0, bond1, or all).

---

### Exercise 18: High Availability Groups

**Objective**: Learn how to configure HA groups for automatic failover across multiple HSM partitions.

```bash
# Start LunaSH
python hsm_emulator.py --lunash
login

# Create two partitions (requires HSM SO login)
hsm login
partition create -name part1 -label "HA Primary"
partition create -name part2 -label "HA Secondary"

# Create an HA group with the first partition
ha create -name ha_group1 -slot 1 -label "Production HA"

# Add the second partition as a member
ha addmember -name ha_group1 -slot 2

# List all HA groups
ha list

# Show details of the HA group
ha show -name ha_group1

# Configure retry count (use -1 for infinite polling)
ha setretry -name ha_group1 -retry 100
ha setretry -name ha_group1 -retry -1

# Configure polling interval
ha setinterval -name ha_group1 -interval 10

# Synchronize all members (copies key material)
ha synchronize -name ha_group1

# Show HA group status
ha status -name ha_group1

# Remove a member
ha removemember -name ha_group1 -slot 2

# Delete the HA group
ha delete -name ha_group1
```

**What you learned**: HA groups link partitions across multiple HSMs so that if one HSM becomes unavailable, clients automatically failover to another. All members must share the same cloning domain. You can configure retry count (including infinite polling with -1), polling interval, and synchronize key material across members. An HA group must retain at least one member at all times.

---

### Exercise 19: NTP Configuration

**Objective**: Learn how to configure NTP for time synchronization on the appliance.

```bash
# Show current NTP configuration
ntp show

# Add an NTP server
ntp add time.google.com

# Add another server
ntp add time.cloudflare.com

# Show updated configuration
ntp show

# Force synchronization
ntp sync

# Delete an NTP server
ntp delete time.google.com

# Disable NTP
ntp disable

# Re-enable NTP
ntp enable
```

**What you learned**: NTP ensures the appliance clock stays synchronized, which is critical for audit log integrity and certificate validity. You can add multiple NTP servers for redundancy, force synchronization, and enable/disable NTP as needed. At least one NTP server is required.

---

### Exercise 20: Network Interface Bonding

**Objective**: Learn how to configure network interface bonding for redundancy.

```bash
# Show current bonds
bond show

# Configure bond0 with eth0 and eth1
bond configure -name bond0 -members eth0,eth1 -ip 10.0.0.5 -netmask 255.255.255.0 -gateway 10.0.0.1

# Show the configured bond
bond show

# Configure bond1 with eth2 and eth3
bond configure -name bond1 -members eth2,eth3 -ip 10.0.1.5 -netmask 255.255.255.0

# Disable a bond
bond disable -name bond1

# Re-enable a bond
bond enable -name bond1

# Delete a bond
bond delete -name bond1
```

**What you learned**: Network bonding combines two physical interfaces into a single logical interface for redundancy. If one link fails, traffic continues through the other. The Luna 7 supports bond0 and bond1, each requiring two distinct interfaces from eth0 through eth3. An interface cannot belong to more than one bond simultaneously.

---

### Exercise 21: Licenses and Support Diagnostics

**Objective**: Learn how to manage licenses and generate diagnostic support bundles.

```bash
# List all installed licenses
license list

# Show details of a specific license
license show ha

# Set a license limit
license setlimit -name max_partitions -limit 20

# Enable a license
license enable -name ha

# Disable a license
license disable -name stc

# Generate a sanitized support bundle
hsm supportInfo

# The bundle includes:
# - Appliance status (hostname, uptime, partitions, clients, services)
# - Network configuration (interfaces, bonds, DNS)
# - NTP configuration
# - Connection summary (NTLS/STC)
# - HA group details
# - License inventory
# - Safety notice (credentials and key material are excluded)
```

**What you learned**: The Luna 7 uses software licenses to enable features like HA, STC, key backup, and maximum partition counts. You can view, enable, disable, and configure license limits. The support bundle (`hsm supportInfo`) generates a diagnostic report safe to share with support teams — it excludes all credentials, PINs, password hashes, private keys, encrypted key blobs, and secret values.

---

## Architecture

```
luna-hsm-emulator/
├── hsm_emulator.py          # Main entry point
├── pkcs11/
│   ├── __init__.py
│   ├── api.py               # PKCS#11 function implementations
│   ├── mechanisms.py        # Cryptographic mechanism definitions
│   ├── objects.py           # CK Object classes (keys, certs, data)
│   └── constants.py         # CKR_, CKA_, CKM_, CKO_ constants
├── hsm/
│   ├── __init__.py
│   ├── token.py             # Token/partition management, policies
│   ├── backup.py            # Luna Backup HSM 7 emulation
│   ├── policies.py          # Partition capabilities and policies catalog
│   ├── appliance.py         # Luna Network HSM 7 appliance emulation
│   ├── connections.py       # NTLS and STC client-partition connections
│   ├── deployment.py        # HA groups, NTP, bonding, licenses, support bundles
│   ├── session.py           # Session management
│   ├── auth.py              # Role-based authentication
│   ├── ped.py               # PED keys and M-of-N quorum
│   ├── domain.py            # Cloning domains and secure object cloning
│   ├── lifecycle.py         # Partition types, lifecycle, and role states
│   ├── keystore.py          # Key storage and retrieval
│   └── audit.py             # Audit logging with hash chaining
├── cli/
│   ├── __init__.py
│   ├── lunacm.py            # Interactive lunacm shell
│   ├── lunash.py            # Interactive LunaSH appliance shell
│   ├── commands.py          # lunacm command handlers
│   └── lunash_commands.py   # LunaSH command handlers
├── crypto/
│   ├── __init__.py
│   ├── symmetric.py         # AES, 3DES operations
│   ├── asymmetric.py        # RSA, ECC operations
│   ├── digest.py            # Hashing and MAC operations
│   └── kdf.py               # Key derivation functions
├── storage/
│   ├── __init__.py
│   └── db.py                # SQLite persistence layer
├── tests/
│   ├── test_pkcs11.py       # PKCS#11 and appliance tests
│   ├── test_ped.py          # PED authentication and quorum tests
│   ├── test_domain.py       # Cloning domain and secure cloning tests
│   ├── test_lifecycle.py    # Partition lifecycle and quota tests
│   └── test_ha_behavior.py  # HA routing, failover, and synchronization tests
├── requirements.txt
└── README.md
```

### Data Flow

```
CLI Command → Command Handler → PKCS11 API → Crypto Layer
                                        ↓
                                  HSM Modules (Session, Token, Auth, Keystore, Audit)
                                        ↓
                                  Storage Layer (SQLite + AES-GCM encrypted blobs)
```

### Authentication Roles

| Role | Abbreviation | Description |
|------|-------------|-------------|
| HSM Security Officer | HSO | Full administrative access to the HSM |
| Partition Security Officer | SO | Partition-level administration (init, set PINs) |
| Crypto Officer | CO | Key management (generate, delete, wrap keys) |
| Crypto User | CU | Cryptographic operations only (encrypt, sign, verify) |

---

## Supported Algorithms

### Symmetric
- **AES**: 128, 192, 256-bit — ECB, CBC, CBC-PAD, CTR, GCM modes
- **3DES**: 112, 168-bit — ECB, CBC, CBC-PAD modes
- **DES**: 56-bit (legacy) — ECB, CBC

### Asymmetric
- **RSA**: 1024, 2048, 3072, 4096-bit — PKCS#1 v1.5, OAEP, PSS
- **ECC**: P-256, P-384, P-521, secp256k1 — ECDSA, ECDH
- **DSA**: 1024, 2048, 3072-bit

### Hashing / MAC
- SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
- HMAC-SHA256, HMAC-SHA384, HMAC-SHA512
- CMAC (AES-based)

### Key Derivation
- PBKDF2 (RFC 2898)
- HKDF (RFC 5869)
- SP800-108 KDF (NIST SP 800-108, Counter Mode)

---

## Testing

Run the full test suite:

```bash
python tests/test_pkcs11.py -v
```

The suite covers:

| Test Suite | Tests | What's Covered |
|-----------|-------|----------------|
| `TestStorage` | 3 | Blob encryption, PIN hashing, partition CRUD |
| `TestPKCS11Sessions` | 2 | Session open/close, close-all |
| `TestAuthentication` | 3 | Login/logout, wrong PIN, PIN lockout |
| `TestKeyGeneration` | 3 | AES, RSA key pair, EC key pair generation |
| `TestCryptoOperations` | 6 | AES-GCM, AES-CBC, RSA sign/verify, ECDSA, digest, HMAC |
| `TestKeyWrapping` | 2 | Wrap/unwrap round-trip, non-extractable rejection |
| `TestObjectManagement` | 4 | Find by template, find by label, destroy, copy |
| `TestAuditLog` | 3 | Entry recording, hash chain integrity, clear |
| `TestKDF` | 3 | PBKDF2, HKDF, SP800-108 |
| `TestFirmwareUpgrade` | 14 | Firmware info, list, pre-checks, upgrade, rollback, history, persistence, audit |
| `TestBackupHSM` | 31 | STM recovery, init, login, backup, restore, firmware, factory reset, persistence, audit |
| `TestPartitionPolicies` | 26 | Policy catalog, show/verbose, change by ID/name, destructive changes, mutual exclusion, templates, persistence, audit |
| `TestLunaSH` | 50 | Appliance login, HSM SO login, user management, client management, network, services, sysconf, syslog, NTLS, packages, RBAC, persistence |
| `TestClientPartitionConnections` | 48 | NTLS cert, connection lifecycle, STC identities, STC connections, STC config, NTLS-to-STC conversion, persistence |
| `TestDeploymentFeatures` | 50 | HA groups, NTP, network bonding, licenses, support bundles, persistence |
| `TestPEDManager` | 7 | PED colors, quorum, duplication, loss, remote PED, colored-role login |
| `TestCloningDomains` | 7 | Domain inheritance/change, secure cloning, HA domain enforcement |
| `TestPartitionLifecycle` | 9 | PPSO/legacy states, role hierarchy, deletion authorization, quotas |
| `TestHABehavior` | 8 | Load balancing, failover, recovery, network failures, compatibility, session objects |

```
Ran 298 tests in 4.1s

OK
```

---

## Disclaimer

This is a **software emulator** designed for educational and training purposes only.

- It does **not** provide the physical security guarantees of a real Hardware Security Module.
- All key material is stored in software and is only as secure as the host system.
- It should **never** be used in production environments.
- The Thales Luna 7 is a real product of Thales e-Security. This emulator is not affiliated with or endorsed by Thales.
- PKCS#11 is a standard maintained by OASIS. This implementation follows the v2.40 specification conceptually but is not a certified implementation.
