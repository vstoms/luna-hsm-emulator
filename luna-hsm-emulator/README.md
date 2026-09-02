# Thales Luna 7 Network HSM Emulator

A **software emulator** of the Thales Luna 7 Network HSM for educational and training purposes. This tool implements a complete PKCS#11 v2.40 API surface with realistic cryptographic operations, partition management, role-based authentication, and an interactive `lunacm` command shell.

> **WARNING**: This is a software emulator. It does NOT provide the physical security guarantees of a real Hardware Security Module. All key material is stored in software and is only as secure as the host system. **Never use this in production environments.**

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Command Reference](#cli-command-reference)
- [Training Exercises](#training-exercises)
- [Architecture](#architecture)
- [Supported Algorithms](#supported-algorithms)
- [Disclaimer](#disclaimer)

---

## Features

### PKCS#11 v2.40 API
- **Session Management**: `C_Initialize`, `C_OpenSession`, `C_CloseSession`, `C_Login`, `C_Logout`, etc.
- **Slot/Token Management**: `C_GetSlotList`, `C_GetTokenInfo`, `C_InitToken`, `C_InitPIN`, `C_SetPIN`
- **Object Management**: `C_CreateObject`, `C_DestroyObject`, `C_FindObjects*`, `C_GetAttributeValue`, `C_SetAttributeValue`
- **Cryptographic Operations**: `C_Encrypt*`, `C_Decrypt*`, `C_Sign*`, `C_Verify*`, `C_Digest*`
- **Key Operations**: `C_GenerateKey`, `C_GenerateKeyPair`, `C_WrapKey`, `C_UnwrapKey`, `C_DeriveKey`

### Luna 7 HSM-Specific Features
- **Role-based authentication**: HSO, Partition SO, Crypto Officer (CO), Crypto User (CU)
- **PIN lockout policies** (configurable max failed attempts, default 10)
- **PED (PIN Entry Device) simulation** via CLI prompts
- **Partition management** with per-partition storage quotas
- **Key extraction policies** (`CKA_EXTRACTABLE`, `CKA_SENSITIVE`)
- **Key lifecycle states** (pre-active, active, deactivated, destroyed)
- **Key usage counters**

### Security Features
- **Encrypted storage**: All key material encrypted at rest with AES-256-GCM
- **Master password**: PBKDF2-derived master key (100,000 iterations)
- **Hash-chained audit log**: Tamper-evident SHA-256 hash chain
- **Export/Import**: Backup and restore HSM state

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

All 30 tests should pass.

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

## CLI Command Reference

### Slot/Partition Management

| Command | Description |
|---------|-------------|
| `slot list` | List all available slots/partitions |
| `slot set -slot <id>` | Set active slot |
| `partition create -name <name>` | Create a new partition |
| `partition delete -name <name>` | Delete a partition |
| `partition list` | List all partitions |
| `partition showinfo` | Show partition details and storage usage |

### Authentication

| Command | Description |
|---------|-------------|
| `role login -name co` | Login as Crypto Officer |
| `role login -name cu` | Login as Crypto User |
| `role login -name so` | Login as Security Officer |
| `role logout` | Logout current role |
| `role changepw -name co` | Change role password |

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

### Audit & Logging

| Command | Description |
|---------|-------------|
| `audit log show` | Display audit log |
| `audit log clear` | Clear audit log |
| `audit log verify` | Verify hash chain integrity |

### HSM Info

| Command | Description |
|---------|-------------|
| `hsm show` | Show HSM firmware/model info |
| `hsm factoryreset` | Reset HSM to factory defaults (with confirmation) |
| `hsm export -file <path>` | Export HSM state for backup |
| `hsm import -file <path>` | Import HSM state for restore |

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

---

## Training Exercises

These exercises cover common HSM workflows, from basic key generation to advanced key wrapping, firmware upgrades, and audit verification.

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

# Generate an extractable key on your partition
slot set -slot 1
key generate -kt aes -ks 256 -label backup_test_key --explain
# Note: default keys are non-extractable. For backup testing, generate with
# extractable=true by modifying the template, or use the API directly.

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

**What you learned**: The Luna Backup HSM 7 lifecycle — connecting, recovering from Secure Transport Mode, initializing with an SO PIN, backing up objects via the cloning protocol (which requires CKA_EXTRACTABLE=TRUE and a shared cloning domain), restoring objects back to a partition, firmware management, and the destructive nature of firmware rollback (zeroizes all backup data).

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

**Objective**: Learn how to establish and manage client-partition connections using both NTLS and STC channels.

```bash
# Start LunaSH
python hsm_emulator.py --lunash

# Login
login

# Register a client and assign a partition
client register -name client1 -ip 192.168.1.50
client assignPartition -name client1 -partition 1

# --- NTLS Connection ---

# Show NTLS server certificate
ntls certificate show

# Create an NTLS connection (self-signed cert)
ntls connection create -client client1 -slot 1 -cert self-signed

# List NTLS connections
ntls connection list

# Establish the NTLS trust link
ntls connection connect -client client1 -slot 1

# Show connection details
ntls connection show -client client1 -slot 1

# Show NTLS status
ntls show

# Disconnect
ntls connection disconnect -client client1 -slot 1

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

**What you learned**: The Luna 7 supports two types of client-partition connections. NTLS (Network Trust Link Service) is high-performance, certificate-based, and suited for traditional data centers. STC (Secure Trusted Channel) provides higher assurance with symmetric encryption, message authentication codes, and mutual identity-based authentication — preferred for cloud and virtual environments. NTLS connections can be converted to STC (one-way, irreversible). Both channels have a full lifecycle: create, connect, disconnect, restore. STC identities (client and partition) must be created and exported before establishing connections.

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
│   ├── policies.py           # Partition capabilities and policies catalog
│   ├── appliance.py          # Luna Network HSM 7 appliance emulation
│   ├── connections.py        # NTLS and STC client-partition connections
│   ├── session.py           # Session management
│   ├── auth.py              # Role-based authentication
│   ├── keystore.py          # Key storage and retrieval
│   └── audit.py             # Audit logging with hash chaining
├── cli/
│   ├── __init__.py
│   ├── lunacm.py            # Interactive lunacm shell
│   ├── lunash.py            # Interactive LunaSH appliance shell
│   ├── commands.py          # lunacm command handlers
│   └── lunash_commands.py    # LunaSH command handlers
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
│   └── test_pkcs11.py       # 217 unit tests for PKCS#11 operations
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
- **AES**: 128, 192, 256-bit — ECB, CBC, CTR, GCM modes
- **3DES**: 112, 168-bit — ECB, CBC modes
- **DES**: 56-bit (legacy)

### Asymmetric
- **RSA**: 1024, 2048, 3072, 4096-bit — PKCS#1 v1.5, OAEP, PSS
- **ECC**: P-256, P-384, P-521, secp256k1 — ECDSA, ECDH
- **DSA**: 1024, 2048, 3072-bit

### Hashing / MAC
- SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
- HMAC-SHA256, HMAC-SHA512
- CMAC (AES-based)

### Key Derivation
- PBKDF2
- HKDF
- SP800-108 KDF (Counter Mode)

---

## Disclaimer

This is a **software emulator** designed for educational and training purposes only.

- It does **not** provide the physical security guarantees of a real Hardware Security Module.
- All key material is stored in software and is only as secure as the host system.
- It should **never** be used in production environments.
- The Thales Luna 7 is a real product of Thales e-Security. This emulator is not affiliated with or endorsed by Thales.
- PKCS#11 is a standard maintained by OASIS. This implementation follows the v2.40 specification conceptually but is not a certified implementation.
