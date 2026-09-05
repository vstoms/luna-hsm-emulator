<div align="center">

# Thales Luna 7 Network HSM Emulator

A fully functional software emulator of the Thales Luna 7 Network HSM, built for **educational and training purposes**. Implements the complete PKCS#11 v2.40 API surface with real cryptographic operations, two interactive command shells (`lunacm` and `lunash`), partition management, role-based authentication, and full client-partition connection management.

[![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)](https://www.python.org/)
[![PKCS#11](https://img.shields.io/badge/PKCS%2311-v2.40-green)](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html)
[![License](https://img.shields.io/badge/License-Educational-orange)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-332%20passing-brightgreen)](#testing)

</div>

---

> **⚠️ WARNING**: This is a **software emulator** for educational and training purposes only. It does **NOT** provide the physical security guarantees of a real Hardware Security Module. All key material is stored in software and is only as secure as the host system. **Never use this in production environments.**

---

## Table of Contents

- [Key Features](#key-features)
- [Quick Start](#quick-start)
- [Two Shells: lunacm and lunash](#two-shells-lunacm-and-lunash)
- [lunacm Command Reference](#lunacm-command-reference)
- [LunaSH Command Reference](#lunash-command-reference)
- [Example Session](#example-session)
- [Supported Algorithms](#supported-algorithms)
- [Authentication Model](#authentication-model)
- [Architecture](#architecture)
- [Testing](#testing)
- [Training Exercises](#training-exercises)
- [Technology Stack](#technology-stack)
- [Disclaimer](#disclaimer)

---

## Key Features

### Real Cryptography via PKCS#11 v2.40

Every operation uses real cryptographic algorithms through `pyca/cryptography` (OpenSSL). The full PKCS#11 v2.40 API is implemented — `C_Initialize` through `C_DeriveKey` — with accurate `CKR_*` return codes.

| Capability | Details |
|-----------|---------|
| **Symmetric** | AES (128/192/256, ECB/CBC/CTR/GCM), 3DES, DES, AES-CMAC |
| **Asymmetric** | RSA (1024–4096, PKCS#1 v1.5/PSS/OAEP), ECC (P-256/P-384/P-521/secp256k1, ECDSA/ECDH), DSA |
| **Hashing & MAC** | SHA-1/224/256/384/512, HMAC-SHA256/384/512, AES-CMAC |
| **Key Derivation** | PBKDF2 (RFC 2898), HKDF (RFC 5869), SP800-108 Counter Mode |
| **Key Operations** | Generate, wrap/unwrap, derive, import/export with extraction policies |

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
- **Interface binding** — bind NTLS to eth0–eth3, bond0, bond1, or all interfaces
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

- Full lifecycle states: uninitialized, initialized with pending roles, ready, and deactivated
- PPSO partitions with separate Partition SO, CO, and optional CU identities
- Legacy partitions with a combined Partition Owner/CO identity
- Superior-role authorization for role initialization, deactivation, reactivation, lockout reset, and SO reset
- Partition deletion requires an authenticated HSM SO
- Accurate object-count and persisted-byte storage quota enforcement
- Cloning-domain initialization and inheritance are included in partition status
- **30-policy catalog** matching Luna 7 capabilities, including destructive changes and mutual exclusion
- **Partition Policy Templates (PPT)** — predefined sets (FIPS Strict, High Security, Development, Backup Ready) plus custom templates

```text
partition show -partition app1
```

### Role-Based Authentication

Four-role hierarchy with PIN lockout policies and PED (PIN Entry Device) simulation:

| Role | Capabilities |
|------|-------------|
| **HSO** (HSM Security Officer) | Full HSM administration, factory reset, partition creation |
| **SO** (Partition Security Officer) | Partition initialization, PIN management |
| **CO** (Crypto Officer) | Key generation, deletion, wrapping, attribute management |
| **CU** (Crypto User) | Cryptographic operations only (encrypt, decrypt, sign, verify) |

### Cloning Domains, Backup, and High Availability

- HSM-level cloning domains inherited by new partitions, with optional partition overrides
- Password-derived domains and Red PED-key domains
- Direct secure partition-to-partition cloning only when domain fingerprints match
- Cloning-policy enforcement for private and secret keys
- Backup and HA synchronization use the same domain-matching rules
- Domain changes on populated partitions require explicit destructive zeroization

Cloning is distinct from wrapping: secure cloning can transfer sensitive, non-extractable objects inside the emulated security boundary, while wrapping exports an encrypted key blob. Backup stores an offline recoverable clone.

```text
partition domain show
partition domain set
partition clone -source 1 -destination 2
```

Domain mismatches return `LUNA_RET_CLONING_DOMAIN_MISMATCH`.

### Backup HSM

Luna Backup HSM 7 emulation with STM recovery, secure cloning-based backup/restore, firmware management, and factory reset.

### High Availability

HA groups are real client-side virtual slots, not just configuration:

- Each group gets an immutable **virtual slot** (`1000000+`) that applications open like any other slot; `C_Login`, `C_GenerateKey`, `C_Encrypt`, `C_Sign`, `C_FindObjects`, etc. are dispatched to healthy members
- **Logical key handles** are stable across members and failover (mapped by cloning identity, never by label)
- **HA Only** (`hagroup haonly -enable`) hides member slots from applications; LunaCM still sees them
- Multipart operations (`C_SignUpdate` …) migrate to another member if the current one fails mid-operation
- Key mutations replicate immediately to reachable members; deletions are tombstoned so recovery cannot resurrect keys
- Application-driven recovery honours the retry budget and poll interval (no sleeping inside crypto calls)
- Session objects stay local to one member and are destroyed on session close
- Round-robin load balancing and active/standby routing modes
- Automatic failover with operation and failover counters
- Per-member active, standby, unavailable, recovering, and incompatible states
- Automatic or manual failed-member recovery with retry tracking
- Cloning-domain key replication and per-member synchronization status
- Partial synchronization results when only some members can be updated
- Simulated network partitions and restoration
- Firmware and partition-policy compatibility checks
- Session objects remain local to the selected member and are never replicated

```text
hagroup creategroup -label production-ha -slot 1 -password <co>
hagroup addmember -group production-ha -slot 2 -password <co>
hagroup haonly -enable
hagroup recover -group production-ha
ha status -name production-ha
ha operation -name production-ha -operation sign
ha network -name production-ha -slot 2 -state partitioned
ha recover -name production-ha -slot 2
```

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

- **`--explain` flag**: Shows underlying PKCS#11 function calls, attributes, mechanisms, and security implications
- **Accurate return codes**: All operations return proper `CKR_*` codes with human-readable descriptions

---

## Quick Start

### Prerequisites

- **Python 3.10+**
- **pip** (Python package installer)

### Installation

```bash
git clone https://github.com/vstoms/luna-hsm-emulator.git
cd luna-hsm-emulator
pip install -r luna-hsm-emulator/requirements.txt
```

### Initialize the HSM

```bash
cd luna-hsm-emulator
python hsm_emulator.py --init
```

You'll be prompted for:
1. A **master password** — encrypts all key material at rest (PBKDF2, 100,000 iterations)
2. An **SO PIN** — Security Officer for the default partition
3. A **CO PIN** — Crypto Officer for the default partition

### Launch the Interactive Shell

```bash
python hsm_emulator.py
```

```
  ╔══════════════════════════════════════════════════════════════════╗
  ║         Thales Luna 7 Network HSM Emulator — lunacm             ║
  ║         Firmware 7.13.0  |  PKCS#11 v2.40  |  Training Use       ║
  ║                                                                  ║
  ║  WARNING: This is a software emulator for educational purposes    ║
  ║           only. It must NOT be used in production environments.  ║
  ╚══════════════════════════════════════════════════════════════════╝

  Type 'help' for command reference, 'exit' to quit.
LunaCM Emulator v7.x >
```

### Run a Single Command (Non-Interactive)

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

### Slot & Partition Management

```text
slot list                          # List all available slots/partitions
slot set -slot <id>                # Set active slot
partition create -name <name>     # Create a new partition
partition delete -name <name>     # Delete a partition
partition list                     # List all partitions
partition showinfo                 # Show partition details and storage usage
partition showpolicies [-verbose]  # Show partition policies
partition changepolicy -policy <id> -value <value> [-force]
partition policytemplate list|show|apply|create|delete
```

### Authentication

```text
role login -name co               # Login as Crypto Officer
role login -name cu               # Login as Crypto User
role login -name so               # Login as Security Officer
role logout                       # Logout current role
role changepw -name <role>        # Change role password
```

### Key Operations

```text
key generate -kt aes -ks 256 -label <name>           # Generate AES key
key generate -kt rsa -ks 2048 -label <name>          # Generate RSA key pair
key generate -kt ec -curve P-256 -label <name>       # Generate EC key pair
key generate -kt des3 -ks 192 -label <name>          # Generate 3DES key
key list                                             # List all key objects
key show -label <name>                               # Show key attributes
key delete -label <name>                             # Delete a key
key wrap -wrap-key <label> -target-key <label>       # Wrap a key
key unwrap -wrap-key <label> -file <file>            # Unwrap a key
```

### Cryptographic Operations

```text
crypto encrypt -key <label> -mech AES_GCM -in <file> [-out <file>]
crypto decrypt -key <label> -mech AES_GCM -in <file> [-out <file>]
crypto sign -key <label> -mech SHA256_RSA_PKCS -in <file> [-out <file>]
crypto verify -key <label> -mech SHA256_RSA_PKCS -in <file> -sig <file>
crypto digest -mech SHA256 -in <file>
```

### Audit & HSM Management

```text
audit log show                     # Display audit log
audit log clear                    # Clear audit log
audit log verify                   # Verify hash chain integrity
hsm show                           # Show HSM firmware/model info
hsm factoryreset                   # Reset HSM to factory defaults
hsm export -file <path>            # Export HSM state for backup
hsm import -file <path>            # Import HSM state for restore
hsm firmware show                  # Show current firmware details
hsm firmware list                  # List all available firmware versions
hsm firmware upgrade -version <v>  # Upgrade firmware to specified version
hsm firmware rollback              # Roll back to previous firmware
hsm firmware history               # Show firmware upgrade history
hsm supportInfo                    # Generate sanitized support bundle
```

### Backup HSM

```text
backup connect                     # Connect Luna Backup HSM 7
backup stm show                    # Show Secure Transport Mode status
backup stm recover -string <s>     # Recover from STM
backup init                        # Initialize backup HSM (set SO PIN)
backup login                       # Login to backup HSM as SO
backup show                        # Show backup HSM status
backup backup -slot <id> -domain <d>   # Back up objects
backup restore -slot <id> -domain <d>  # Restore objects
backup list                        # List objects on backup HSM
backup firmware show               # Show backup HSM firmware
backup firmware upgrade -version <v>
backup firmware rollback           # Rollback (destructive — erases backups)
backup factoryreset                # Factory reset backup HSM
backup disconnect                  # Disconnect backup HSM
```

> **Tip:** Append `--explain` to any command for educational PKCS#11 output showing the underlying function calls, attributes, mechanisms, and security implications.

---

## LunaSH Command Reference

LunaSH is the server-side appliance shell. Start it with `python hsm_emulator.py --lunash`.

### Appliance Login & Status

```text
login                              # Login to appliance (SSH-style)
logout                             # Logout
status cpu|mem|disk|date|interface  # System status
```

### HSM Management

```text
hsm login                          # Login as HSM Security Officer
hsm logout                         # Logout of HSM
hsm show                           # Show HSM info
hsm init                           # Initialize HSM (set SO PIN)
partition create -name <name>      # Create a partition
partition list                     # List partitions
```

### User Management (RBAC)

```text
user list                          # List appliance users
user add -name <name> -role <role> # Add user (admin/operator/monitor/audit)
user delete -name <name>
user enable|disable -name <name>
```

### Client Management

```text
client register -name <name> -ip <ip>           # Register HSM client
client assignPartition -name <name> -partition <id>
client revokePartition -name <name> -partition <id>
client list
client show -name <name>
client delete -name <name>
```

### NTLS Certificate & Connections

```text
ntls show                          # Show NTLS status, bound interfaces, certificate
ntls bind <eth0|eth1|eth2|eth3|bond0|bond1|all>   # Bind NTLS to interface(s)
ntls unbind <interface>            # Unbind NTLS from an interface
ntls certificate show              # Show NTLS server certificate details
ntls certificate regenerate        # Regenerate certificate (breaks all connections)

sysconf regenCert [-force] [-csr] [-hostname <h>] [-keytype RSA|EC] [-keysize <n>]
  [-curve <name>] [-days <n>] [-country <c>] [-state <s>] [-location <l>]
  [-organization <o>] [-orgunit <u>] [-email <e>] [-san <san>]

ntls connection create -client <name> -slot <id> [-cert self-signed|ca-signed] [-ip <ip>] [-hostname <h>]
ntls connection list
ntls connection connect -client <name> -slot <id>
ntls connection disconnect -client <name> -slot <id>
ntls connection restore -client <name> -slot <id>
ntls connection show -client <name> -slot <id>
ntls connection delete -client <name> -slot <id>
```

### STC (Secure Trusted Channel)

```text
stc enable|disable|show
stc identity create -type client|partition -name <name>
stc identity list|show|export|delete
stc connection create -client <name> -partition <name> -slot <id>
stc connection list|connect|disconnect|restore|delete
stc cipher show|enable <name>|disable <name>
stc hmac show|enable|disable
stc rekeyThreshold set <n>|show
stc activationTimeOut set <n>|show
stc convert -client <name> -slot <id>     # Convert NTLS to STC (irreversible)
stc admin show
```

### Network & System Configuration

```text
network show                       # Show network configuration
network hostname <name>            # Set hostname
network interface static <iface> -ip <ip> -netmask <mask> [-gateway <gw>]
network interface dhcp <iface>
network dns add|delete <server>
network route add|delete <destination>
sysconf timezone set <tz>
sysconf banner add <text>|clear|show
sysconf ssh port <port>|show
sysconf appliance reboot|poweroff
```

### Services & Syslog

```text
service list|start|stop|restart|status <name>
syslog show
syslog severity set <level>
syslog remotehost add|delete|list <host>
syslog rotate
```

### High Availability

```text
ha create -name <name> -slot <id> [-label <label>]
ha addmember -name <name> -slot <id>
ha removemember -name <name> -slot <id>
ha list|show -name <name>|status -name <name>
ha setretry -name <name> -retry <n>       # -1 for infinite
ha setinterval -name <name> -interval <n>
ha synchronize -name <name>
ha delete -name <name>
```

### NTP, Bonding, Licenses

```text
ntp show|add|delete|enable|disable|sync
bond show|configure|enable|disable|delete
license list|show|setlimit|enable|disable
```

### Packages & Audit

```text
package list|verify|update|listfile|deletefile|erase
audit login|logout|show|log
my password set
```

---

## Example Session

Here's a complete walkthrough showing key generation, encryption, and signing:

```text
LunaCM Emulator v7.x > slot list
  Slot     Description                              Partition
  ----------------------------------------------------------------------
  1        Luna Partition partition1                partition1

  No active slot set. Use 'slot set -slot <id>' to select one.

LunaCM Emulator v7.x > slot set -slot 1
  Active slot set to 1.

LunaCM Emulator v7.x > role login -name co
  [PED Simulation] Enter PIN for role 'CO':
  PIN: ********
  Logged in as CO.

LunaCM Emulator v7.x > key generate -kt aes -ks 256 -label mykey --explain
  [EXPLAIN] Calling C_GenerateKey with mechanism CKM_AES_KEY_GEN
  [EXPLAIN] Template attributes:
            CKA_CLASS = CKO_SECRET_KEY
            CKA_KEY_TYPE = CKK_AES
            CKA_VALUE_LEN = 32 (256 bits)
            CKA_TOKEN = TRUE (persistent storage)
            CKA_SENSITIVE = TRUE (key cannot be read in plaintext)
            CKA_EXTRACTABLE = FALSE (key cannot leave HSM)
  [EXPLAIN] Return code: CKR_OK (0x00000000)
  [EXPLAIN] Security Note: Setting CKA_EXTRACTABLE=FALSE ensures this key
            never leaves the HSM boundary, a core HSM security guarantee.

  Key 'mykey' generated successfully. Handle: 0x00000001

LunaCM Emulator v7.x > key generate -kt rsa -ks 2048 -label rsakey
  RSA key pair 'rsakey' generated successfully.
  Private key handle: 0x00000002
  Public  key handle: 0x00000003

LunaCM Emulator v7.x > key list
  Handle       Label                   Class            Key Type        Sensitive  Extractable
  ------------------------------------------------------------------------------------------
  0x00000001   mykey                   CKO_SECRET_KEY   CKK_AES          Yes        No
  0x00000002   rsakey                  CKO_PRIVATE_KEY  CKK_RSA          Yes        No
  0x00000003   rsakey                  CKO_PUBLIC_KEY   CKK_RSA           No        No

LunaCM Emulator v7.x > audit log show
  ID    Timestamp             Sess  Role         Operation                       Object               Result   Hash
  ------------------------------------------------------------------------------------------------------------------------
  5     2026-09-02 12:00:05    1     CO           C_GenerateKey                   rsakey               SUCCESS  a1b2c3d4e5f6...
  4     2026-09-02 12:00:03    1     CO           C_GenerateKey                   mykey                SUCCESS  9f8e7d6c5b4a...
  3     2026-09-02 12:00:01    1     CO           C_Login                                              SUCCESS  3a2b1c0d9e8f...
  2     2026-09-02 12:00:00    1     anonymous    C_OpenSession                                        SUCCESS  7a6b5c4d3e2f...
  1     2026-09-02 11:59:59    0     anonymous    C_OpenSession                                        SUCCESS  1a2b3c4d5e6f...

  Chain integrity: VERIFIED
```

---

## Supported Algorithms

### Symmetric Encryption

| Algorithm | Key Sizes | Modes |
|-----------|-----------|-------|
| **AES** | 128, 192, 256-bit | ECB, CBC, CBC-PAD, CTR, GCM |
| **3DES** | 112, 168-bit | ECB, CBC, CBC-PAD |
| **DES** | 56-bit (legacy) | ECB, CBC |

### Asymmetric Cryptography

| Algorithm | Key Sizes | Operations |
|-----------|-----------|------------|
| **RSA** | 1024, 2048, 3072, 4096-bit | Sign/Verify (PKCS#1 v1.5, PSS), Encrypt/Decrypt (PKCS#1 v1.5, OAEP) |
| **ECC** | P-256, P-384, P-521, secp256k1 | ECDSA sign/verify, ECDH key agreement |
| **DSA** | 1024, 2048, 3072-bit | Sign/Verify |

### Hashing & MAC

| Algorithm | Output Size |
|-----------|-------------|
| SHA-1 | 160-bit |
| SHA-224 | 224-bit |
| SHA-256 | 256-bit |
| SHA-384 | 384-bit |
| SHA-512 | 512-bit |
| HMAC-SHA256 | 256-bit |
| HMAC-SHA384 | 384-bit |
| HMAC-SHA512 | 512-bit |
| AES-CMAC | 128-bit |

### Key Derivation

| KDF | Standard |
|-----|----------|
| PBKDF2 | RFC 2898 |
| HKDF | RFC 5869 |
| SP800-108 | NIST SP 800-108 (Counter Mode) |

---

## Authentication Model

The emulator implements the Luna 7's four-role authentication hierarchy:

```
┌─────────────────────────────────────────────────┐
│                    HSM                           │
│  ┌─────────────────────────────────────────────┐ │
│  │  HSO (HSM Security Officer)                 │ │
│  │  Full administrative access                  │ │
│  └──────────────┬──────────────────────────────┘ │
│                 │                                 │
│  ┌──────────────▼──────────────────────────────┐ │
│  │  Partition 1    Partition 2    Partition N  │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  │ │
│  │  │  SO      │  │  SO      │  │  SO      │  │ │
│  │  │  CO      │  │  CO      │  │  CO      │  │ │
│  │  │  CU      │  │  CU      │  │  CU      │  │ │
│  │  │  Keys    │  │  Keys    │  │  Keys    │  │ │
│  │  └──────────┘  └──────────┘  └──────────┘  │ │
│  └─────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────┘
```

The HSM can be initialized in password-authenticated or PED-authenticated mode. Password authentication includes configurable lockout policies (default: 10 failed attempts before lockout).

### PED authentication and M-of-N quorum

PED mode persists local/remote PED state and colored key sets:

| Color | Identity |
|-------|----------|
| Blue | HSM or partition Security Officer |
| Black | Crypto Officer |
| Gray | Crypto User |
| Red | Cloning domain |
| Orange | Remote PED vector |
| White | Audit identity |

Each key set supports an M-of-N threshold, an optional shared secret, and duplicate physical keys. A duplicate is another copy of the same share and therefore does not count twice toward quorum. Keys can be marked lost; status output reports whether enough distinct shares remain. Red key validation produces a specific cloning-domain mismatch error, and remote connections require an Orange key set.

```text
hsm init -label TrainingHSM -ped
ped connect
ped key create -type blue -m 2 -n 3
hsm login
```

Additional commands:

```text
ped show
ped key list
ped key create -type red -m 2 -n 3 -sharedsecret
ped key duplicate -serial BL-12345678 -count 2
ped key lose -serial BL-12345678
ped disconnect
ped connect -remote ped.example.test -keys OR-12345678
```

For partition roles, create key sets with `-scope <slot-id>`. LunaCM's role login accepts the matching Blue, Black, or Gray serials and prompts for a shared secret when configured.

### PED activation and auto-activation

Mirrors the Luna activation lifecycle for CO/LCO/CU on PED-authenticated partitions:

- **Partition policy 22** enables activation; the PO sets the CO challenge secret and the CO sets CU/LCO secrets (`role createchallenge -name <role>`)
- First login requires **both** the challenge secret and the PED-key quorum; the quorum proof is then cached and later logins need only the challenge secret
- `role deactivate` clears the cache (the role stays initialized); disabling policy 22 clears it too
- **Partition policy 23** (auto-activation) lets the cache survive `sysconf appliance reboot`/`poweroff` for at most two hours of downtime (`sysconf appliance reboot -downtime <seconds>` for training)
- A tamper (`hsm tamper simulate|clear|show` in LunaSH) zeroizes all caches and invalidates every application session
- Failed challenge responses count towards lockout unless policy 15 is on; the superior role resets with `role resetchallenge`
- Challenge secrets are stored as salted hashes; cached quorum proofs are encrypted at rest and never logged

```text
role login -name po
partition changepolicy -policy 22 -value 1
role createchallenge -name co
role logout
role login -name co        # challenge + Black PED keys once, challenge only afterwards
```

---

## Architecture

```
luna-hsm-emulator/
├── hsm_emulator.py              # Main entry point
├── pkcs11/
│   ├── api.py                   # PKCS#11 v2.40 function implementations
│   ├── mechanisms.py            # Cryptographic mechanism definitions
│   ├── objects.py               # CK object classes (keys, certs, data)
│   └── constants.py             # CKR_, CKA_, CKM_, CKO_ constants
├── hsm/
│   ├── ha.py                    # HA virtual slots: dispatch, logical handles, failover
│   ├── activation.py            # PED activation cache, challenge secrets, power/tamper events
│   ├── token.py                 # Token/partition management, firmware
│   ├── session.py               # Session management
│   ├── auth.py                  # Role-based authentication
│   ├── ped.py                   # PED colors, M-of-N key sets, local/remote state
│   ├── domain.py                # Cloning domains and secure object cloning
│   ├── lifecycle.py             # Partition types, lifecycle, and role states
│   ├── keystore.py              # Key storage and retrieval
│   ├── audit.py                 # Audit logging with hash chaining
│   ├── appliance.py             # Luna 7 appliance emulation (users, network, NTLS, services)
│   ├── connections.py           # NTLS and STC client-partition connections
│   ├── policies.py              # Partition capabilities and policies catalog (30 policies)
│   ├── backup.py                # Luna Backup HSM 7 emulation
│   └── deployment.py            # HA groups, NTP, bonding, licenses, support bundles
├── cli/
│   ├── lunacm.py                # Interactive lunacm shell
│   ├── lunash.py                # Interactive LunaSH appliance shell
│   ├── commands.py              # lunacm command handlers
│   └── lunash_commands.py       # LunaSH command handlers
├── crypto/
│   ├── symmetric.py             # AES, 3DES, DES, CMAC
│   ├── asymmetric.py            # RSA, ECC, DSA
│   ├── digest.py                # Hashing and MAC operations
│   └── kdf.py                   # Key derivation functions
├── storage/
│   └── db.py                    # SQLite persistence with AES-GCM encryption
├── tests/
│   ├── test_pkcs11.py           # PKCS#11 and appliance tests
│   ├── test_ped.py              # PED and quorum tests
│   ├── test_domain.py           # Domain and cloning tests
│   ├── test_lifecycle.py        # Partition lifecycle and quota tests
│   ├── test_ha_behavior.py      # HA routing, failover, and synchronization tests
│   ├── test_ha_operations.py    # Real PKCS#11 operations through HA virtual slots
│   └── test_activation.py       # PED challenge secrets, activation cache, reboot/tamper
├── requirements.txt
└── README.md
```

### Data Flow

```
CLI Command → Command Handler → PKCS#11 API → Crypto Layer
                                        ↓
                              HSM Modules (Session, Token, Auth, Keystore, Audit)
                                        ↓
                              Storage Layer (SQLite + AES-256-GCM encrypted blobs)
```

---

## Testing

Run the full test suite:

```bash
cd luna-hsm-emulator
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
| `HAOperationsTest` | 10 | Virtual slots, HA Only, logical handles, multipart failover, tombstones, retry budget |
| `ActivationTest` | 16 | Challenge secrets, cached quorum, auto-activation window, poweroff, tamper, lockout |

```
Ran 332 tests in 7.6s

OK
```

---

## Training Exercises

The emulator includes **31 hands-on training exercises**. Exercises 1–21 teach individual capabilities; exercises 22–31 combine them into realistic commissioning changes, key ceremonies, outages, certificate rotations, lockout recovery, and decommissioning. See the [detailed exercise guide](luna-hsm-emulator/README.md#training-exercises) for step-by-step instructions.

| # | Exercise | Skills Learned |
|---|----------|---------------|
| 1 | Initialize and Explore the HSM | Basic navigation, HSM info |
| 2 | Generate an AES Key with `--explain` | Key generation, PKCS#11 attributes |
| 3 | Encrypt and Decrypt with AES-GCM | Symmetric encryption through HSM |
| 4 | RSA Key Pair and Signing | Asymmetric crypto, digital signatures |
| 5 | EC Key Pair and ECDSA Signing | Elliptic curve cryptography |
| 6 | Key Wrapping and Unwrapping | Secure key transport between HSMs |
| 7 | Hash Digest Operations | PKCS#11 digest mechanisms |
| 8 | Role Management and PIN Security | RBAC, PIN lockout policies |
| 9 | Audit Log Inspection | Tamper-evident logging, hash chain verification |
| 10 | Multi-Partition Management | Multi-tenant isolation |
| 11 | Export and Import HSM State | Backup and restore |
| 12 | Factory Reset | HSM lifecycle management |
| 13 | Firmware Upgrade and Rollback | HSM firmware lifecycle, pre-checks, staged upgrade |
| 14 | Backup HSM Operations | Luna Backup HSM 7, cloning, backup/restore, STM recovery |
| 15 | Partition Capabilities and Policies | Full policy catalog, destructive changes, PPT templates |
| 16 | LunaSH Appliance Management | Server-side shell, users, network, clients, services, RBAC |
| 17 | Client-Partition Connections | NTLS and STC channels, certificates, identities, conversion |
| 18 | High Availability Groups | HA group creation, member management, retry/polling, synchronization |
| 19 | NTP Configuration | NTP server management, enable/disable, synchronization |
| 20 | Network Bonding | Interface bonding for redundancy, bond0/bond1 configuration |
| 21 | Licenses and Support | License management, support-bundle generation |
| 22 | Day-One Appliance Commissioning | Ordered network, time, logging, RBAC, partition, NTLS, and client setup |
| 23 | PED Partition Onboarding | Custodian key sets, activation policy, challenge secrets, initial quorum |
| 24 | Planned Maintenance Reboot | Auto-activation validation and the two-hour outage boundary |
| 25 | Production HA Outage | Virtual slots, HA Only, live failover, mutation recovery, deletion tombstones |
| 26 | Tamper Incident Response | Session invalidation, controlled recovery, fresh quorum, audit evidence |
| 27 | NTLS Certificate Rotation | Trust-impact inventory, certificate renewal, client restoration |
| 28 | PED Custodian Offboarding | Lost-share analysis, duplication, replacement-key ceremony |
| 29 | Crypto Officer Lockout | Superior-role credential reset and incident audit trail |
| 30 | Signing-Key Ceremony | Restrictive key templates, negative export test, backup and evidence |
| 31 | Partition Decommissioning | Revoke access, destroy keys, verify evidence, release capacity |

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.10+ |
| Cryptography | `pyca/cryptography` (OpenSSL backend) |
| CLI Framework | Python `cmd` module (tab-completion, history) |
| Storage | SQLite via `sqlite3` |
| Key Encryption | AES-256-GCM with PBKDF2-derived master key |
| Audit Logging | SHA-256 hash-chained entries |
| Serialization | JSON with encrypted binary blobs |

---

## Disclaimer

This is a **software emulator** designed for **educational and training purposes only**.

- It does **not** provide the physical security guarantees (tamper resistance, side-channel protection, FIPS certification) of a real Hardware Security Module.
- All key material is stored in software and is only as secure as the host system.
- It should **never** be used in production environments.
- The Thales Luna 7 is a real product of Thales Group. This emulator is **not affiliated with or endorsed by Thales**.
- PKCS#11 is a standard maintained by OASIS. This implementation follows the v2.40 specification conceptually but is **not a certified implementation**.

---

## License

This project is released for educational use. See [LICENSE](LICENSE) for details.

---

<div align="center">

**Built for learning. Not for production.**

</div>
