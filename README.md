<div align="center">

# Thales Luna 7 Network HSM Emulator

A fully functional software emulator of the Thales Luna 7 Network HSM, built for **educational and training purposes**. Implements the complete PKCS#11 v2.40 API surface with real cryptographic operations, partition management, role-based authentication, and an interactive `lunacm` command shell.

[![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)](https://www.python.org/)
[![PKCS#11](https://img.shields.io/badge/PKCS%2311-v2.40-green)](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html)
[![License](https://img.shields.io/badge/License-Educational-orange)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-30%20passing-brightgreen)](#testing)

</div>

---

> **⚠️ WARNING**: This is a **software emulator** for educational and training purposes only. It does **NOT** provide the physical security guarantees of a real Hardware Security Module. All key material is stored in software and is only as secure as the host system. **Never use this in production environments.**

---

## Overview

Hardware Security Modules (HSMs) are specialized devices that safeguard and manage digital keys for strong authentication and provide cryptoprocessing. The Thales Luna 7 Network HSM is one of the industry's most widely deployed network-attached HSMs.

This emulator lets you **learn HSM operations** — partition management, key generation, encryption, signing, key wrapping, role-based access control, and audit logging — without needing access to expensive physical hardware. Every operation maps to real PKCS#11 function calls and returns accurate `CKR_*` return codes.

### What's Inside

| Component | Description |
|-----------|-------------|
| **PKCS#11 v2.40 API** | Full implementation of `C_Initialize` through `C_DeriveKey` — sessions, slots, objects, crypto, keys |
| **lunacm Shell** | Interactive CLI that mimics the real Luna Configuration Manager with tab-completion |
| **Real Cryptography** | AES, RSA, ECC, DSA, SHA, HMAC, CMAC, PBKDF2, HKDF — powered by `pyca/cryptography` (OpenSSL) |
| **Role-Based Auth** | HSO, Partition SO, Crypto Officer (CO), Crypto User (CU) with PIN lockout policies |
| **Firmware Upgrade** | Simulated firmware upgrade with pre-checks, staged progress, rollback, and history |
| **Backup HSM** | Luna Backup HSM 7 emulation with STM recovery, cloning, backup/restore, and firmware management |
| **Partition Policies** | Full 30-policy catalog matching Luna 7 capabilities, with destructive changes, mutual exclusion, and PPT templates |
| **LunaSH** | Server-side appliance shell with users, network, NTLS, clients, services, syslog, and RBAC |
| **Client-Partition Connections** | NTLS and STC connection management with certificates, identities, lifecycle, and NTLS-to-STC conversion |
| **High Availability** | HA groups with member management, retry/polling config, and synchronization |
| **Network Deployment** | NTP server management, network interface bonding (bond0/bond1) |
| **License Management** | License inventory, configurable limits, and enable/disable controls |
| **Support Diagnostics** | Sanitized support-bundle generation excluding all credentials and key material |
| **Partition Management** | Create, initialize, and delete named partitions with per-partition storage quotas |
| **Encrypted Storage** | SQLite database with AES-256-GCM encrypted key material blobs at rest |
| **Audit Logging** | Tamper-evident SHA-256 hash-chained audit log |
| **`--explain` Mode** | Educational output showing PKCS#11 internals, attributes, mechanisms, and security notes |

---

## Quick Start

### Prerequisites

- **Python 3.10+**
- **pip** (Python package installer)

### Installation

```bash
git clone https://github.com/yourusername/luna-hsm-emulator.git
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

## CLI Command Reference

### Slot & Partition Management

```text
slot list                          # List all available slots/partitions
slot set -slot <id>                # Set active slot
partition create -name <name>     # Create a new partition
partition delete -name <name>     # Delete a partition
partition list                     # List all partitions
partition showinfo                 # Show partition details and storage usage
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
```

> **Tip:** Append `--explain` to any command for educational PKCS#11 output showing the underlying function calls, attributes, mechanisms, and security implications.

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

| Role | Abbreviation | Capabilities |
|------|-------------|-------------|
| **HSM Security Officer** | HSO | Full HSM administration, factory reset, partition creation |
| **Partition Security Officer** | SO | Partition initialization, PIN management |
| **Crypto Officer** | CO | Key generation, deletion, wrapping, attribute management |
| **Crypto User** | CU | Cryptographic operations only (encrypt, decrypt, sign, verify) |

PIN-based authentication includes configurable lockout policies (default: 10 failed attempts before lockout). The CLI simulates PED (PIN Entry Device) prompts for realistic training.

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
│   ├── token.py                 # Token/partition management
│   ├── session.py               # Session management
│   ├── auth.py                  # Role-based authentication
│   ├── keystore.py              # Key storage and retrieval
│   └── audit.py                 # Audit logging with hash chaining
├── cli/
│   ├── lunacm.py                # Interactive lunacm shell
│   └── commands.py              # Command handlers
├── crypto/
│   ├── symmetric.py             # AES, 3DES, DES operations
│   ├── asymmetric.py            # RSA, ECC, DSA operations
│   ├── digest.py                # Hashing and MAC operations
│   └── kdf.py                   # Key derivation functions
├── storage/
│   └── db.py                    # SQLite persistence with AES-GCM encryption
├── tests/
│   └── test_pkcs11.py           # 267 unit tests
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

```
Ran 267 tests in 11.0s

OK
```

---

## Training Exercises

The emulator includes **21 hands-on training exercises** covering real-world HSM workflows. See the [detailed exercise guide](luna-hsm-emulator/README.md#training-exercises) for step-by-step instructions.

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

## Project Structure Deep Dive

### `pkcs11/` — PKCS#11 v2.40 API Layer

- **`constants.py`** — All `CKR_*`, `CKA_*`, `CKM_*`, `CKO_*`, `CKK_*`, `CKS_*` constants with human-readable name maps
- **`mechanisms.py`** — Mechanism registry with capability flags (generate, encrypt, sign, wrap, etc.)
- **`objects.py`** — `CKObject` class and template builders for AES, RSA, EC, 3DES, HMAC keys
- **`api.py`** — Full `PKCS11API` class implementing every `C_*` function

### `hsm/` — HSM Core Modules

- **`token.py`** — Partition (slot/token) management, HSM info, factory reset, firmware upgrade/rollback
- **`session.py`** — Multi-session support with R/W and R/O session types
- **`auth.py`** — Four-role authentication with PIN lockout and PED simulation
- **`keystore.py`** — Handle allocation, encrypted key material storage, quota enforcement
- **`audit.py`** — Hash-chained audit logger with chain verification
- **`appliance.py`** — Luna Network HSM 7 appliance emulation (users, network, NTLS, clients, services)
- **`policies.py`** — Partition capabilities and policies catalog (30 policies, PPT templates)
- **`backup.py`** — Luna Backup HSM 7 emulation (STM, backup/restore, firmware, factory reset)
- **`connections.py`** — NTLS and STC client-partition connection management
- **`deployment.py`** — HA groups, NTP, network bonding, licenses, and support-bundle generation

### `crypto/` — Cryptographic Operations

- **`symmetric.py`** — AES (ECB/CBC/CTR/GCM), 3DES, DES, CMAC
- **`asymmetric.py`** — RSA (sign/verify/encrypt/decrypt), EC (ECDSA/ECDH), DSA
- **`digest.py`** — SHA-1/256/384/512, HMAC, CMAC
- **`kdf.py`** — PBKDF2, HKDF, SP800-108 Counter Mode

### `storage/` — Persistence Layer

- **`db.py`** — SQLite storage with AES-256-GCM encrypted blobs, PIN hashing, audit chain, export/import

### `cli/` — Command-Line Interface

- **`lunacm.py`** — Interactive `cmd.Cmd`-based shell with tab-completion
- **`lunash.py`** — Interactive LunaSH appliance shell with tab-completion and command shortnames
- **`commands.py`** — All lunacm command handlers (slot, partition, role, key, crypto, audit, hsm, backup)
- **`lunash_commands.py`** — All LunaSH command handlers (status, hsm, partition, user, client, network, ntls, stc, ha, ntp, bond, license, sysconf, service, syslog, my, package, token, audit)

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
