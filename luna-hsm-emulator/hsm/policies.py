"""Partition Capabilities and Policies for the Luna 7 HSM emulator.

This module implements the full partition policy catalog as described in
the Thales Luna Network HSM 7 documentation. Each policy has:
  - A numeric ID (matching the real Luna 7 policy numbers)
  - A capability description (what the HSM hardware allows)
  - A policy description (what the Partition SO can configure)
  - A default value
  - Whether changing it is destructive (and in which direction)
  - Whether it's modifiable by the Partition SO

Capabilities are inherited from the parent HSM policies. If the HSM
disables a capability, the corresponding partition policy cannot be
enabled. We simulate HSM capabilities as always-enabled unless explicitly
disabled.

Policy Templates (PPT) allow consistent policy sets across partitions.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PartitionPolicy:
    """A single partition capability/policy pair."""
    policy_id: int
    name: str
    capability_desc: str
    policy_desc: str
    default_value: int  # 0 (Off) or 1 (On)
    destructive: str  # "none", "off-to-on", "on-to-off", "both"
    modifiable: bool = True
    value_type: str = "on/off"  # "on/off" or "integer"
    min_value: int = 0
    max_value: int = 1
    requires_capability: bool = True  # If False, no HSM capability dependency
    firmware_min: str = "7.0.0"  # Minimum firmware that supports this policy


# The complete partition policy catalog, matching the real Luna 7
# documentation. Policy IDs match the real Luna 7 numbering.
POLICY_CATALOG = [
    PartitionPolicy(
        policy_id=0,
        name="ALLOW_PRIVATE_KEY_CLONING",
        capability_desc="Enable private key cloning. Allows private keys to be cloned to another Luna HSM partition (required for backup and HA).",
        policy_desc="Allow private key cloning. If Off, private keys can never be cloned to another application partition. Policies 0 and 1 may not both be On.",
        default_value=1,
        destructive="off-to-on",
        firmware_min="7.1.0",
    ),
    PartitionPolicy(
        policy_id=1,
        name="ALLOW_PRIVATE_KEY_WRAPPING",
        capability_desc="Enable private key wrapping. Allows private keys to be encrypted (wrapped) and exported off the partition.",
        policy_desc="Allow private key wrapping. If On, private keys may be wrapped and saved to an encrypted file off the partition. Policies 0 and 1 may not both be On.",
        default_value=0,
        destructive="off-to-on",
        firmware_min="7.1.0",
    ),
    PartitionPolicy(
        policy_id=2,
        name="ALLOW_PRIVATE_KEY_UNWRAPPING",
        capability_desc="Enable private key unwrapping. Allows wrapped private keys to be imported to the partition.",
        policy_desc="Allow private key unwrapping. If Off, private keys cannot be unwrapped onto the partition.",
        default_value=1,
        destructive="none",
    ),
    PartitionPolicy(
        policy_id=3,
        name="ALLOW_PRIVATE_KEY_MASKING",
        capability_desc="Enable private key masking. Private keys can be masked off the partition.",
        policy_desc="Allow private key masking. If Off, private keys cannot be masked off the partition.",
        default_value=0,
        destructive="off-to-on",
    ),
    PartitionPolicy(
        policy_id=4,
        name="ALLOW_SECRET_KEY_CLONING",
        capability_desc="Enable secret key cloning. Allows secret keys to be cloned to another Luna HSM partition (required for backup and HA).",
        policy_desc="Allow secret key cloning. If Off, secret keys cannot be backed up or cloned to HA group members.",
        default_value=1,
        destructive="off-to-on",
    ),
    PartitionPolicy(
        policy_id=5,
        name="ALLOW_SECRET_KEY_WRAPPING",
        capability_desc="Enable secret key wrapping. Allows secret keys to be encrypted (wrapped) and exported off the partition.",
        policy_desc="Allow secret key wrapping. If Off, secret keys can never be wrapped and exported off the partition.",
        default_value=0,
        destructive="off-to-on",
    ),
    PartitionPolicy(
        policy_id=6,
        name="ALLOW_SECRET_KEY_UNWRAPPING",
        capability_desc="Enable secret key unwrapping. Allows wrapped secret keys to be imported to the partition.",
        policy_desc="Allow secret key unwrapping. If Off, secret keys cannot be unwrapped onto the partition.",
        default_value=1,
        destructive="none",
    ),
    PartitionPolicy(
        policy_id=7,
        name="ALLOW_SECRET_KEY_MASKING",
        capability_desc="Enable secret key masking. Secret keys can be masked off the partition.",
        policy_desc="Allow secret key masking. If Off, secret keys cannot be masked off the partition.",
        default_value=0,
        destructive="off-to-on",
    ),
    PartitionPolicy(
        policy_id=8,
        name="ALLOW_DIGEST_KEY",
        capability_desc="Enable DigestKey. Enables the C_DigestKey function to hash a symmetric key and return the hash to the calling application.",
        policy_desc="Allow DigestKey. If Off, key derivation functions cannot use DigestKey. Only FIPS-compliant hashes are allowed.",
        default_value=0,
        destructive="off-to-on",
        firmware_min="7.8.0",
    ),
    PartitionPolicy(
        policy_id=9,
        name="ALLOW_MULTIPURPOSE_KEYS",
        capability_desc="Enable multipurpose keys. Allows keys to have more than one operation attribute enabled (e.g., sign+encrypt, decrypt+verify).",
        policy_desc="Allow multipurpose keys. If Off, keys can only have one operation attribute enabled at a time.",
        default_value=1,
        destructive="on-to-off",
    ),
    PartitionPolicy(
        policy_id=10,
        name="ALLOW_CHANGING_KEY_ATTRIBUTES",
        capability_desc="Enable changing key attributes. Allows the Crypto Officer to modify non-sensitive attributes of keys on the partition.",
        policy_desc="Allow changing key attributes. If Off, keys created on the partition cannot be modified.",
        default_value=1,
        destructive="on-to-off",
    ),
    PartitionPolicy(
        policy_id=11,
        name="ALLOW_FAILED_CHALLENGE_RESPONSES",
        capability_desc="Allow failed challenge responses. Determines whether failed login attempts using a challenge secret count towards a partition lockout.",
        policy_desc="Allow failed challenge responses. Applies to multifactor quorum-authenticated HSMs only.",
        default_value=1,
        destructive="none",
    ),
    PartitionPolicy(
        policy_id=12,
        name="ALLOW_OPERATION_WITHOUT_RSA_BLINDING",
        capability_desc="Enable operation without RSA blinding. RSA blinding introduces random elements into the signature process to prevent timing attacks.",
        policy_desc="Allow operation without RSA blinding. If Off, RSA blinding is always applied (affects performance but improves security).",
        default_value=0,
        destructive="off-to-on",
    ),
    PartitionPolicy(
        policy_id=13,
        name="ALLOW_SIGNING_WITH_NON_LOCAL_KEYS",
        capability_desc="Enable signing with non-local keys. Keys generated on the HSM have CKA_LOCAL=1; imported keys have CKA_LOCAL=0.",
        policy_desc="Allow signing with non-local keys. If Off, only keys with CKA_LOCAL=1 can be used to sign data on the partition.",
        default_value=1,
        destructive="on-to-off",
    ),
    PartitionPolicy(
        policy_id=14,
        name="ALLOW_RAW_RSA_OPERATIONS",
        capability_desc="Enable raw RSA operations. Enables CKM_RSA_X_509 on the partition, which allows weak encryption.",
        policy_desc="Allow raw RSA operations. If Off, operations using CKM_RSA_X_509 are blocked on the partition.",
        default_value=0,
        destructive="off-to-on",
    ),
    PartitionPolicy(
        policy_id=15,
        name="ALLOW_HIGH_AVAILABILITY_RECOVERY",
        capability_desc="Enable high availability recovery. Enables the RecoveryLogin feature on the partition for HA group members to restore login state.",
        policy_desc="Allow high availability recovery. If Off, RecoveryLogin is disabled on the partition.",
        default_value=1,
        destructive="none",
    ),
    PartitionPolicy(
        policy_id=16,
        name="ALLOW_ACTIVATION",
        capability_desc="Enable activation. Allows the partition to be activated, so PED keys need not be presented at each login.",
        policy_desc="Allow activation. If Off, PED keys must be presented at each login.",
        default_value=1,
        destructive="none",
    ),
    PartitionPolicy(
        policy_id=17,
        name="ALLOW_AUTO_ACTIVATION",
        capability_desc="Enable auto-activation. Allows the partition to be automatically activated on HSM reboot.",
        policy_desc="Allow auto-activation. If Off, the partition must be manually activated after each reboot.",
        default_value=0,
        destructive="none",
    ),
    PartitionPolicy(
        policy_id=18,
        name="ALLOW_QUORUM",
        capability_desc="Enable quorum. Allows multifactor quorum authentication for partition operations.",
        policy_desc="Allow quorum. If Off, quorum authentication is disabled for the partition.",
        default_value=0,
        destructive="none",
    ),
    PartitionPolicy(
        policy_id=19,
        name="ALLOW_FORCE_PIN_CHANGE",
        capability_desc="Enable force PIN change. Forces a PIN change on first login after initialization.",
        policy_desc="Allow force PIN change. If On, the CO must change their PIN on first login after partition initialization.",
        default_value=0,
        destructive="none",
    ),
    PartitionPolicy(
        policy_id=20,
        name="ALLOW_PIN_RESET_VIA_PED",
        capability_desc="Enable PIN reset via PED. Allows the Partition SO to reset the CO PIN using the PED.",
        policy_desc="Allow PIN reset via PED. If Off, PIN reset must be done via LunaCM.",
        default_value=1,
        destructive="none",
    ),
    PartitionPolicy(
        policy_id=21,
        name="ALLOW_NETWORK_CONNECTION",
        capability_desc="Enable network connection. Allows the partition to accept network-based client connections.",
        policy_desc="Allow network connection. If Off, only local client connections are accepted.",
        default_value=1,
        destructive="none",
    ),
    PartitionPolicy(
        policy_id=22,
        name="ALLOW_THRESHOLD_LOGIN",
        capability_desc="Enable threshold login. Allows threshold-based login for multifactor quorum authentication.",
        policy_desc="Allow threshold login. If Off, threshold-based login is disabled.",
        default_value=0,
        destructive="none",
    ),
    PartitionPolicy(
        policy_id=23,
        name="MIN_PIN_LENGTH",
        capability_desc="Minimum PIN length. The minimum length of PINs for roles on this partition.",
        policy_desc="Minimum PIN length. Sets the minimum number of characters required for a PIN.",
        default_value=4,
        modifiable=True,
        value_type="integer",
        min_value=4,
        max_value=32,
        destructive="none",
    ),
    PartitionPolicy(
        policy_id=24,
        name="MAX_PIN_LENGTH",
        capability_desc="Maximum PIN length. The maximum length of PINs for roles on this partition.",
        policy_desc="Maximum PIN length. Sets the maximum number of characters allowed for a PIN.",
        default_value=32,
        modifiable=False,
        value_type="integer",
        min_value=4,
        max_value=32,
        destructive="none",
    ),
    PartitionPolicy(
        policy_id=25,
        name="MAX_LOGIN_ATTEMPTS",
        capability_desc="Maximum login attempts. The number of failed login attempts before the role is locked.",
        policy_desc="Maximum login attempts. Sets the number of failed login attempts before the role PIN is locked.",
        default_value=10,
        modifiable=True,
        value_type="integer",
        min_value=1,
        max_value=100,
        destructive="none",
    ),
    PartitionPolicy(
        policy_id=26,
        name="ALLOW_KEY_USAGE_COUNT",
        capability_desc="Enable key usage count. Allows tracking the number of times a key is used for cryptographic operations.",
        policy_desc="Allow key usage count. If Off, key usage is not tracked.",
        default_value=0,
        destructive="none",
    ),
    PartitionPolicy(
        policy_id=27,
        name="ALLOW_KEY_USAGE_LIMIT",
        capability_desc="Enable key usage limit. Allows setting a maximum number of uses for a key.",
        policy_desc="Allow key usage limit. If Off, keys have unlimited uses.",
        default_value=0,
        destructive="none",
    ),
    PartitionPolicy(
        policy_id=28,
        name="ALLOW_ALTERNATE_AUTHENTICATION",
        capability_desc="Enable alternate authentication. Allows alternate authentication methods beyond PIN/PED.",
        policy_desc="Allow alternate authentication. If Off, only PIN/PED authentication is supported.",
        default_value=0,
        destructive="none",
    ),
    PartitionPolicy(
        policy_id=29,
        name="ALLOW_RESTRICTED_TO_V1",
        capability_desc="Enable restricted restore to V1 partitions. Controls whether objects can be restored to V1 partitions only (FIPS compliance).",
        policy_desc="Allow restricted restore to V1. If On, restore is restricted to V1 partitions for FIPS compliance.",
        default_value=0,
        destructive="none",
    ),
]

# Build a lookup by policy_id
POLICY_BY_ID = {p.policy_id: p for p in POLICY_CATALOG}
# Build a lookup by name (case-insensitive)
POLICY_BY_NAME = {p.name.upper(): p for p in POLICY_CATALOG}


def get_policy(policy_id: int) -> Optional[PartitionPolicy]:
    """Look up a policy by its numeric ID."""
    return POLICY_BY_ID.get(policy_id)


def get_policy_by_name(name: str) -> Optional[PartitionPolicy]:
    """Look up a policy by its name (case-insensitive)."""
    return POLICY_BY_NAME.get(name.upper())


def get_default_policies() -> dict:
    """Return a dict of policy_id -> default_value for all policies."""
    return {p.policy_id: p.default_value for p in POLICY_CATALOG}


def format_policies_table(policies: dict, verbose: bool = False) -> str:
    """Format policies as a table for display.

    Args:
        policies: dict of policy_id -> current_value
        verbose: If True, show full descriptions and destructiveness info
    """
    if verbose:
        lines = [
            f"  {'ID':<5} {'Policy Name':<40} {'Value':<8} {'Default':<8} {'Destructive':<15} {'Description'}",
            "  " + "-" * 120,
        ]
        for p in POLICY_CATALOG:
            current = policies.get(p.policy_id, p.default_value)
            if p.value_type == "integer":
                val = str(current)
                dflt = str(p.default_value)
            else:
                val = "On" if current else "Off"
                dflt = "On" if p.default_value else "Off"
            desc = p.policy_desc[:60]
            lines.append(
                f"  {p.policy_id:<5} {p.name:<40} {val:<8} {dflt:<8} {p.destructive:<15} {desc}"
            )
        return "\n".join(lines)
    else:
        lines = [
            f"  {'ID':<5} {'Policy Name':<40} {'Value':<8} {'Modifiable'}",
            "  " + "-" * 70,
        ]
        for p in POLICY_CATALOG:
            current = policies.get(p.policy_id, p.default_value)
            if p.value_type == "integer":
                val = str(current)
            else:
                val = "On" if current else "Off"
            mod = "Yes" if p.modifiable else "No"
            lines.append(
                f"  {p.policy_id:<5} {p.name:<40} {val:<8} {mod}"
            )
        return "\n".join(lines)


def validate_policy_change(policy: PartitionPolicy, old_value: int,
                           new_value: int) -> tuple:
    """Validate a policy change.

    Returns (is_valid, error_message, is_destructive).
    """
    if not policy.modifiable:
        return (False, f"Policy '{policy.name}' is not modifiable.", False)

    if policy.value_type == "integer":
        if new_value < policy.min_value or new_value > policy.max_value:
            return (False, f"Value must be between {policy.min_value} and {policy.max_value}.", False)
    else:
        if new_value not in (0, 1):
            return (False, "Value must be 0 (Off) or 1 (On).", False)

    # Check mutual exclusivity: policies 0 and 1 cannot both be On
    if policy.policy_id == 0 and new_value == 1:
        return (True, None, policy.destructive != "none")
    if policy.policy_id == 1 and new_value == 1:
        return (True, None, policy.destructive != "none")

    # Determine if this change is destructive
    is_destr = False
    if policy.destructive == "both":
        is_destr = True
    elif policy.destructive == "off-to-on" and old_value == 0 and new_value == 1:
        is_destr = True
    elif policy.destructive == "on-to-off" and old_value == 1 and new_value == 0:
        is_destr = True

    return (True, None, is_destr)


def validate_policy_change_safe(policy: PartitionPolicy, old_value: int,
                                 new_value: int) -> tuple:
    """Like validate_policy_change but never raises — used for pre-checking.

    Returns (is_valid, error_message, is_destructive).
    """
    if not policy.modifiable:
        return (False, f"Policy '{policy.name}' is not modifiable.", False)

    if policy.value_type == "integer":
        if new_value < policy.min_value or new_value > policy.max_value:
            return (False, f"Value must be between {policy.min_value} and {policy.max_value}.", False)
    else:
        if new_value not in (0, 1):
            return (False, "Value must be 0 (Off) or 1 (On).", False)

    is_destr = False
    if policy.destructive == "both":
        is_destr = True
    elif policy.destructive == "off-to-on" and old_value == 0 and new_value == 1:
        is_destr = True
    elif policy.destructive == "on-to-off" and old_value == 1 and new_value == 0:
        is_destr = True

    return (True, None, is_destr)


def check_mutual_exclusion(policies: dict, policy_id: int, new_value: int) -> tuple:
    """Check if setting a policy would violate mutual exclusion rules.

    Returns (is_valid, error_message).
    """
    # Policies 0 (cloning) and 1 (wrapping) cannot both be On
    if policy_id == 0 and new_value == 1:
        if policies.get(1, 0) == 1:
            return (False, "Cannot enable private key cloning while private key wrapping is enabled (policies 0 and 1 are mutually exclusive).")
    if policy_id == 1 and new_value == 1:
        if policies.get(0, 0) == 1:
            return (False, "Cannot enable private key wrapping while private key cloning is enabled (policies 0 and 1 are mutually exclusive).")

    return (True, None)


def check_firmware_support(policy: PartitionPolicy, current_firmware: str) -> bool:
    """Check if the current firmware supports this policy."""
    from hsm.token import _compare_versions
    return _compare_versions(current_firmware, policy.firmware_min) >= 0


# ------------------------------------------------------------------
# Partition Policy Templates (PPT)
# ------------------------------------------------------------------

# Predefined templates matching common Luna 7 configurations
PREDEFINED_TEMPLATES = {
    "DEFAULT": {
        "description": "Default policy settings for a standard application partition.",
        "policies": {},  # All defaults
    },
    "FIPS_STRICT": {
        "description": "FIPS-compliant configuration with maximum security restrictions.",
        "policies": {
            0: 1,   # Allow private key cloning (needed for backup)
            1: 0,   # No private key wrapping
            4: 1,   # Allow secret key cloning
            5: 0,   # No secret key wrapping
            12: 0,  # RSA blinding always on
            14: 0,  # No raw RSA operations
            29: 1,  # Restricted restore to V1
        },
    },
    "HIGH_SECURITY": {
        "description": "High-security configuration with wrapping disabled and strict key controls.",
        "policies": {
            0: 1,   # Allow cloning for backup
            1: 0,   # No wrapping
            3: 0,   # No masking
            5: 0,   # No secret key wrapping
            7: 0,   # No secret key masking
            9: 0,   # No multipurpose keys
            14: 0,  # No raw RSA
            19: 1,  # Force PIN change on first login
        },
    },
    "DEVELOPMENT": {
        "description": "Permissive configuration for development and testing environments.",
        "policies": {
            0: 0,   # Cloning off (mutual exclusion with wrapping)
            1: 1,   # Wrapping on (NOT recommended for production)
            4: 1,   # Secret key cloning on
            5: 1,   # Secret key wrapping on
            9: 1,   # Multipurpose keys on
            14: 1,  # Raw RSA on
        },
    },
    "BACKUP_READY": {
        "description": "Configuration optimized for backup operations with cloning enabled.",
        "policies": {
            0: 1,   # Private key cloning on (required for backup)
            1: 0,   # Wrapping off
            4: 1,   # Secret key cloning on
            5: 0,   # Secret key wrapping off
            15: 1,  # HA recovery on
        },
    },
}


def get_predefined_template(name: str) -> Optional[dict]:
    """Get a predefined PPT by name (case-insensitive)."""
    return PREDEFINED_TEMPLATES.get(name.upper())


def list_predefined_templates() -> list:
    """List all predefined templates with their descriptions."""
    return [
        {"name": name, "description": t["description"],
         "policy_count": len(t["policies"])}
        for name, t in PREDEFINED_TEMPLATES.items()
    ]


def validate_template(policies: dict, current_firmware: str = "7.13.0") -> tuple:
    """Validate a set of policy values for a template.

    Returns (is_valid, errors_list).
    """
    errors = []

    # Check mutual exclusivity
    if policies.get(0, 0) == 1 and policies.get(1, 0) == 1:
        errors.append("Policies 0 (cloning) and 1 (wrapping) cannot both be On.")

    # Check firmware support for each policy
    for pid, val in policies.items():
        policy = get_policy(pid)
        if policy is None:
            errors.append(f"Unknown policy ID: {pid}")
            continue
        if not check_firmware_support(policy, current_firmware):
            errors.append(f"Policy {pid} ({policy.name}) requires firmware {policy.firmware_min} or newer.")

    return (len(errors) == 0, errors)


def apply_template_to_policies(template_policies: dict,
                                current_policies: dict) -> dict:
    """Apply template policy values on top of current policies.

    Only policies specified in the template are overridden; others
    retain their current values.
    """
    result = dict(current_policies)
    for pid, val in template_policies.items():
        result[pid] = val
    return result
