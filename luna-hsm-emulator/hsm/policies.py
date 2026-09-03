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
        policy_id=0, name="ALLOW_PRIVATE_KEY_CLONING",
        capability_desc="Enable Allow private key cloning.",
        policy_desc="Allow private key cloning.",
        default_value=1, destructive="off-to-on",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.1.0",
    ),
    PartitionPolicy(
        policy_id=1, name="ALLOW_PRIVATE_KEY_WRAPPING",
        capability_desc="Enable Allow private key wrapping.",
        policy_desc="Allow private key wrapping.",
        default_value=0, destructive="off-to-on",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.1.0",
    ),
    PartitionPolicy(
        policy_id=2, name="ALLOW_PRIVATE_KEY_UNWRAPPING",
        capability_desc="Enable Allow private key unwrapping.",
        policy_desc="Allow private key unwrapping.",
        default_value=1, destructive="none",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.0.0",
    ),
    PartitionPolicy(
        policy_id=3, name="ALLOW_PRIVATE_KEY_MASKING",
        capability_desc="Enable Allow private key masking.",
        policy_desc="Allow private key masking.",
        default_value=0, destructive="off-to-on",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.7.0",
    ),
    PartitionPolicy(
        policy_id=4, name="ALLOW_SECRET_KEY_CLONING",
        capability_desc="Enable Allow secret key cloning.",
        policy_desc="Allow secret key cloning.",
        default_value=1, destructive="off-to-on",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.0.0",
    ),
    PartitionPolicy(
        policy_id=5, name="ALLOW_SECRET_KEY_WRAPPING",
        capability_desc="Enable Allow secret key wrapping.",
        policy_desc="Allow secret key wrapping.",
        default_value=1, destructive="off-to-on",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.0.0",
    ),
    PartitionPolicy(
        policy_id=6, name="ALLOW_SECRET_KEY_UNWRAPPING",
        capability_desc="Enable Allow secret key unwrapping.",
        policy_desc="Allow secret key unwrapping.",
        default_value=1, destructive="none",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.0.0",
    ),
    PartitionPolicy(
        policy_id=7, name="ALLOW_SECRET_KEY_MASKING",
        capability_desc="Enable Allow secret key masking.",
        policy_desc="Allow secret key masking.",
        default_value=0, destructive="off-to-on",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.7.0",
    ),
    PartitionPolicy(
        policy_id=9, name="ALLOW_DIGEST_KEY",
        capability_desc="Enable Allow DigestKey.",
        policy_desc="Allow DigestKey.",
        default_value=0, destructive="off-to-on",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.8.0",
    ),
    PartitionPolicy(
        policy_id=10, name="ALLOW_MULTIPURPOSE_KEYS",
        capability_desc="Enable Allow multipurpose keys.",
        policy_desc="Allow multipurpose keys.",
        default_value=1, destructive="off-to-on",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.0.0",
    ),
    PartitionPolicy(
        policy_id=11, name="ALLOW_CHANGING_KEY_ATTRIBUTES",
        capability_desc="Enable Allow changing key attributes.",
        policy_desc="Allow changing key attributes.",
        default_value=1, destructive="off-to-on",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.0.0",
    ),
    PartitionPolicy(
        policy_id=15, name="IGNORE_FAILED_CHALLENGE_RESPONSES",
        capability_desc="Enable Ignore failed challenge responses.",
        policy_desc="Ignore failed challenge responses.",
        default_value=1, destructive="off-to-on",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.0.0",
    ),
    PartitionPolicy(
        policy_id=16, name="OPERATE_WITHOUT_RSA_BLINDING",
        capability_desc="Enable Operate without RSA blinding.",
        policy_desc="Operate without RSA blinding.",
        default_value=1, destructive="off-to-on",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.0.0",
    ),
    PartitionPolicy(
        policy_id=17, name="ALLOW_SIGNING_WITH_NON_LOCAL_KEYS",
        capability_desc="Enable Allow signing with non-local keys.",
        policy_desc="Allow signing with non-local keys.",
        default_value=1, destructive="none",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.0.0",
    ),
    PartitionPolicy(
        policy_id=18, name="ALLOW_RAW_RSA_OPERATIONS",
        capability_desc="Enable Allow raw RSA operations.",
        policy_desc="Allow raw RSA operations.",
        default_value=1, destructive="off-to-on",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.0.0",
    ),
    PartitionPolicy(
        policy_id=20, name="MAX_LOGIN_ATTEMPTS",
        capability_desc="Enable Max failed user logins allowed.",
        policy_desc="Max failed user logins allowed.",
        default_value=10, destructive="none",
        modifiable=True, value_type="integer", min_value=1, max_value=10,
        firmware_min="7.0.0",
    ),
    PartitionPolicy(
        policy_id=21, name="ALLOW_HIGH_AVAILABILITY_RECOVERY",
        capability_desc="Enable Allow high availability recovery.",
        policy_desc="Allow high availability recovery.",
        default_value=1, destructive="none",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.0.0",
    ),
    PartitionPolicy(
        policy_id=22, name="ALLOW_ACTIVATION",
        capability_desc="Enable Allow activation.",
        policy_desc="Allow activation.",
        default_value=0, destructive="none",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.0.0",
    ),
    PartitionPolicy(
        policy_id=23, name="ALLOW_AUTO_ACTIVATION",
        capability_desc="Enable Allow auto-activation.",
        policy_desc="Allow auto-activation.",
        default_value=0, destructive="none",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.0.0",
    ),
    PartitionPolicy(
        policy_id=25, name="MIN_PIN_LENGTH",
        capability_desc="Enable Minimum PIN length (stored as 255 minus length).",
        policy_desc="Minimum PIN length (stored as 255 minus length).",
        default_value=247, destructive="none",
        modifiable=True, value_type="integer", min_value=0, max_value=247,
        firmware_min="7.0.0",
    ),
    PartitionPolicy(
        policy_id=26, name="MAX_PIN_LENGTH",
        capability_desc="Enable Maximum PIN length.",
        policy_desc="Maximum PIN length.",
        default_value=255, destructive="none",
        modifiable=True, value_type="integer", min_value=8, max_value=255,
        firmware_min="7.0.0",
    ),
    PartitionPolicy(
        policy_id=28, name="ALLOW_KEY_MANAGEMENT_FUNCTIONS",
        capability_desc="Enable Allow Key Management Functions.",
        policy_desc="Allow Key Management Functions.",
        default_value=1, destructive="off-to-on",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.0.0",
    ),
    PartitionPolicy(
        policy_id=29, name="PERFORM_RSA_SIGNING_WITHOUT_CONFIRMATION",
        capability_desc="Enable Perform RSA signing without confirmation.",
        policy_desc="Perform RSA signing without confirmation.",
        default_value=1, destructive="off-to-on",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.0.0",
    ),
    PartitionPolicy(
        policy_id=31, name="ALLOW_PRIVATE_KEY_UNMASKING",
        capability_desc="Enable Allow private key unmasking.",
        policy_desc="Allow private key unmasking.",
        default_value=0, destructive="none",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.7.0",
    ),
    PartitionPolicy(
        policy_id=32, name="ALLOW_SECRET_KEY_UNMASKING",
        capability_desc="Enable Allow secret key unmasking.",
        policy_desc="Allow secret key unmasking.",
        default_value=0, destructive="none",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.7.0",
    ),
    PartitionPolicy(
        policy_id=33, name="ALLOW_RSA_PKCS_MECHANISM",
        capability_desc="Enable Allow RSA PKCS mechanism.",
        policy_desc="Allow RSA PKCS mechanism.",
        default_value=1, destructive="off-to-on",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.0.0",
    ),
    PartitionPolicy(
        policy_id=34, name="ALLOW_CBC_PAD_SMALL_KEYS",
        capability_desc="Enable Allow CBC-PAD wrap of keys of any size.",
        policy_desc="Allow CBC-PAD wrap of keys of any size.",
        default_value=1, destructive="off-to-on",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.0.0",
    ),
    PartitionPolicy(
        policy_id=37, name="FORCE_SECURE_TRUSTED_CHANNEL",
        capability_desc="Enable Force Secure Trusted Channel.",
        policy_desc="Force Secure Trusted Channel.",
        default_value=0, destructive="on-to-off",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.0.0",
    ),
    PartitionPolicy(
        policy_id=39, name="ALLOW_START_END_DATE_ATTRIBUTES",
        capability_desc="Enable Allow Start/End Date Attributes.",
        policy_desc="Allow Start/End Date Attributes.",
        default_value=0, destructive="on-to-off",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.0.0",
    ),
    PartitionPolicy(
        policy_id=40, name="REQUIRE_PER_KEY_AUTHORIZATION",
        capability_desc="Enable Require Per-Key Authorization Data.",
        policy_desc="Require Per-Key Authorization Data.",
        default_value=0, destructive="both",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.7.0",
    ),
    PartitionPolicy(
        policy_id=41, name="PARTITION_VERSION",
        capability_desc="Enable Partition Version.",
        policy_desc="Partition Version.",
        default_value=0, destructive="on-to-off",
        modifiable=True, value_type="integer", min_value=0, max_value=1,
        firmware_min="7.7.0",
    ),
    PartitionPolicy(
        policy_id=42, name="ALLOW_CPV1",
        capability_desc="Enable Allow CPv1.",
        policy_desc="Allow CPv1.",
        default_value=0, destructive="off-to-on",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.7.1",
    ),
    PartitionPolicy(
        policy_id=43, name="ALLOW_NON_FIPS_ALGORITHMS",
        capability_desc="Enable Allow non-FIPS algorithms.",
        policy_desc="Allow non-FIPS algorithms.",
        default_value=1, destructive="off-to-on",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.7.1",
    ),
    PartitionPolicy(
        policy_id=44, name="ALLOW_EXTENDED_DOMAIN_MANAGEMENT",
        capability_desc="Enable Allow Extended Domain Management.",
        policy_desc="Allow Extended Domain Management.",
        default_value=0, destructive="none",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.8.0",
    ),
    PartitionPolicy(
        policy_id=45, name="ALLOW_ECDSA_RSA_PREHASH_SIGVER",
        capability_desc="Enable Allow ECDSA/RSA Prehash SigVer.",
        policy_desc="Allow ECDSA/RSA Prehash SigVer.",
        default_value=0, destructive="none",
        modifiable=True, value_type="on/off", min_value=0, max_value=1,
        firmware_min="7.9.0",
    ),
]

# Build a lookup by policy_id
POLICY_BY_ID = {p.policy_id: p for p in POLICY_CATALOG}
# Build a lookup by name (case-insensitive)
POLICY_BY_NAME = {p.name.upper(): p for p in POLICY_CATALOG}

# HSM policies are a distinct namespace from partition policies.
HSM_POLICY_CATALOG = [
    PartitionPolicy(6, "ALLOW_MASKING", "Enable masking.", "Allow masking.", 1, "both"),
    PartitionPolicy(7, "ALLOW_CLONING", "Enable cloning.", "Allow cloning.", 1, "both"),
    PartitionPolicy(12, "ALLOW_NON_FIPS_ALGORITHMS", "Enable non-FIPS algorithms.",
                    "Allow non-FIPS algorithms.", 1, "both"),
    PartitionPolicy(15, "SO_CAN_RESET_PARTITION_PIN", "Enable SO reset of partition PIN.",
                    "SO can reset partition PIN.", 0, "both"),
    PartitionPolicy(16, "ALLOW_NETWORK_REPLICATION", "Enable network replication.",
                    "Allow network replication.", 1, "none"),
    PartitionPolicy(21, "FORCE_USER_PIN_CHANGE", "Enable forcing user PIN change.",
                    "Force user PIN change after set/reset.", 1, "none"),
    PartitionPolicy(25, "ALLOW_REMOTE_PED", "Enable Remote PED usage.",
                    "Allow Remote PED usage.", 1, "none"),
    PartitionPolicy(30, "ALLOW_UNMASKING", "Enable unmasking.", "Allow unmasking.", 1, "none"),
    PartitionPolicy(33, "MAX_PARTITIONS", "Maximum number of partitions.",
                    "Current maximum number of partitions.", 100, "none", value_type="integer",
                    min_value=1, max_value=100),
    PartitionPolicy(37, "ALLOW_M_OF_N", "Enable MofN.", "Allow MofN.", 1, "none"),
    PartitionPolicy(39, "ALLOW_SECURE_TRUSTED_CHANNEL", "Enable Secure Trusted Channel.",
                    "Allow Secure Trusted Channel.", 0, "both"),
    PartitionPolicy(40, "DECOMMISSION_ON_TAMPER", "Enable decommission on tamper.",
                    "Decommission on tamper.", 0, "both"),
    PartitionPolicy(43, "ALLOW_LOW_LEVEL_MATH_ACCELERATION", "Enable low level math acceleration.",
                    "Allow low-level math acceleration.", 1, "none"),
    PartitionPolicy(46, "DISABLE_DECOMMISSION", "Allow disabling Decommission.",
                    "Disable Decommission.", 0, "both"),
    PartitionPolicy(48, "CONTROLLED_TAMPER_RECOVERY", "Enable controlled tamper recovery.",
                    "Do Controlled Tamper Recovery.", 0, "both"),
    PartitionPolicy(50, "ALLOW_FUNCTIONALITY_MODULES", "Enable Functionality Modules.",
                    "Allow Functionality Modules.", 0, "both"),
    PartitionPolicy(51, "SMFS_AUTO_ACTIVATION", "Enable SMFS Auto Activation.",
                    "Enable SMFS Auto Activation.", 0, "both"),
    PartitionPolicy(57, "ALLOW_SYNC_WITH_HOST_TIME", "Enable sync with host time.",
                    "Allow sync with host time.", 0, "none"),
]
HSM_POLICY_BY_ID = {p.policy_id: p for p in HSM_POLICY_CATALOG}
HSM_POLICY_BY_NAME = {p.name.upper(): p for p in HSM_POLICY_CATALOG}


def get_hsm_policy(value) -> Optional[PartitionPolicy]:
    try:
        return HSM_POLICY_BY_ID.get(int(value))
    except (TypeError, ValueError):
        return HSM_POLICY_BY_NAME.get(str(value).upper())


def get_default_hsm_policies() -> dict:
    return {policy.policy_id: policy.default_value for policy in HSM_POLICY_CATALOG}


def get_policy(policy_id: int) -> Optional[PartitionPolicy]:
    """Look up a policy by its numeric ID."""
    return POLICY_BY_ID.get(policy_id)


def get_policy_by_name(name: str) -> Optional[PartitionPolicy]:
    """Look up a policy by its name (case-insensitive)."""
    return POLICY_BY_NAME.get(name.upper())


def get_default_policies() -> dict:
    """Return a dict of policy_id -> default_value for all policies."""
    return {p.policy_id: p.default_value for p in POLICY_CATALOG}


def format_policies_table(policies: dict, verbose: bool = False,
                          catalog: list = None) -> str:
    """Format policies as a table for display.

    Args:
        policies: dict of policy_id -> current_value
        verbose: If True, show full descriptions and destructiveness info
    """
    catalog = POLICY_CATALOG if catalog is None else catalog
    if verbose:
        lines = [
            f"  {'ID':<5} {'Policy Name':<40} {'Value':<8} {'Default':<8} {'Destructive':<15} {'Description'}",
            "  " + "-" * 120,
        ]
        for p in catalog:
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
        for p in catalog:
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
            16: 0,  # RSA blinding always on
            18: 0,  # No raw RSA operations
            43: 0,  # Disallow non-FIPS algorithms
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
            10: 0,  # No multipurpose keys
            18: 0,  # No raw RSA
            33: 0,  # No RSA PKCS mechanism
        },
    },
    "DEVELOPMENT": {
        "description": "Permissive configuration for development and testing environments.",
        "policies": {
            0: 0,   # Cloning off (mutual exclusion with wrapping)
            1: 1,   # Wrapping on (NOT recommended for production)
            4: 1,   # Secret key cloning on
            5: 1,   # Secret key wrapping on
            10: 1,  # Multipurpose keys on
            18: 1,  # Raw RSA on
        },
    },
    "BACKUP_READY": {
        "description": "Configuration optimized for backup operations with cloning enabled.",
        "policies": {
            0: 1,   # Private key cloning on (required for backup)
            1: 0,   # Wrapping off
            4: 1,   # Secret key cloning on
            5: 0,   # Secret key wrapping off
            21: 1,  # HA recovery on
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
