"""Client-Partition Connections for the Luna Network HSM 7 emulator.

This module implements the two types of client-partition connections
described in the Thales Luna 7 documentation:

  NTLS (Network Trust Link Service):
    - High-performance, traditional data center environments
    - Client identified by IP address or hostname
    - Certificate-based mutual authentication
    - Self-signed or CA-signed certificates
    - Client registration and partition assignment

  STC (Secure Trusted Channel):
    - Higher-assurance, session protection beyond TLS
    - Symmetric encryption of all data in transit
    - Message authentication codes prevent tampering
    - Mutual authentication via STC identities
    - Client and partition identities
    - Configurable ciphers, HMAC, rekey threshold
    - Admin channel for management operations
    - Supports multi-client connections to a single partition
    - NTLS partitions can be converted to STC

Connection states:
  NTLS: unregistered -> registered -> assigned -> connected
  STC: identity_created -> registered -> connected
"""

import time
import hashlib
import secrets
import json
from typing import Optional
from dataclasses import dataclass, field


# Connection types
CONN_NTLS = "NTLS"
CONN_STC = "STC"

# Connection states
STATE_UNREGISTERED = "unregistered"
STATE_REGISTERED = "registered"
STATE_ASSIGNED = "assigned"
STATE_CONNECTED = "connected"
STATE_DISCONNECTED = "disconnected"
STATE_BROKEN = "broken"

# Certificate types
CERT_SELF_SIGNED = "self-signed"
CERT_CA_SIGNED = "ca-signed"

# STC cipher options
STC_CIPHERS = ["AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305"]
STC_DEFAULT_CIPHER = "AES-256-GCM"

# STC HMAC options
STC_HMACS = ["HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512"]
STC_DEFAULT_HMAC = "HMAC-SHA256"

# STC rekey threshold (in messages)
STC_DEFAULT_REKEY_THRESHOLD = 1000000
STC_DEFAULT_ACTIVATION_TIMEOUT = 300  # seconds


@dataclass
class NTLSConnection:
    """An NTLS connection between a client and a partition."""
    client_name: str
    slot_id: int
    cert_type: str = CERT_SELF_SIGNED
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_serial: str = ""
    cert_fingerprint: str = ""
    cert_expiry: str = ""
    state: str = STATE_ASSIGNED
    created_at: float = field(default_factory=time.time)
    connected_at: float = 0.0
    last_activity: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "conn_type": CONN_NTLS,
            "client_name": self.client_name,
            "slot_id": self.slot_id,
            "cert_type": self.cert_type,
            "cert_subject": self.cert_subject,
            "cert_issuer": self.cert_issuer,
            "cert_serial": self.cert_serial,
            "cert_fingerprint": self.cert_fingerprint,
            "cert_expiry": self.cert_expiry,
            "state": self.state,
            "created_at": self.created_at,
            "connected_at": self.connected_at,
            "last_activity": self.last_activity,
        }

    @classmethod
    def from_dict(cls, d: dict):
        c = cls(d["client_name"], d["slot_id"], d.get("cert_type", CERT_SELF_SIGNED))
        c.cert_subject = d.get("cert_subject", "")
        c.cert_issuer = d.get("cert_issuer", "")
        c.cert_serial = d.get("cert_serial", "")
        c.cert_fingerprint = d.get("cert_fingerprint", "")
        c.cert_expiry = d.get("cert_expiry", "")
        c.state = d.get("state", STATE_ASSIGNED)
        c.created_at = d.get("created_at", time.time())
        c.connected_at = d.get("connected_at", 0.0)
        c.last_activity = d.get("last_activity", time.time())
        return c


@dataclass
class STCIdentity:
    """An STC identity (client or partition)."""
    identity_id: int
    name: str
    identity_type: str  # "client" or "partition"
    public_key: str = ""
    private_key_hash: str = ""
    initialized: bool = False
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "identity_id": self.identity_id,
            "name": self.name,
            "identity_type": self.identity_type,
            "public_key": self.public_key,
            "private_key_hash": self.private_key_hash,
            "initialized": self.initialized,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: dict):
        return cls(
            d["identity_id"], d["name"], d.get("identity_type", "client"),
            d.get("public_key", ""), d.get("private_key_hash", ""),
            d.get("initialized", False), d.get("created_at", time.time()),
        )


@dataclass
class STCConnection:
    """An STC connection between a client identity and a partition identity."""
    connection_id: int
    client_identity_id: int
    partition_identity_id: int
    slot_id: int
    cipher: str = STC_DEFAULT_CIPHER
    hmac: str = STC_DEFAULT_HMAC
    rekey_threshold: int = STC_DEFAULT_REKEY_THRESHOLD
    activation_timeout: int = STC_DEFAULT_ACTIVATION_TIMEOUT
    state: str = STATE_REGISTERED
    created_at: float = field(default_factory=time.time)
    connected_at: float = 0.0
    message_count: int = 0

    def to_dict(self) -> dict:
        return {
            "conn_type": CONN_STC,
            "connection_id": self.connection_id,
            "client_identity_id": self.client_identity_id,
            "partition_identity_id": self.partition_identity_id,
            "slot_id": self.slot_id,
            "cipher": self.cipher,
            "hmac": self.hmac,
            "rekey_threshold": self.rekey_threshold,
            "activation_timeout": self.activation_timeout,
            "state": self.state,
            "created_at": self.created_at,
            "connected_at": self.connected_at,
            "message_count": self.message_count,
        }

    @classmethod
    def from_dict(cls, d: dict):
        c = cls(
            d["connection_id"], d["client_identity_id"],
            d["partition_identity_id"], d["slot_id"],
        )
        c.cipher = d.get("cipher", STC_DEFAULT_CIPHER)
        c.hmac = d.get("hmac", STC_DEFAULT_HMAC)
        c.rekey_threshold = d.get("rekey_threshold", STC_DEFAULT_REKEY_THRESHOLD)
        c.activation_timeout = d.get("activation_timeout", STC_DEFAULT_ACTIVATION_TIMEOUT)
        c.state = d.get("state", STATE_REGISTERED)
        c.created_at = d.get("created_at", time.time())
        c.connected_at = d.get("connected_at", 0.0)
        c.message_count = d.get("message_count", 0)
        return c


class ConnectionManager:
    """Manages NTLS and STC client-partition connections.

    This emulates the connection lifecycle for both NTLS and STC
    channels on the Luna Network HSM 7 appliance.
    """

    def __init__(self, storage):
        self.storage = storage
        self._ensure_state()

    def _ensure_state(self):
        if not self.storage.get_meta("connections_ntls"):
            self.storage.set_meta("connections_ntls", "[]")
        if not self.storage.get_meta("connections_stc"):
            self.storage.set_meta("connections_stc", "[]")
        if not self.storage.get_meta("stc_identities"):
            self.storage.set_meta("stc_identities", "[]")
        if not self.storage.get_meta("stc_next_conn_id"):
            self.storage.set_meta("stc_next_conn_id", "1")
        if not self.storage.get_meta("stc_next_identity_id"):
            self.storage.set_meta("stc_next_identity_id", "1")
        if not self.storage.get_meta("ntls_server_cert"):
            self._generate_ntls_server_cert()
        if not self.storage.get_meta("stc_config"):
            self.storage.set_meta("stc_config", json.dumps({
                "enabled": False,
                "cipher": STC_DEFAULT_CIPHER,
                "hmac": STC_DEFAULT_HMAC,
                "rekey_threshold": STC_DEFAULT_REKEY_THRESHOLD,
                "activation_timeout": STC_DEFAULT_ACTIVATION_TIMEOUT,
            }))

    # ------------------------------------------------------------------
    # NTLS Server Certificate
    # ------------------------------------------------------------------

    def _generate_ntls_server_cert(self):
        """Generate the NTLS server self-signed certificate."""
        serial = secrets.token_hex(8).upper()
        fingerprint = hashlib.sha256(secrets.token_bytes(32)).hexdigest()[:40].upper()
        cert = {
            "subject": f"CN=luna7-appliance,O=Thales,C=US",
            "issuer": f"CN=luna7-appliance,O=Thales,C=US",  # self-signed
            "serial": serial,
            "fingerprint": fingerprint,
            "type": CERT_SELF_SIGNED,
            "expiry": "2027-01-01",
            "key_type": "RSA-2048",
        }
        self.storage.set_meta("ntls_server_cert", json.dumps(cert))

    def get_ntls_server_cert(self) -> dict:
        """Return the NTLS server certificate info."""
        raw = self.storage.get_meta("ntls_server_cert")
        if raw:
            try:
                return json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                pass
        return {}

    def regenerate_ntls_cert(self) -> dict:
        """Regenerate the NTLS server certificate."""
        self._generate_ntls_server_cert()
        return self.get_ntls_server_cert()

    # ------------------------------------------------------------------
    # NTLS Connections
    # ------------------------------------------------------------------

    def _get_ntls_connections(self) -> list:
        raw = self.storage.get_meta("connections_ntls") or "[]"
        try:
            return [NTLSConnection.from_dict(d) for d in json.loads(raw)]
        except (json.JSONDecodeError, TypeError):
            return []

    def _save_ntls_connections(self, conns: list):
        self.storage.set_meta("connections_ntls",
                              json.dumps([c.to_dict() for c in conns]))

    def create_ntls_connection(self, client_name: str, slot_id: int,
                                cert_type: str = CERT_SELF_SIGNED,
                                cert_subject: str = "",
                                cert_issuer: str = "",
                                cert_serial: str = "",
                                cert_fingerprint: str = "",
                                cert_expiry: str = "") -> dict:
        """Create an NTLS connection between a client and a partition.

        On a real Luna 7, this involves:
        1. Client generates a certificate (self-signed or CA-signed)
        2. Client cert is registered on the appliance (client register)
        3. Partition is assigned to the client (client assignPartition)

        We simulate this by creating the connection record with
        the certificate information.
        """
        # Check for duplicate
        conns = self._get_ntls_connections()
        for c in conns:
            if c.client_name == client_name and c.slot_id == slot_id:
                return {"success": False,
                        "error": f"NTLS connection already exists for client '{client_name}' to slot {slot_id}"}

        if cert_type not in (CERT_SELF_SIGNED, CERT_CA_SIGNED):
            return {"success": False, "error": f"Invalid cert type. Use '{CERT_SELF_SIGNED}' or '{CERT_CA_SIGNED}'"}

        # Generate client cert info if not provided
        if not cert_subject:
            cert_subject = f"CN={client_name},O=Client,C=US"
        if not cert_issuer:
            cert_issuer = f"CN={client_name},O=Client,C=US" if cert_type == CERT_SELF_SIGNED else "CN=MyCA,O=MyOrg,C=US"
        if not cert_serial:
            cert_serial = secrets.token_hex(8).upper()
        if not cert_fingerprint:
            cert_fingerprint = hashlib.sha256(secrets.token_bytes(32)).hexdigest()[:40].upper()
        if not cert_expiry:
            cert_expiry = "2027-01-01"

        conn = NTLSConnection(
            client_name=client_name, slot_id=slot_id,
            cert_type=cert_type, cert_subject=cert_subject,
            cert_issuer=cert_issuer, cert_serial=cert_serial,
            cert_fingerprint=cert_fingerprint, cert_expiry=cert_expiry,
        )
        conns.append(conn)
        self._save_ntls_connections(conns)

        return {
            "success": True,
            "client_name": client_name,
            "slot_id": slot_id,
            "cert_type": cert_type,
            "cert_fingerprint": cert_fingerprint,
            "state": conn.state,
        }

    def delete_ntls_connection(self, client_name: str, slot_id: int) -> dict:
        """Delete an NTLS connection."""
        conns = self._get_ntls_connections()
        new_conns = [c for c in conns if not (c.client_name == client_name and c.slot_id == slot_id)]
        if len(new_conns) == len(conns):
            return {"success": False, "error": "NTLS connection not found"}
        self._save_ntls_connections(new_conns)
        return {"success": True}

    def list_ntls_connections(self) -> list:
        """List all NTLS connections."""
        conns = self._get_ntls_connections()
        return [c.to_dict() for c in conns]

    def get_ntls_connection(self, client_name: str, slot_id: int) -> Optional[dict]:
        """Get a specific NTLS connection."""
        conns = self._get_ntls_connections()
        conn = next((c for c in conns if c.client_name == client_name and c.slot_id == slot_id), None)
        return conn.to_dict() if conn else None

    def connect_ntls(self, client_name: str, slot_id: int) -> dict:
        """Simulate establishing an NTLS connection.

        On a real Luna 7, the client connects to the appliance via NTLS
        using its registered certificate. The appliance verifies the
        client cert and establishes the trust link.
        """
        conns = self._get_ntls_connections()
        conn = next((c for c in conns if c.client_name == client_name and c.slot_id == slot_id), None)
        if conn is None:
            return {"success": False, "error": "NTLS connection not found. Register the client and assign the partition first."}
        if conn.state == STATE_CONNECTED:
            return {"success": False, "error": "NTLS connection already established"}
        conn.state = STATE_CONNECTED
        conn.connected_at = time.time()
        conn.last_activity = time.time()
        self._save_ntls_connections(conns)
        return {"success": True, "client_name": client_name, "slot_id": slot_id,
                "state": STATE_CONNECTED}

    def disconnect_ntls(self, client_name: str, slot_id: int) -> dict:
        """Simulate disconnecting an NTLS connection."""
        conns = self._get_ntls_connections()
        conn = next((c for c in conns if c.client_name == client_name and c.slot_id == slot_id), None)
        if conn is None:
            return {"success": False, "error": "NTLS connection not found"}
        conn.state = STATE_DISCONNECTED
        conn.last_activity = time.time()
        self._save_ntls_connections(conns)
        return {"success": True}

    def restore_ntls_connection(self, client_name: str, slot_id: int) -> dict:
        """Restore a broken NTLS connection.

        On a real Luna 7, broken connections can be restored by
        re-registering the client certificate and reassigning the partition.
        """
        conns = self._get_ntls_connections()
        conn = next((c for c in conns if c.client_name == client_name and c.slot_id == slot_id), None)
        if conn is None:
            return {"success": False, "error": "NTLS connection not found"}
        conn.state = STATE_ASSIGNED
        conn.connected_at = 0.0
        self._save_ntls_connections(conns)
        return {"success": True, "message": "Connection restored to assigned state. Use connect to re-establish."}

    # ------------------------------------------------------------------
    # STC Identities
    # ------------------------------------------------------------------

    def _get_stc_identities(self) -> list:
        raw = self.storage.get_meta("stc_identities") or "[]"
        try:
            return [STCIdentity.from_dict(d) for d in json.loads(raw)]
        except (json.JSONDecodeError, TypeError):
            return []

    def _save_stc_identities(self, identities: list):
        self.storage.set_meta("stc_identities",
                              json.dumps([i.to_dict() for i in identities]))

    def create_stc_identity(self, name: str, identity_type: str) -> dict:
        """Create an STC identity for a client or partition.

        On a real Luna 7:
        - Client identity: 'hsm stc identity create -client <name>'
        - Partition identity: 'hsm stc identity create -partition <slot>'

        Identities have a public/private key pair. The public key is
        exported and registered on the other end.
        """
        if identity_type not in ("client", "partition"):
            return {"success": False, "error": "identity_type must be 'client' or 'partition'"}

        identities = self._get_stc_identities()
        if any(i.name == name and i.identity_type == identity_type for i in identities):
            return {"success": False, "error": f"STC {identity_type} identity '{name}' already exists"}

        next_id = int(self.storage.get_meta("stc_next_identity_id") or "1")
        identity = STCIdentity(next_id, name, identity_type)
        identity.public_key = secrets.token_hex(32)
        identity.private_key_hash = hashlib.sha256(secrets.token_bytes(32)).hexdigest()[:32]
        identity.initialized = True
        identities.append(identity)
        self._save_stc_identities(identities)
        self.storage.set_meta("stc_next_identity_id", str(next_id + 1))

        return {
            "success": True,
            "identity_id": next_id,
            "name": name,
            "identity_type": identity_type,
            "public_key": identity.public_key,
        }

    def delete_stc_identity(self, name: str, identity_type: str) -> dict:
        """Delete an STC identity."""
        identities = self._get_stc_identities()
        identity = next((i for i in identities if i.name == name and i.identity_type == identity_type), None)
        if identity is None:
            return {"success": False, "error": f"STC {identity_type} identity '{name}' not found"}
        # Check no active connections
        stc_conns = self._get_stc_connections()
        for c in stc_conns:
            if (c.client_identity_id == identity.identity_id or c.partition_identity_id == identity.identity_id) and c.state == STATE_CONNECTED:
                return {"success": False, "error": "Cannot delete identity with active connections. Disconnect first."}
        identities = [i for i in identities if not (i.name == name and i.identity_type == identity_type)]
        self._save_stc_identities(identities)
        return {"success": True}

    def list_stc_identities(self) -> list:
        """List all STC identities."""
        identities = self._get_stc_identities()
        return [i.to_dict() for i in identities]

    def get_stc_identity(self, identity_id: int) -> Optional[STCIdentity]:
        """Get an STC identity by ID."""
        identities = self._get_stc_identities()
        return next((i for i in identities if i.identity_id == identity_id), None)

    def get_stc_identity_by_name(self, name: str, identity_type: str) -> Optional[STCIdentity]:
        """Get an STC identity by name and type."""
        identities = self._get_stc_identities()
        return next((i for i in identities if i.name == name and i.identity_type == identity_type), None)

    def export_stc_identity(self, name: str, identity_type: str) -> dict:
        """Export an STC identity's public key.

        On a real Luna 7: 'hsm stc identity show' or 'partition stcIdentity export'
        The exported .pid (partition identity) or .clientID file is
        transferred to the other end for registration.
        """
        identity = self.get_stc_identity_by_name(name, identity_type)
        if identity is None:
            return {"success": False, "error": f"STC {identity_type} identity '{name}' not found"}
        return {
            "success": True,
            "name": name,
            "identity_type": identity_type,
            "public_key": identity.public_key,
            "file": f"{name}.{'pid' if identity_type == 'partition' else 'clientID'}",
        }

    # ------------------------------------------------------------------
    # STC Connections
    # ------------------------------------------------------------------

    def _get_stc_connections(self) -> list:
        raw = self.storage.get_meta("connections_stc") or "[]"
        try:
            return [STCConnection.from_dict(d) for d in json.loads(raw)]
        except (json.JSONDecodeError, TypeError):
            return []

    def _save_stc_connections(self, conns: list):
        self.storage.set_meta("connections_stc",
                              json.dumps([c.to_dict() for c in conns]))

    def create_stc_connection(self, client_identity_name: str,
                                partition_identity_name: str, slot_id: int,
                                cipher: str = None, hmac: str = None,
                                rekey_threshold: int = None) -> dict:
        """Create an STC connection between a client and partition identity.

        On a real Luna 7, this involves:
        1. Create client identity (hsm stc identity create -client)
        2. Create partition identity (hsm stc identity create -partition)
        3. Export partition identity (.pid file)
        4. Register partition identity on client
        5. Register client identity on appliance
        6. Create the STC connection

        We simulate this by linking the two identities.
        """
        client_id = self.get_stc_identity_by_name(client_identity_name, "client")
        if client_id is None:
            return {"success": False, "error": f"Client identity '{client_identity_name}' not found. Create it first with 'hsm stc identity create -client {client_identity_name}'"}
        partition_id = self.get_stc_identity_by_name(partition_identity_name, "partition")
        if partition_id is None:
            return {"success": False, "error": f"Partition identity '{partition_identity_name}' not found. Create it first with 'hsm stc identity create -partition {partition_identity_name}'"}

        # Check for duplicate
        conns = self._get_stc_connections()
        for c in conns:
            if c.client_identity_id == client_id.identity_id and c.partition_identity_id == partition_id.identity_id:
                return {"success": False, "error": "STC connection already exists for this client/partition pair"}

        next_id = int(self.storage.get_meta("stc_next_conn_id") or "1")
        conn = STCConnection(
            connection_id=next_id,
            client_identity_id=client_id.identity_id,
            partition_identity_id=partition_id.identity_id,
            slot_id=slot_id,
        )
        if cipher:
            if cipher not in STC_CIPHERS:
                return {"success": False, "error": f"Invalid cipher. Available: {', '.join(STC_CIPHERS)}"}
            conn.cipher = cipher
        if hmac:
            if hmac not in STC_HMACS:
                return {"success": False, "error": f"Invalid HMAC. Available: {', '.join(STC_HMACS)}"}
            conn.hmac = hmac
        if rekey_threshold:
            conn.rekey_threshold = rekey_threshold

        conns.append(conn)
        self._save_stc_connections(conns)
        self.storage.set_meta("stc_next_conn_id", str(next_id + 1))

        return {
            "success": True,
            "connection_id": next_id,
            "client_identity": client_identity_name,
            "partition_identity": partition_identity_name,
            "slot_id": slot_id,
            "cipher": conn.cipher,
            "hmac": conn.hmac,
            "state": conn.state,
        }

    def delete_stc_connection(self, connection_id: int) -> dict:
        """Delete an STC connection."""
        conns = self._get_stc_connections()
        new_conns = [c for c in conns if c.connection_id != connection_id]
        if len(new_conns) == len(conns):
            return {"success": False, "error": f"STC connection {connection_id} not found"}
        self._save_stc_connections(new_conns)
        return {"success": True}

    def list_stc_connections(self) -> list:
        """List all STC connections."""
        conns = self._get_stc_connections()
        identities = {i.identity_id: i for i in self._get_stc_identities()}
        result = []
        for c in conns:
            d = c.to_dict()
            client = identities.get(c.client_identity_id)
            partition = identities.get(c.partition_identity_id)
            d["client_name"] = client.name if client else "unknown"
            d["partition_name"] = partition.name if partition else "unknown"
            result.append(d)
        return result

    def connect_stc(self, connection_id: int) -> dict:
        """Simulate establishing an STC connection.

        On a real Luna 7, this involves:
        1. Mutual authentication using STC identities
        2. Session key negotiation
        3. Secure tunnel creation with symmetric encryption
        """
        conns = self._get_stc_connections()
        conn = next((c for c in conns if c.connection_id == connection_id), None)
        if conn is None:
            return {"success": False, "error": f"STC connection {connection_id} not found"}
        if conn.state == STATE_CONNECTED:
            return {"success": False, "error": "STC connection already established"}
        conn.state = STATE_CONNECTED
        conn.connected_at = time.time()
        self._save_stc_connections(conns)
        return {"success": True, "connection_id": connection_id,
                "state": STATE_CONNECTED, "cipher": conn.cipher}

    def disconnect_stc(self, connection_id: int) -> dict:
        """Disconnect an STC connection."""
        conns = self._get_stc_connections()
        conn = next((c for c in conns if c.connection_id == connection_id), None)
        if conn is None:
            return {"success": False, "error": f"STC connection {connection_id} not found"}
        conn.state = STATE_DISCONNECTED
        self._save_stc_connections(conns)
        return {"success": True}

    def restore_stc_connection(self, connection_id: int) -> dict:
        """Restore a broken STC connection."""
        conns = self._get_stc_connections()
        conn = next((c for c in conns if c.connection_id == connection_id), None)
        if conn is None:
            return {"success": False, "error": f"STC connection {connection_id} not found"}
        conn.state = STATE_REGISTERED
        conn.connected_at = 0.0
        self._save_stc_connections(conns)
        return {"success": True, "message": "STC connection restored to registered state."}

    # ------------------------------------------------------------------
    # STC Configuration
    # ------------------------------------------------------------------

    def get_stc_config(self) -> dict:
        """Get STC global configuration."""
        raw = self.storage.get_meta("stc_config") or "{}"
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {}

    def enable_stc(self) -> dict:
        """Enable STC on the appliance."""
        config = self.get_stc_config()
        config["enabled"] = True
        self.storage.set_meta("stc_config", json.dumps(config))
        return {"success": True, "enabled": True}

    def disable_stc(self) -> dict:
        """Disable STC on the appliance."""
        config = self.get_stc_config()
        config["enabled"] = False
        self.storage.set_meta("stc_config", json.dumps(config))
        return {"success": True, "enabled": False}

    def set_stc_cipher(self, cipher: str) -> dict:
        """Set the default STC cipher."""
        if cipher not in STC_CIPHERS:
            return {"success": False, "error": f"Invalid cipher. Available: {', '.join(STC_CIPHERS)}"}
        config = self.get_stc_config()
        config["cipher"] = cipher
        self.storage.set_meta("stc_config", json.dumps(config))
        return {"success": True, "cipher": cipher}

    def enable_stc_hmac(self) -> dict:
        """Enable STC HMAC for message authentication."""
        config = self.get_stc_config()
        config["hmac_enabled"] = True
        self.storage.set_meta("stc_config", json.dumps(config))
        return {"success": True}

    def disable_stc_hmac(self) -> dict:
        """Disable STC HMAC."""
        config = self.get_stc_config()
        config["hmac_enabled"] = False
        self.storage.set_meta("stc_config", json.dumps(config))
        return {"success": True}

    def set_stc_rekey_threshold(self, threshold: int) -> dict:
        """Set the STC rekey threshold (messages before rekeying)."""
        if threshold < 1000:
            return {"success": False, "error": "Threshold must be at least 1000"}
        config = self.get_stc_config()
        config["rekey_threshold"] = threshold
        self.storage.set_meta("stc_config", json.dumps(config))
        return {"success": True, "rekey_threshold": threshold}

    def set_stc_activation_timeout(self, timeout: int) -> dict:
        """Set the STC activation timeout in seconds."""
        if timeout < 10 or timeout > 3600:
            return {"success": False, "error": "Timeout must be between 10 and 3600 seconds"}
        config = self.get_stc_config()
        config["activation_timeout"] = timeout
        self.storage.set_meta("stc_config", json.dumps(config))
        return {"success": True, "activation_timeout": timeout}

    # ------------------------------------------------------------------
    # NTLS to STC Conversion
    # ------------------------------------------------------------------

    def convert_ntls_to_stc(self, client_name: str, slot_id: int,
                            client_identity_name: str = None,
                            partition_identity_name: str = None) -> dict:
        """Convert an NTLS partition connection to STC.

        On a real Luna 7:
        1. Create STC identities for the client and partition
        2. Export and register identities
        3. Create the STC connection
        4. Remove the NTLS connection

        This is a one-way operation — STC partitions cannot be
        converted back to NTLS without zeroizing.
        """
        # Find the NTLS connection
        ntls_conn = self.get_ntls_connection(client_name, slot_id)
        if ntls_conn is None:
            return {"success": False, "error": "NTLS connection not found"}
        if ntls_conn["state"] == STATE_CONNECTED:
            return {"success": False, "error": "Cannot convert a connected NTLS connection. Disconnect first."}

        # Create identities if not provided
        if not client_identity_name:
            client_identity_name = f"{client_name}_stc"
        if not partition_identity_name:
            partition_identity_name = f"slot{slot_id}_stc"

        # Create client identity if it doesn't exist
        client_id = self.get_stc_identity_by_name(client_identity_name, "client")
        if client_id is None:
            result = self.create_stc_identity(client_identity_name, "client")
            if not result["success"]:
                return result

        # Create partition identity if it doesn't exist
        partition_id = self.get_stc_identity_by_name(partition_identity_name, "partition")
        if partition_id is None:
            result = self.create_stc_identity(partition_identity_name, "partition")
            if not result["success"]:
                return result

        # Create STC connection
        result = self.create_stc_connection(client_identity_name, partition_identity_name, slot_id)
        if not result["success"]:
            return result

        # Delete the NTLS connection
        self.delete_ntls_connection(client_name, slot_id)

        return {
            "success": True,
            "message": f"Converted NTLS connection for '{client_name}' on slot {slot_id} to STC.",
            "stc_connection_id": result["connection_id"],
            "client_identity": client_identity_name,
            "partition_identity": partition_identity_name,
        }

    # ------------------------------------------------------------------
    # STC Admin Channel
    # ------------------------------------------------------------------

    def get_stc_admin_status(self) -> dict:
        """Get STC admin channel status.

        The STC admin channel is used for management operations
        between the appliance and the HSM, separate from client
        data channels.
        """
        config = self.get_stc_config()
        return {
            "enabled": config.get("enabled", False),
            "cipher": config.get("cipher", STC_DEFAULT_CIPHER),
            "hmac_enabled": config.get("hmac_enabled", True),
            "hmac": config.get("hmac", STC_DEFAULT_HMAC),
            "rekey_threshold": config.get("rekey_threshold", STC_DEFAULT_REKEY_THRESHOLD),
            "activation_timeout": config.get("activation_timeout", STC_DEFAULT_ACTIVATION_TIMEOUT),
            "identities": len(self._get_stc_identities()),
            "connections": len(self._get_stc_connections()),
        }

    # ------------------------------------------------------------------
    # Summary / Status
    # ------------------------------------------------------------------

    def get_connection_summary(self) -> dict:
        """Get a summary of all connections."""
        ntls = self._get_ntls_connections()
        stc = self._get_stc_connections()
        return {
            "ntls_total": len(ntls),
            "ntls_connected": sum(1 for c in ntls if c.state == STATE_CONNECTED),
            "ntls_assigned": sum(1 for c in ntls if c.state == STATE_ASSIGNED),
            "stc_total": len(stc),
            "stc_connected": sum(1 for c in stc if c.state == STATE_CONNECTED),
            "stc_registered": sum(1 for c in stc if c.state == STATE_REGISTERED),
            "stc_identities": len(self._get_stc_identities()),
            "stc_enabled": self.get_stc_config().get("enabled", False),
        }
