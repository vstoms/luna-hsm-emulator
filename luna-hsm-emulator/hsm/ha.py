"""Client-side virtual slots over the emulator's physical PKCS#11 sessions.

Logical handles refer to cloning identities, never labels or member handles.
Multipart operations use the emulator's buffered state: on failover only that
operation's state is moved, and key bytes are reloaded from the surviving HSM.
This is not an implementation of the proprietary Luna network protocol.
"""

import copy
import inspect
from functools import wraps

from hsm.deployment import DeploymentManager
from pkcs11.constants import (
    PKCS11Error, CKR_OK, CKR_DEVICE_ERROR, CKR_TOKEN_NOT_PRESENT,
    CKR_OBJECT_HANDLE_INVALID, CKR_OPERATION_ACTIVE,
    CKR_OPERATION_NOT_INITIALIZED, CKR_ACTION_PROHIBITED,
    CKR_USER_ALREADY_LOGGED_IN, CKR_USER_NOT_LOGGED_IN,
    CKA_TOKEN, CKA_PRIVATE,
)


HANDLE_ARGS = {"handle", "wrapping_handle", "key_handle", "unwrapping_handle", "base_handle"}
NEW_OBJECTS = {"C_CreateObject", "C_CopyObject", "C_GenerateKey", "C_GenerateKeyPair",
               "C_UnwrapKey", "C_DeriveKey"}
MUTATIONS = NEW_OBJECTS | {"C_SetAttributeValue", "C_DestroyObject"}


def ha_sessions(cls):
    """Keep virtual dispatch at the API boundary, including keyword calls."""
    for name, method in list(vars(cls).items()):
        if not name.startswith("C_") or not callable(method):
            continue
        signature = inspect.signature(method)
        if "session_id" not in signature.parameters:
            continue

        def wrap(fn, sig):
            @wraps(fn)
            def call(api, *args, **kwargs):
                api._check_device(allow_offline=fn.__name__ == "C_CloseSession")
                bound = sig.bind(api, *args, **kwargs)
                bound.apply_defaults()
                sid = bound.arguments["session_id"]
                if api.ha and sid in api.ha.sessions:
                    params = dict(bound.arguments)
                    params.pop("self")
                    return api.ha.call(fn, params)
                return fn(api, *args, **kwargs)
            return call
        setattr(cls, name, wrap(method, signature))
    return cls


class HAClient:
    def __init__(self, api):
        self.api = api
        self.storage = api.storage
        self.deployment = DeploymentManager(self.storage)
        self.sessions = {}
        self.handles = {}
        self.next_handle = 1 << 40

    def open(self, group, flags):
        if not self._healthy(group):
            raise PKCS11Error(CKR_DEVICE_ERROR, "No available HA member")
        sid = self.api.sessions.open_session(group["virtual_slot"], flags)
        self.sessions[sid] = {"group": group["name"], "children": {}, "operations": {},
                              "credential": None, "user_type": None, "owned": set()}
        return sid

    def _healthy(self, group):
        return {m["slot_id"] for m in group["members"]
                if m["state"] in ("active", "standby") and not m["network_partition"]
                and self.storage.get_partition(m["slot_id"]) is not None
                and self.deployment.check_ha_compatibility(group["name"], m["slot_id"])["compatible"]}

    def _child(self, sid, slot):
        state = self.sessions[sid]
        if slot not in state["children"]:
            parent = self.api.sessions.get_session(sid)
            state["children"][slot] = self.api.sessions.open_session(slot, parent.flags)
        child = state["children"][slot]
        if state["credential"] is not None and not self.api.auth.is_logged_in(child):
            pin = self.storage.decrypt_blob(state["credential"]).decode()
            self.api.C_Login(child, state["user_type"], pin)
        return child

    def _logical(self, sid, physical):
        state = self.sessions[sid]
        identity = self.storage.object_identity(physical)
        obj, _ = self.storage.get_object(physical)
        owner = None if obj.is_token_object() else sid
        for handle, entry in self.handles.items():
            if entry == (state["group"], identity, owner):
                return handle
        handle = self.next_handle
        self.next_handle += 1
        self.handles[handle] = (state["group"], identity, owner)
        if owner is not None:
            state["owned"].add(identity)
        return handle

    def _identity(self, sid, handle):
        entry = self.handles.get(handle)
        if not entry or entry[0] != self.sessions[sid]["group"] or entry[2] not in (None, sid):
            raise PKCS11Error(CKR_OBJECT_HANDLE_INVALID, "Invalid HA logical object handle")
        return entry[1]

    def _resolve(self, sid, slot, handle):
        identity = self._identity(sid, handle)
        physical = self.storage.object_handle(slot, identity)
        if physical is None:
            raise PKCS11Error(CKR_OBJECT_HANDLE_INVALID, "Object unavailable on HA member")
        return physical

    def close(self, sid):
        state = self.sessions.pop(sid)
        # Session objects are neither cloned nor allowed to survive session close.
        for slot, child in state["children"].items():
            for identity in state["owned"]:
                physical = self.storage.object_handle(slot, identity)
                if physical is not None:
                    self.storage.delete_object(physical)
            self.api.C_CloseSession(child)
        self.api.auth.clear_session(sid)
        self.api.sessions.close_session(sid)
        self.handles = {h: e for h, e in self.handles.items() if e[2] != sid}
        return CKR_OK

    def _find(self, name, params, group, healthy):
        sid = params["session_id"]
        parent = self.api.sessions.get_session(sid)
        if name == "C_FindObjectsInit":
            if parent._find_active:
                raise PKCS11Error(CKR_OPERATION_ACTIVE)
            found = set()
            for slot in sorted(healthy):
                child = self._child(sid, slot)
                for obj, _ in self.storage.get_all_objects(slot):
                    identity = self.storage.object_identity(obj.handle)
                    if identity in group["deleted_objects"]:
                        continue
                    if not obj.is_token_object() and identity not in self.sessions[sid]["owned"]:
                        continue
                    if obj.get(CKA_PRIVATE, False) and not self.api.auth.is_logged_in(child):
                        continue
                    def matches(key, value):
                        actual = obj.get(key)
                        if isinstance(value, str) and isinstance(actual, bytes):
                            actual = actual.decode("utf-8", errors="replace")
                        return actual == value
                    if all(matches(k, v) for k, v in params["template"].items()):
                        found.add(self._logical(sid, obj.handle))
            parent._find_results = sorted(found)
            parent._find_active = True
            return CKR_OK
        if not parent._find_active:
            raise PKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
        if name == "C_FindObjectsFinal":
            parent._find_results = []
            parent._find_active = False
            return CKR_OK
        count = params["max_count"]
        result, parent._find_results = parent._find_results[:count], parent._find_results[count:]
        return result

    def call(self, fn, params, excluded=None):
        name, sid = fn.__name__, params["session_id"]
        state = self.sessions[sid]
        if name == "C_CloseSession":
            return self.close(sid)
        if name == "C_GetSessionInfo":
            return self.api.sessions.get_session_info(sid)
        group = self.deployment.get_ha_group(state["group"])
        if not group:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, "HA group deleted")
        if name == "C_Logout":
            if state["credential"] is None:
                raise PKCS11Error(CKR_USER_NOT_LOGGED_IN)
            for child in state["children"].values():
                if self.api.auth.is_logged_in(child):
                    self.api.C_Logout(child)
            state["credential"] = None
            state["user_type"] = None
            state["operations"].clear()
            self.api.auth.clear_session(sid)
            self.api.sessions.get_session(sid).user_type = None
            return CKR_OK
        if not excluded:
            self.deployment.poll_ha_recovery(group["name"])
        group = self.deployment.get_ha_group(group["name"])
        healthy = self._healthy(group) - (excluded or set())
        if not healthy:
            raise PKCS11Error(CKR_DEVICE_ERROR, "No available HA member")
        if name == "C_Login":
            if state["credential"] is not None:
                raise PKCS11Error(CKR_USER_ALREADY_LOGGED_IN)
            logged = []
            try:
                for slot in sorted(healthy):
                    child = self._child(sid, slot)
                    self.api.C_Login(child, params["user_type"], params["pin"],
                                     params.get("ped_keys"), params.get("ped_secret"))
                    logged.append(child)
            except Exception:
                for child in logged:
                    self.api.C_Logout(child)
                raise
            state["credential"] = self.storage.encrypt_blob(params["pin"].encode())
            state["user_type"] = params["user_type"]
            self.api.sessions.get_session(sid).user_type = params["user_type"]
            self.api.auth._sessions[sid] = (group["virtual_slot"], self.api.auth.get_role(logged[0]))
            return CKR_OK
        if name in ("C_InitPIN", "C_SetPIN"):
            raise PKCS11Error(CKR_ACTION_PROHIBITED, "Manage credentials on physical partitions")
        if name.startswith("C_FindObjects"):
            return self._find(name, params, group, healthy)

        operation = next((op for op in ("Encrypt", "Decrypt", "Sign", "Verify", "Digest")
                          if name.startswith("C_" + op)), None)
        context = state["operations"].get(operation) if operation else None
        if operation and name.endswith("Init") and context:
            raise PKCS11Error(CKR_OPERATION_ACTIVE)
        if operation and not name.endswith("Init") and not context:
            raise PKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
        handles = {k: v for k, v in params.items() if k in HANDLE_ARGS}
        if context:
            handles = context["handles"]
        for handle in handles.values():
            identity = self._identity(sid, handle)
            healthy = {slot for slot in healthy if self.storage.object_handle(slot, identity) is not None}
        if not healthy:
            raise PKCS11Error(CKR_DEVICE_ERROR, "No available member holds the operation's key")
        if context and context["slot"] in healthy:
            slot = context["slot"]
        else:
            route = self.deployment.route_ha_operation(group["name"], name, allowed_slots=healthy)
            if not route["success"]:
                raise PKCS11Error(CKR_DEVICE_ERROR, route["error"])
            slot = route["slot_id"]
        child = self._child(sid, slot)
        if context and context["slot"] != slot:
            old = self.api.sessions.get_session(state["children"][context["slot"]])
            new = self.api.sessions.get_session(child)
            prefix = "_" + operation.lower() + "_"
            for field, value in vars(old).items():
                if field.startswith(prefix):
                    setattr(new, field, copy.deepcopy(value))
            if handles:
                physical = self._resolve(sid, slot, next(iter(handles.values())))
                _, material = self.storage.get_object(physical)
                setattr(new, prefix + "key", material)
            setattr(old, prefix + "active", False)
            if hasattr(old, prefix + "key"):
                setattr(old, prefix + "key", None)
            context["slot"] = slot
        actual = dict(params, session_id=child)
        for key in HANDLE_ARGS & params.keys():
            actual[key] = self._resolve(sid, slot, params[key])
        deleted = self._identity(sid, params["handle"]) if name == "C_DestroyObject" else None
        snapshot = copy.deepcopy(vars(self.api.sessions.get_session(child))) if operation else None
        try:
            result = fn(self.api, **actual)
        except PKCS11Error as error:
            if error.code == CKR_DEVICE_ERROR and operation:
                # Retry only crypto, never a possibly committed key mutation.
                vars(self.api.sessions.get_session(child)).update(snapshot)
                self.deployment.fail_ha_member(group["name"], slot, str(error))
                return self.call(fn, params, (excluded or set()) | {slot})
            raise
        if operation:
            if name.endswith("Init"):
                state["operations"][operation] = {"slot": slot, "handles": handles}
            elif not name.endswith("Update"):
                state["operations"].pop(operation, None)
        if deleted:
            self.deployment.record_deletion(group["name"], deleted)
        if name in MUTATIONS:
            # Offline members catch up on recovery. Never repeat a mutation on retry.
            self.deployment.synchronize_ha_group(group["name"], source_slot=slot)
        if name in NEW_OBJECTS:
            if isinstance(result, tuple):
                return tuple(self._logical(sid, handle) for handle in result)
            return self._logical(sid, result)
        return result
