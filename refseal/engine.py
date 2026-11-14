from __future__ import annotations
from typing import Any

import hashlib
import hmac
import json
import re


ZERO_OID = "0" * 40

REASON_ORDER = (
    "broken_ref",
    "force_push",
    "unsigned_commit",
    "bad_signature",
    "committer_mismatch",
    "unsigned_parent",
    "tag_mismatch",
    "unsigned_tag_target",
    "trailer_only",
)

COMMIT_FIELDS = ("type", "tree", "parents", "author", "committer", "message")
TAG_FIELDS = ("type", "object", "object_type", "tag", "tagger", "message")
_EMAIL_RE = re.compile(r"<([^>]+)>")


def _signed_bytes(obj: dict[str, Any]) -> bytes:
    fields = TAG_FIELDS if obj.get("type") == "tag" else COMMIT_FIELDS
    payload = {key: obj[key] for key in fields if key in obj}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _email(identity: Any) -> str:
    text = str(identity or "")
    match = _EMAIL_RE.search(text)
    return (match.group(1) if match else text.strip()).lower()


def _mac_matches(obj: dict[str, Any], signature: dict[str, Any] | None, keys: dict[str, str]) -> bool:
    if not isinstance(signature, dict):
        return False
    key_id = signature.get("key_id")
    mac = signature.get("mac")
    if not isinstance(key_id, str) or not isinstance(mac, str):
        return False
    try:
        key = bytes.fromhex(str(keys.get(key_id, "")))
    except ValueError:
        return False
    expected = hmac.new(key, _signed_bytes(obj), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, mac.lower())


def _mapped_key(identity: Any, policy: dict[str, Any]) -> str | None:
    mapping = policy.get("committer_keys") or {}
    if not isinstance(mapping, dict):
        return None
    key_id = mapping.get(_email(identity))
    return key_id if isinstance(key_id, str) else None


def _has_trailer(message: Any) -> bool:
    return any("signed-off-by:" in line.lower() for line in str(message or "").splitlines())


def _verify_actor(oid: str, obj: dict[str, Any], identity_key: str,
                  update: dict[str, Any], policy: dict[str, Any],
                  keys: dict[str, str], trailer: bool) -> str | None:
    signature = (update.get("signatures") or {}).get(oid)
    if signature is None:
        if trailer and _has_trailer(obj.get("message")):
            return "trailer_only"
        return "unsigned_commit"
    if not _mac_matches(obj, signature, keys):
        return "bad_signature"
    if signature.get("key_id") != _mapped_key(obj.get(identity_key), policy):
        return "committer_mismatch"
    return None


def _valid_mapped_signature(oid: str, update: dict[str, Any], policy: dict[str, Any],
                            keys: dict[str, str]) -> bool:
    obj = (update.get("objects") or {}).get(oid)
    if not isinstance(obj, dict) or obj.get("type") != "commit":
        return False
    signature = (update.get("signatures") or {}).get(oid)
    if not _mac_matches(obj, signature, keys):
        return False
    return signature.get("key_id") == _mapped_key(obj.get("committer"), policy)


def _reachable(start: str | None, objects: dict[str, Any]) -> set[str]:
    seen: set[str] = set()
    stack = [start]
    while stack:
        oid = stack.pop()
        if not oid or oid in seen:
            continue
        obj = objects.get(oid)
        if not isinstance(obj, dict):
            continue
        seen.add(oid)
        if obj.get("type") == "commit":
            stack.extend(parent for parent in obj.get("parents", []) if isinstance(parent, str))
        elif obj.get("type") == "tag":
            target = obj.get("object")
            if isinstance(target, str):
                stack.append(target)
    return seen


def _ordered(reasons: set[str]) -> list[str]:
    return [code for code in REASON_ORDER if code in reasons]


def admit(update: dict[str, Any], policy: dict[str, Any], keys: dict[str, str]) -> dict[str, Any]:
    objects = update.get("objects") or {}
    signatures = update.get("signatures") or {}
    ref = update.get("ref") or ""
    old_oid = update.get("old_oid")
    new_oid = update.get("new_oid")

    reasons: set[str] = set()
    notes: list[str] = []

    if not new_oid or new_oid == ZERO_OID or new_oid not in objects:
        return {
            "decision": "deny",
            "reason_codes": ["broken_ref"],
            "introduced": [],
            "notes": ["broken_ref: new_oid is missing, zero, or absent from objects"],
        }

    old_set: set[str] = set()
    if old_oid and old_oid != ZERO_OID:
        old_set = _reachable(old_oid, objects)
    new_set = _reachable(new_oid, objects)
    introduced = sorted(new_set - old_set)

    protected = ref in (policy.get("protected_refs") or [])
    if protected and not policy.get("allow_force") and old_oid and old_oid != ZERO_OID:
        if old_oid not in new_set:
            reasons.add("force_push")
            notes.append(f"force_push: old tip {old_oid} is not reachable from {new_oid}")

    merge_parents: list[tuple[str, dict[str, Any]]] = []
    for oid in introduced:
        obj = objects.get(oid)
        if not isinstance(obj, dict):
            continue
        obj_type = obj.get("type")
        if obj_type == "commit":
            reason = _verify_actor(oid, obj, "committer", update, policy, keys, trailer=True)
            if reason:
                reasons.add(reason)
                notes.append(f"{reason}: commit {oid}")
            if len(obj.get("parents", [])) >= 2:
                merge_parents.append((oid, obj))
        elif obj_type == "tag":
            reason = _verify_actor(oid, obj, "tagger", update, policy, keys, trailer=False)
            if reason:
                reasons.add(reason)
                notes.append(f"{reason}: tag {oid}")

    for merge_oid, merge_obj in merge_parents:
        for parent in merge_obj.get("parents", []):
            if parent in old_set:
                continue
            if not _valid_mapped_signature(parent, update, policy, keys):
                reasons.add("unsigned_parent")
                notes.append(f"unsigned_parent: merge {merge_oid} parent {parent}")

    new_obj = objects.get(new_oid)
    is_tag_ref = str(ref).startswith("refs/tags/")
    if is_tag_ref or (isinstance(new_obj, dict) and new_obj.get("type") == "tag"):
        tag_name = ref[len("refs/tags/"):] if is_tag_ref else None
        if isinstance(new_obj, dict) and new_obj.get("type") == "tag":
            if tag_name is not None and new_obj.get("tag") != tag_name:
                reasons.add("tag_mismatch")
                notes.append(f"tag_mismatch: tag object names {new_obj.get('tag')!r}, ref names {tag_name!r}")
            target = new_obj.get("object")
            if not _valid_mapped_signature(target, update, policy, keys):
                reasons.add("unsigned_tag_target")
                notes.append(f"unsigned_tag_target: tag {new_oid} target {target}")
        elif isinstance(new_obj, dict) and new_obj.get("type") == "commit":
            target_signature = signatures.get(new_oid)
            if target_signature is None or not _mac_matches(new_obj, target_signature, keys):
                reasons.add("unsigned_tag_target")
                notes.append(f"unsigned_tag_target: lightweight tag {new_oid}")

    ordered = _ordered(reasons)
    notes.sort(key=lambda note: (REASON_ORDER.index(note.split(":", 1)[0]), note))
    return {
        "decision": "deny" if ordered else "allow",
        "reason_codes": ordered,
        "introduced": introduced,
        "notes": notes,
    }
