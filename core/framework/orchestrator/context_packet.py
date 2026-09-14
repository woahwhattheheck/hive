"""Authority-hardened context packets for worker dispatch.

The implementation merged in #17 is preserved as ``context_packet_v1``.
This public module keeps its API while closing three live dispatch boundaries:

* packet selection cannot expand a node's existing shared-buffer read authority;
* credential-shaped fields are fenced recursively inside JSON values; and
* a separate hard ceiling bounds the complete worker-facing packet, including
  metadata, rather than only admitted value characters.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from framework.orchestrator import context_packet_v1 as _legacy

PACKET_VERSION = _legacy.PACKET_VERSION
DEFAULT_CONTEXT_BUDGET_CHARS = _legacy.DEFAULT_CONTEXT_BUDGET_CHARS
DEFAULT_CONTEXT_PACKET_MAX_CHARS = 16_384
HARD_CONTEXT_PACKET_MAX_CHARS = 32_768
MAX_CONTEXT_KEYS = 128
MAX_CONTEXT_KEY_CHARS = 256

ContextPacketError = _legacy.ContextPacketError
ContextPacketConfigurationError = _legacy.ContextPacketConfigurationError
MissingRequiredContextError = _legacy.MissingRequiredContextError
ContextPacketBudgetError = _legacy.ContextPacketBudgetError
ContextPacketSerializationError = _legacy.ContextPacketSerializationError
SensitiveContextKeyError = _legacy.SensitiveContextKeyError
ContextPacketEntry = _legacy.ContextPacketEntry
ContextPacketOmission = _legacy.ContextPacketOmission


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ContextPacketSerializationError(f"context value is not canonical JSON: {exc}") from exc


def _validated_keys(values: Sequence[str], *, label: str) -> tuple[str, ...]:
    """Validate and deduplicate packet key declarations before metadata build."""

    if len(values) > MAX_CONTEXT_KEYS:
        raise ContextPacketConfigurationError(
            f"{label} contains {len(values)} entries; maximum is {MAX_CONTEXT_KEYS}"
        )

    seen: set[str] = set()
    result: list[str] = []
    for raw in values:
        if not isinstance(raw, str) or not raw:
            raise ContextPacketConfigurationError(f"{label} entries must be non-empty strings")
        if len(raw) > MAX_CONTEXT_KEY_CHARS:
            raise ContextPacketConfigurationError(
                f"{label} entry exceeds {MAX_CONTEXT_KEY_CHARS} characters"
            )
        if raw not in seen:
            seen.add(raw)
            result.append(raw)
    return tuple(result)


def _sensitive_value_path(value: Any) -> str | None:
    """Find a nested credential-shaped object key without recursive traversal.

    Iterative, cycle-tolerant traversal keeps pre-serialization inspection from
    becoming its own recursion/cycle failure mode.
    """

    stack: list[tuple[Any, str]] = [(value, "$")]
    seen: set[int] = set()

    while stack:
        current, path = stack.pop()

        if isinstance(current, Mapping):
            marker = id(current)
            if marker in seen:
                continue
            seen.add(marker)
            for raw_key, nested in current.items():
                if isinstance(raw_key, str):
                    child_path = f"{path}.{raw_key}"
                    if _legacy._sensitive_key(raw_key):
                        return child_path
                else:
                    child_path = f"{path}.[key]"
                stack.append((nested, child_path))
            continue

        if isinstance(current, (list, tuple)):
            marker = id(current)
            if marker in seen:
                continue
            seen.add(marker)
            for index, nested in enumerate(current):
                stack.append((nested, f"{path}[{index}]"))

    return None


@dataclass(frozen=True, slots=True)
class ContextPacket:
    """Immutable logical packet with a complete-representation ceiling."""

    node_id: str
    node_name: str
    goal_sha256: str
    requested_keys: tuple[str, ...]
    required_keys: tuple[str, ...]
    budget_chars: int
    payload_chars: int
    max_packet_chars: int
    entries: tuple[ContextPacketEntry, ...]
    omissions: tuple[ContextPacketOmission, ...]
    packet_sha256: str
    version: str = PACKET_VERSION

    def _body_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "node_id": self.node_id,
            "node_name": self.node_name,
            "goal_sha256": self.goal_sha256,
            "requested_keys": list(self.requested_keys),
            "required_keys": list(self.required_keys),
            "budget_chars": self.budget_chars,
            "payload_chars": self.payload_chars,
            "max_packet_chars": self.max_packet_chars,
            "entries": [entry.to_dict() for entry in self.entries],
            "omissions": [omission.to_dict() for omission in self.omissions],
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self._body_dict()
        payload["packet_sha256"] = self.packet_sha256
        return payload


def _render_unchecked(packet: ContextPacket) -> str:
    lines = [
        "--- Context Packet (bounded handoff) ---",
        f"version: {packet.version}",
        f"packet_sha256: {packet.packet_sha256}",
        f"goal_sha256: {packet.goal_sha256}",
        f"payload_chars: {packet.payload_chars}/{packet.budget_chars}",
        f"packet_max_chars: {packet.max_packet_chars}",
        "Use only supplied entry values as facts from this packet; omission hashes prove identity, not content.",
    ]

    if packet.entries:
        lines.append("entries:")
        for entry in packet.entries:
            lines.append(f"- {entry.key} [sha256={entry.sha256}; chars={entry.chars}]: {entry.canonical_json}")
    else:
        lines.append("entries: []")

    if packet.omissions:
        lines.append("omissions:")
        for omission in packet.omissions:
            metadata = [f"reason={omission.reason}"]
            if omission.sha256 is not None:
                metadata.append(f"sha256={omission.sha256}")
            if omission.chars is not None:
                metadata.append(f"chars={omission.chars}")
            lines.append(f"- {omission.key} [{'; '.join(metadata)}]")

    lines.append("--- End Context Packet ---")
    return "\n".join(lines)


def _validate_representation_bound(packet: ContextPacket) -> None:
    structured_chars = len(_canonical_json(packet.to_dict()))
    rendered_chars = len(_render_unchecked(packet))
    largest = max(structured_chars, rendered_chars)
    if largest > packet.max_packet_chars:
        raise ContextPacketBudgetError(
            "complete context packet exceeds context_packet_max_chars "
            f"({largest} > {packet.max_packet_chars}; "
            f"structured={structured_chars}, rendered={rendered_chars})"
        )


def build_context_packet(
    *,
    node_id: str,
    node_name: str,
    goal_context: str,
    values: Mapping[str, Any],
    context_keys: Sequence[str],
    required_keys: Sequence[str] = (),
    budget_chars: int = DEFAULT_CONTEXT_BUDGET_CHARS,
    max_packet_chars: int = DEFAULT_CONTEXT_PACKET_MAX_CHARS,
) -> ContextPacket:
    """Build a deterministic packet with nested-secret and full-size fencing.

    ``budget_chars`` retains #17's whole-value payload admission semantics.
    ``max_packet_chars`` independently bounds both worker-facing packet forms.
    """

    requested = _validated_keys(context_keys, label="context_keys")
    required = _validated_keys(required_keys, label="context_required_keys")
    required_set = set(required)

    try:
        resolved_max = int(max_packet_chars)
    except (TypeError, ValueError) as exc:
        raise ContextPacketConfigurationError("context_packet_max_chars must be an integer") from exc
    if resolved_max <= 0:
        raise ContextPacketConfigurationError("context_packet_max_chars must be > 0")
    if resolved_max > HARD_CONTEXT_PACKET_MAX_CHARS:
        raise ContextPacketConfigurationError(
            "context_packet_max_chars exceeds framework hard maximum "
            f"({resolved_max} > {HARD_CONTEXT_PACKET_MAX_CHARS})"
        )

    # Never hand nested credential-bearing material to the v1 serializer. For an
    # optional value we remove it and later rewrite v1's "missing" omission to
    # the truthful "sensitive_value" reason without retaining a secret digest.
    nested_sensitive: set[str] = set()
    filtered_values = dict(values)
    for key in requested:
        if key not in values or _legacy._sensitive_key(key):
            continue
        sensitive_path = _sensitive_value_path(values[key])
        if sensitive_path is None:
            continue
        if key in required_set:
            raise SensitiveContextKeyError(
                f"required context key '{key}' contains credential-like nested field at {sensitive_path}"
            )
        nested_sensitive.add(key)
        filtered_values.pop(key, None)

    base = _legacy.build_context_packet(
        node_id=node_id,
        node_name=node_name,
        goal_context=goal_context,
        values=filtered_values,
        context_keys=requested,
        required_keys=required,
        budget_chars=budget_chars,
    )

    omissions: list[ContextPacketOmission] = []
    for omission in base.omissions:
        if omission.key in nested_sensitive:
            omissions.append(
                ContextPacketOmission(
                    key=omission.key,
                    reason="sensitive_value",
                )
            )
        else:
            omissions.append(omission)

    body = {
        "version": base.version,
        "node_id": base.node_id,
        "node_name": base.node_name,
        "goal_sha256": base.goal_sha256,
        "requested_keys": list(base.requested_keys),
        "required_keys": list(base.required_keys),
        "budget_chars": base.budget_chars,
        "payload_chars": base.payload_chars,
        "max_packet_chars": resolved_max,
        "entries": [entry.to_dict() for entry in base.entries],
        "omissions": [omission.to_dict() for omission in omissions],
    }

    packet = ContextPacket(
        node_id=base.node_id,
        node_name=base.node_name,
        goal_sha256=base.goal_sha256,
        requested_keys=base.requested_keys,
        required_keys=base.required_keys,
        budget_chars=base.budget_chars,
        payload_chars=base.payload_chars,
        max_packet_chars=resolved_max,
        entries=base.entries,
        omissions=tuple(omissions),
        packet_sha256=_sha256(_canonical_json(body)),
        version=base.version,
    )
    _validate_representation_bound(packet)
    return packet


def _authorized_buffer_keys(node_spec: Any, values: Mapping[str, Any]) -> set[str] | None:
    """Mirror the node's existing DataBuffer read authority for packet reads."""

    input_keys = list(getattr(node_spec, "input_keys", None) or [])
    # DataBuffer represents unrestricted read access as an empty allow-set.
    # build_scoped_buffer() only adds managed `_` keys when read_keys is already
    # non-empty, so output-only nodes remain read-unrestricted.
    if not input_keys:
        return None

    authorized = set(input_keys)
    authorized.update(
        key for key in values if isinstance(key, str) and key.startswith("_")
    )
    return authorized


def build_node_context_packet(*, node_spec: Any, buffer: Any, goal_context: str) -> ContextPacket | None:
    """Build a packet without expanding the node's shared-buffer read scope."""

    raw_context_keys = list(getattr(node_spec, "context_keys", None) or [])
    if not raw_context_keys:
        return None

    context_keys = _validated_keys(raw_context_keys, label="context_keys")
    required_keys = _validated_keys(
        list(getattr(node_spec, "context_required_keys", None) or []),
        label="context_required_keys",
    )

    raw_budget = getattr(node_spec, "context_char_budget", DEFAULT_CONTEXT_BUDGET_CHARS)
    raw_max_packet = getattr(
        node_spec,
        "context_packet_max_chars",
        DEFAULT_CONTEXT_PACKET_MAX_CHARS,
    )
    try:
        budget_chars = int(raw_budget)
    except (TypeError, ValueError) as exc:
        raise ContextPacketConfigurationError("context_char_budget must be an integer") from exc
    try:
        max_packet_chars = int(raw_max_packet)
    except (TypeError, ValueError) as exc:
        raise ContextPacketConfigurationError("context_packet_max_chars must be an integer") from exc

    values = buffer.read_all()
    authorized = _authorized_buffer_keys(node_spec, values)
    if authorized is not None:
        unauthorized = [key for key in context_keys if key not in authorized]
        if unauthorized:
            raise ContextPacketConfigurationError(
                "context_keys exceed node buffer read authority: " + ", ".join(unauthorized)
            )
        values = {key: value for key, value in values.items() if key in authorized}

    return build_context_packet(
        node_id=getattr(node_spec, "id", ""),
        node_name=getattr(node_spec, "name", ""),
        goal_context=goal_context,
        values=values,
        context_keys=context_keys,
        required_keys=required_keys,
        budget_chars=budget_chars,
        max_packet_chars=max_packet_chars,
    )


def render_context_packet(packet: ContextPacket) -> str:
    """Render a compact worker-facing prompt block within the packet ceiling."""

    rendered = _render_unchecked(packet)
    if len(rendered) > packet.max_packet_chars:
        raise ContextPacketBudgetError(
            "rendered context packet exceeds context_packet_max_chars "
            f"({len(rendered)} > {packet.max_packet_chars})"
        )
    return rendered
