"""Bounded, integrity-bound context packets for worker dispatch.

Context packets are deliberately deterministic and non-generative: the
framework selects explicitly named shared-buffer keys, admits whole JSON
values under a worker-facing render budget, hashes every admitted/omitted
serializable value, and binds the packet to the worker + goal. No LLM
summarization happens here.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

PACKET_VERSION = "hive.context-packet/v1"
DEFAULT_CONTEXT_BUDGET_CHARS = 12_000
DEFAULT_CONTEXT_PACKET_MAX_CHARS = 16_384
HARD_CONTEXT_PACKET_MAX_CHARS = 32_768
MAX_CONTEXT_KEYS = 128

_SENSITIVE_KEY_PARTS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "client_secret",
        "access_token",
        "refresh_token",
        "auth_token",
        "api_key",
        "apikey",
        "private_key",
        "cookie",
        "authorization",
        "credential",
        "credentials",
    }
)


class ContextPacketError(ValueError):
    """Base class for context-packet construction failures."""


class ContextPacketConfigurationError(ContextPacketError):
    """Raised for an invalid node context-packet configuration."""


class MissingRequiredContextError(ContextPacketError):
    """Raised when a required context key is not present."""


class ContextPacketBudgetError(ContextPacketError):
    """Raised when required context cannot fit within a configured bound."""


class ContextPacketSerializationError(ContextPacketError):
    """Raised when required context cannot be represented as canonical JSON."""


class SensitiveContextKeyError(ContextPacketError):
    """Raised when required context contains a credential-like mapping key."""


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


def _normalize_key_sequence(values: Any, *, field: str) -> tuple[str, ...]:
    """Validate and deduplicate one declared context-key sequence.

    NodeSpec intentionally allows extra fields, so context-packet extras do not
    receive Pydantic's normal ``list[str]`` validation. Treating a scalar string
    as a sequence would split one key into characters, while coercing arbitrary
    values with ``str()`` could alias identities or copy caller data into packet
    metadata. Require an actual non-string sequence of exact strings instead.
    """

    if isinstance(values, (str, bytes, bytearray)) or not isinstance(values, Sequence):
        raise ContextPacketConfigurationError(f"{field} must be a sequence of strings")

    seen: set[str] = set()
    result: list[str] = []
    for index, raw in enumerate(values):
        if type(raw) is not str:
            raise ContextPacketConfigurationError(
                f"{field}[{index}] must be a string, not {type(raw).__name__}"
            )
        if raw not in seen:
            result.append(raw)
            seen.add(raw)
    return tuple(result)


def _parse_integer_bound(value: Any, *, field: str) -> int:
    """Parse an integer config bound without bool/float truncation."""

    if type(value) is int:
        return value
    if type(value) is str:
        candidate = value.strip()
        if re.fullmatch(r"[0-9]+", candidate):
            return int(candidate)
    raise ContextPacketConfigurationError(f"{field} must be an integer")


def _validate_key_declarations(requested: tuple[str, ...], required: tuple[str, ...]) -> None:
    """Bound packet metadata before constructing repeated structured fields."""

    if len(requested) > MAX_CONTEXT_KEYS:
        raise ContextPacketConfigurationError(
            f"context_keys contains {len(requested)} entries; maximum is {MAX_CONTEXT_KEYS}"
        )
    if len(required) > MAX_CONTEXT_KEYS:
        raise ContextPacketConfigurationError(
            f"context_required_keys contains {len(required)} entries; maximum is {MAX_CONTEXT_KEYS}"
        )

    declaration_chars = sum(len(key) for key in requested) + sum(len(key) for key in required)
    if declaration_chars > HARD_CONTEXT_PACKET_MAX_CHARS:
        raise ContextPacketConfigurationError(
            "context key declarations exceed framework metadata ceiling "
            f"({declaration_chars} > {HARD_CONTEXT_PACKET_MAX_CHARS} chars)"
        )


def _normalize_key_name(key: str) -> str:
    """Normalize snake/kebab/camel/Pascal key names for secret screening."""

    split_camel = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key)
    split_acronym = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", split_camel)
    return re.sub(r"[^a-z0-9]+", "_", split_acronym.casefold()).strip("_")


def _sensitive_key(key: str) -> bool:
    normalized = _normalize_key_name(key)
    if normalized in _SENSITIVE_KEY_PARTS:
        return True
    parts = normalized.split("_") if normalized else []
    joined_pairs = {"_".join(parts[i : i + 2]) for i in range(max(0, len(parts) - 1))}
    return bool(_SENSITIVE_KEY_PARTS.intersection(parts) or _SENSITIVE_KEY_PARTS.intersection(joined_pairs))


def _find_sensitive_mapping_key(value: Any, path: str = "$", seen: set[int] | None = None) -> str | None:
    """Return the first credential-like mapping-key path in a JSON-like value.

    Values are never inspected for credential *content*. The boundary is
    intentionally key-name based so generic prose is not heuristically
    classified as a secret.
    """

    if seen is None:
        seen = set()

    if isinstance(value, dict):
        object_id = id(value)
        if object_id in seen:
            return None
        seen.add(object_id)
        for raw_key, child in value.items():
            key = str(raw_key)
            child_path = f"{path}.{key}"
            if _sensitive_key(key):
                return child_path
            nested = _find_sensitive_mapping_key(child, child_path, seen)
            if nested is not None:
                return nested
        return None

    if isinstance(value, (list, tuple)):
        object_id = id(value)
        if object_id in seen:
            return None
        seen.add(object_id)
        for index, child in enumerate(value):
            nested = _find_sensitive_mapping_key(child, f"{path}[{index}]", seen)
            if nested is not None:
                return nested

    return None


@dataclass(frozen=True, slots=True)
class ContextPacketEntry:
    """One admitted, whole context value."""

    key: str
    canonical_json: str
    sha256: str
    chars: int

    @property
    def value(self) -> Any:
        return json.loads(self.canonical_json)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "value": self.value,
            "sha256": self.sha256,
            "chars": self.chars,
        }


@dataclass(frozen=True, slots=True)
class ContextPacketOmission:
    """Metadata for context deliberately not included in a packet."""

    key: str
    reason: str
    sha256: str | None = None
    chars: int | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"key": self.key, "reason": self.reason}
        if self.sha256 is not None:
            payload["sha256"] = self.sha256
        if self.chars is not None:
            payload["chars"] = self.chars
        return payload


@dataclass(frozen=True, slots=True)
class ContextPacket:
    """Immutable logical packet delivered to one worker."""

    node_id: str
    node_name: str
    goal_sha256: str
    requested_keys: tuple[str, ...]
    required_keys: tuple[str, ...]
    budget_chars: int
    max_packet_chars: int
    payload_chars: int
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
            "max_packet_chars": self.max_packet_chars,
            "payload_chars": self.payload_chars,
            "entries": [entry.to_dict() for entry in self.entries],
            "omissions": [omission.to_dict() for omission in self.omissions],
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self._body_dict()
        payload["packet_sha256"] = self.packet_sha256
        return payload


def _build_packet_object(
    *,
    node_id: str,
    node_name: str,
    goal_sha256: str,
    requested: tuple[str, ...],
    required: tuple[str, ...],
    budget_chars: int,
    max_packet_chars: int,
    entries: Sequence[ContextPacketEntry],
    omission_by_key: Mapping[str, ContextPacketOmission],
) -> ContextPacket:
    omissions = tuple(omission_by_key[key] for key in requested if key in omission_by_key)
    payload_chars = sum(entry.chars for entry in entries)
    body = {
        "version": PACKET_VERSION,
        "node_id": str(node_id),
        "node_name": str(node_name),
        "goal_sha256": goal_sha256,
        "requested_keys": list(requested),
        "required_keys": list(required),
        "budget_chars": int(budget_chars),
        "max_packet_chars": int(max_packet_chars),
        "payload_chars": payload_chars,
        "entries": [entry.to_dict() for entry in entries],
        "omissions": [omission.to_dict() for omission in omissions],
    }
    return ContextPacket(
        node_id=str(node_id),
        node_name=str(node_name),
        goal_sha256=goal_sha256,
        requested_keys=requested,
        required_keys=required,
        budget_chars=int(budget_chars),
        max_packet_chars=int(max_packet_chars),
        payload_chars=payload_chars,
        entries=tuple(entries),
        omissions=omissions,
        packet_sha256=_sha256(_canonical_json(body)),
    )


def _render_context_packet_text(packet: ContextPacket) -> str:
    """Render prompt-safe packet text without performing bound assertions."""

    entries_json = _canonical_json([entry.to_dict() for entry in packet.entries])
    reason_counts = dict(sorted(Counter(omission.reason for omission in packet.omissions).items()))
    omissions_summary = _canonical_json({"count": len(packet.omissions), "reasons": reason_counts})

    return "\n".join(
        [
            "--- Context Packet (bounded handoff) ---",
            f"version: {packet.version}",
            f"packet_sha256: {packet.packet_sha256}",
            f"goal_sha256: {packet.goal_sha256}",
            f"render_budget_chars: {packet.budget_chars}",
            f"packet_max_chars: {packet.max_packet_chars}",
            f"payload_chars: {packet.payload_chars}",
            "entries_json: " + entries_json,
            "omissions_summary: " + omissions_summary,
            (
                "Use only supplied entry values as facts from this packet. "
                "Detailed omission metadata is programmatic; omission hashes prove identity, not content."
            ),
            "--- End Context Packet ---",
        ]
    )


def _packet_sizes(packet: ContextPacket) -> tuple[int, int]:
    structured_chars = len(_canonical_json(packet.to_dict()))
    rendered_chars = len(_render_context_packet_text(packet))
    return structured_chars, rendered_chars


def _packet_within_bounds(packet: ContextPacket) -> bool:
    structured_chars, rendered_chars = _packet_sizes(packet)
    return (
        rendered_chars <= packet.budget_chars
        and structured_chars <= packet.max_packet_chars
        and rendered_chars <= packet.max_packet_chars
    )


def _assert_packet_bounds(packet: ContextPacket) -> None:
    structured_chars, rendered_chars = _packet_sizes(packet)
    if rendered_chars > packet.budget_chars:
        raise ContextPacketBudgetError(
            "context packet render exceeds configured budget "
            f"({rendered_chars} > {packet.budget_chars} chars)"
        )
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
    """Build a deterministic packet under hard render and complete-size bounds.

    Required keys are admitted before optional keys. Optional entries retain
    declaration order as priority and are admitted whole or omitted whole.
    Credential-like mapping keys are fenced recursively before serialization.
    ``budget_chars`` bounds worker-facing render text; ``max_packet_chars``
    independently bounds both that text and canonical structured packet JSON.
    """

    requested = _normalize_key_sequence(context_keys, field="context_keys")
    required = _normalize_key_sequence(required_keys, field="context_required_keys")
    _validate_key_declarations(requested, required)
    requested_set = set(requested)

    unknown_required = [key for key in required if key not in requested_set]
    if unknown_required:
        raise ContextPacketConfigurationError(
            "required context keys must also appear in context_keys: " + ", ".join(unknown_required)
        )

    resolved_budget = _parse_integer_bound(
        budget_chars,
        field="context packet budget_chars",
    )
    if resolved_budget <= 0:
        raise ContextPacketConfigurationError("context packet budget_chars must be > 0")

    resolved_max_packet = _parse_integer_bound(
        max_packet_chars,
        field="context_packet_max_chars",
    )
    if resolved_max_packet <= 0:
        raise ContextPacketConfigurationError("context_packet_max_chars must be > 0")
    if resolved_max_packet > HARD_CONTEXT_PACKET_MAX_CHARS:
        raise ContextPacketConfigurationError(
            "context_packet_max_chars exceeds framework hard maximum "
            f"({resolved_max_packet} > {HARD_CONTEXT_PACKET_MAX_CHARS})"
        )

    required_set = set(required)
    admission_order = list(required) + [key for key in requested if key not in required_set]
    required_entries: list[ContextPacketEntry] = []
    optional_entries: list[ContextPacketEntry] = []
    omission_by_key: dict[str, ContextPacketOmission] = {}

    for key in admission_order:
        is_required = key in required_set

        if _sensitive_key(key):
            if is_required:
                raise SensitiveContextKeyError(
                    f"required context key '{key}' is credential-like and cannot be packetized"
                )
            omission_by_key[key] = ContextPacketOmission(key=key, reason="sensitive_key")
            continue

        if key not in values:
            if is_required:
                raise MissingRequiredContextError(f"required context key '{key}' is missing")
            omission_by_key[key] = ContextPacketOmission(key=key, reason="missing")
            continue

        sensitive_path = _find_sensitive_mapping_key(values[key])
        if sensitive_path is not None:
            if is_required:
                raise SensitiveContextKeyError(
                    f"required context key '{key}' contains credential-like mapping key at {sensitive_path}"
                )
            omission_by_key[key] = ContextPacketOmission(key=key, reason="sensitive_key")
            continue

        try:
            canonical = _canonical_json(values[key])
        except ContextPacketSerializationError as exc:
            if is_required:
                raise ContextPacketSerializationError(
                    f"required context key '{key}' is not canonical JSON"
                ) from exc
            omission_by_key[key] = ContextPacketOmission(key=key, reason="non_json")
            continue

        entry = ContextPacketEntry(
            key=key,
            canonical_json=canonical,
            sha256=_sha256(canonical),
            chars=len(canonical),
        )
        if is_required:
            required_entries.append(entry)
        else:
            optional_entries.append(entry)
            omission_by_key[key] = ContextPacketOmission(
                key=key,
                reason="budget",
                sha256=entry.sha256,
                chars=entry.chars,
            )

    goal_sha256 = _sha256(str(goal_context))

    packet = _build_packet_object(
        node_id=node_id,
        node_name=node_name,
        goal_sha256=goal_sha256,
        requested=requested,
        required=required,
        budget_chars=resolved_budget,
        max_packet_chars=resolved_max_packet,
        entries=required_entries,
        omission_by_key=omission_by_key,
    )
    _assert_packet_bounds(packet)

    admitted_entries = list(required_entries)
    for entry in optional_entries:
        trial_entries = [*admitted_entries, entry]
        trial_omissions = dict(omission_by_key)
        trial_omissions.pop(entry.key, None)
        trial_packet = _build_packet_object(
            node_id=node_id,
            node_name=node_name,
            goal_sha256=goal_sha256,
            requested=requested,
            required=required,
            budget_chars=resolved_budget,
            max_packet_chars=resolved_max_packet,
            entries=trial_entries,
            omission_by_key=trial_omissions,
        )
        if _packet_within_bounds(trial_packet):
            admitted_entries = trial_entries
            omission_by_key = trial_omissions

    packet = _build_packet_object(
        node_id=node_id,
        node_name=node_name,
        goal_sha256=goal_sha256,
        requested=requested,
        required=required,
        budget_chars=resolved_budget,
        max_packet_chars=resolved_max_packet,
        entries=admitted_entries,
        omission_by_key=omission_by_key,
    )
    _assert_packet_bounds(packet)
    return packet


def _authorized_buffer_keys(node_spec: Any, values: Mapping[str, Any]) -> set[str] | None:
    """Mirror the node's existing effective shared-buffer read authority."""

    input_keys = list(getattr(node_spec, "input_keys", None) or [])
    if not input_keys:
        return None

    authorized = {str(key) for key in input_keys}
    authorized.update(
        key for key in values if isinstance(key, str) and key.startswith("_")
    )
    return authorized


def build_node_context_packet(*, node_spec: Any, buffer: Any, goal_context: str) -> ContextPacket | None:
    """Build a packet without expanding the node's shared-buffer read scope.

    The feature is opt-in: a node only receives a packet when it declares a
    non-empty ``context_keys`` extra field. ``context_required_keys``,
    ``context_char_budget`` and ``context_packet_max_chars`` are optional
    companion fields.
    """

    raw_context_keys = getattr(node_spec, "context_keys", None)
    if raw_context_keys is None:
        return None
    context_keys = _normalize_key_sequence(raw_context_keys, field="context_keys")
    if not context_keys:
        return None

    raw_required_keys = getattr(node_spec, "context_required_keys", ())
    if raw_required_keys is None:
        raw_required_keys = ()
    required_keys = _normalize_key_sequence(
        raw_required_keys,
        field="context_required_keys",
    )
    _validate_key_declarations(context_keys, required_keys)

    raw_budget = getattr(node_spec, "context_char_budget", DEFAULT_CONTEXT_BUDGET_CHARS)
    raw_max_packet = getattr(
        node_spec,
        "context_packet_max_chars",
        DEFAULT_CONTEXT_PACKET_MAX_CHARS,
    )
    budget_chars = _parse_integer_bound(
        raw_budget,
        field="context_char_budget",
    )
    max_packet_chars = _parse_integer_bound(
        raw_max_packet,
        field="context_packet_max_chars",
    )

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
    """Render a prompt-safe packet and assert both configured hard bounds."""

    _assert_packet_bounds(packet)
    return _render_context_packet_text(packet)
