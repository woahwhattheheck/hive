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
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

PACKET_VERSION = "hive.context-packet/v1"
DEFAULT_CONTEXT_BUDGET_CHARS = 12_000

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
    """Raised when required context cannot fit within the configured budget."""


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


def _dedupe(values: Sequence[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    result: list[str] = []
    for raw in values:
        key = str(raw)
        if key not in seen:
            result.append(key)
            seen.add(key)
    return tuple(result)


def _normalize_key_name(key: str) -> str:
    """Normalize snake/kebab/camel/Pascal key names for secret screening."""

    # ``accessToken`` -> ``access_Token`` and ``APIKey`` -> ``API_Key``.
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
        payload_chars=payload_chars,
        entries=tuple(entries),
        omissions=omissions,
        packet_sha256=_sha256(_canonical_json(body)),
    )


def _render_context_packet_text(packet: ContextPacket) -> str:
    """Render prompt-safe packet text without performing the budget assertion."""

    # Canonical JSON is used for entry rendering so context key names and string
    # values cannot create new prompt lines or delimiters via embedded controls.
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


def build_context_packet(
    *,
    node_id: str,
    node_name: str,
    goal_context: str,
    values: Mapping[str, Any],
    context_keys: Sequence[str],
    required_keys: Sequence[str] = (),
    budget_chars: int = DEFAULT_CONTEXT_BUDGET_CHARS,
) -> ContextPacket:
    """Build a deterministic packet under a hard worker-facing render budget.

    Required keys are admitted before optional keys. Optional entries retain
    declaration order as priority and are admitted whole or omitted whole.
    Credential-like mapping keys are fenced recursively before serialization.
    """

    requested = _dedupe(context_keys)
    required = _dedupe(required_keys)
    requested_set = set(requested)

    unknown_required = [key for key in required if key not in requested_set]
    if unknown_required:
        raise ContextPacketConfigurationError(
            "required context keys must also appear in context_keys: " + ", ".join(unknown_required)
        )
    if budget_chars <= 0:
        raise ContextPacketConfigurationError("context packet budget_chars must be > 0")

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
        except ContextPacketSerializationError:
            if is_required:
                raise ContextPacketSerializationError(f"required context key '{key}' is not canonical JSON")
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
            # Start optional serializable values as budget omissions, then
            # promote them one-by-one in priority order if the complete prompt
            # still fits. This makes the configured budget a real render bound.
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
        budget_chars=budget_chars,
        entries=required_entries,
        omission_by_key=omission_by_key,
    )
    required_render_chars = len(_render_context_packet_text(packet))
    if required_render_chars > budget_chars:
        raise ContextPacketBudgetError(
            "required context plus packet envelope does not fit render budget "
            f"({required_render_chars} > {budget_chars} chars)"
        )

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
            budget_chars=budget_chars,
            entries=trial_entries,
            omission_by_key=trial_omissions,
        )
        if len(_render_context_packet_text(trial_packet)) <= budget_chars:
            admitted_entries = trial_entries
            omission_by_key = trial_omissions

    packet = _build_packet_object(
        node_id=node_id,
        node_name=node_name,
        goal_sha256=goal_sha256,
        requested=requested,
        required=required,
        budget_chars=budget_chars,
        entries=admitted_entries,
        omission_by_key=omission_by_key,
    )
    rendered_chars = len(_render_context_packet_text(packet))
    if rendered_chars > budget_chars:
        # Defensive invariant: the admission loop above should make this
        # unreachable, but fail closed rather than emitting an oversized prompt.
        raise ContextPacketBudgetError(
            f"context packet render exceeds configured budget ({rendered_chars} > {budget_chars} chars)"
        )
    return packet


def build_node_context_packet(*, node_spec: Any, buffer: Any, goal_context: str) -> ContextPacket | None:
    """Build a packet from an orchestrator NodeSpec/DataBuffer-like pair.

    The feature is opt-in: a node only receives a packet when it declares a
    non-empty ``context_keys`` extra field. ``context_required_keys`` and
    ``context_char_budget`` are optional companion fields.
    """

    context_keys = list(getattr(node_spec, "context_keys", None) or [])
    if not context_keys:
        return None

    required_keys = list(getattr(node_spec, "context_required_keys", None) or [])
    raw_budget = getattr(node_spec, "context_char_budget", DEFAULT_CONTEXT_BUDGET_CHARS)
    try:
        budget_chars = int(raw_budget)
    except (TypeError, ValueError) as exc:
        raise ContextPacketConfigurationError("context_char_budget must be an integer") from exc

    values = buffer.read_all()
    return build_context_packet(
        node_id=getattr(node_spec, "id", ""),
        node_name=getattr(node_spec, "name", ""),
        goal_context=goal_context,
        values=values,
        context_keys=context_keys,
        required_keys=required_keys,
        budget_chars=budget_chars,
    )


def render_context_packet(packet: ContextPacket) -> str:
    """Render a prompt-safe packet and assert its configured hard bound."""

    rendered = _render_context_packet_text(packet)
    if len(rendered) > packet.budget_chars:
        raise ContextPacketBudgetError(
            f"context packet render exceeds configured budget ({len(rendered)} > {packet.budget_chars} chars)"
        )
    return rendered
