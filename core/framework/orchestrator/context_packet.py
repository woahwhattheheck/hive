"""Bounded, integrity-bound context packets for worker dispatch.

Context packets are deliberately deterministic and non-generative: the
framework selects explicitly named shared-buffer keys, admits whole JSON
values under a budget, hashes every admitted/omitted serializable value, and
binds the packet to the worker + goal. No LLM summarization happens here.
"""

from __future__ import annotations

import hashlib
import json
import re
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
    """Raised when a required key looks like credential material."""


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


def _sensitive_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_")
    if normalized in _SENSITIVE_KEY_PARTS:
        return True
    parts = normalized.split("_") if normalized else []
    joined_pairs = {"_".join(parts[i : i + 2]) for i in range(max(0, len(parts) - 1))}
    return bool(_SENSITIVE_KEY_PARTS.intersection(parts) or _SENSITIVE_KEY_PARTS.intersection(joined_pairs))


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
    """Build a deterministic, bounded packet from explicitly selected values.

    Required keys are admitted before optional keys so optional material cannot
    crowd out a requirement. Optional entries are admitted whole or omitted;
    values are never truncated into a different fact.
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
    entries: list[ContextPacketEntry] = []
    omissions: list[ContextPacketOmission] = []
    payload_chars = 0

    for key in admission_order:
        is_required = key in required_set

        if _sensitive_key(key):
            if is_required:
                raise SensitiveContextKeyError(f"required context key '{key}' is credential-like and cannot be packetized")
            omissions.append(ContextPacketOmission(key=key, reason="sensitive_key"))
            continue

        if key not in values:
            if is_required:
                raise MissingRequiredContextError(f"required context key '{key}' is missing")
            omissions.append(ContextPacketOmission(key=key, reason="missing"))
            continue

        try:
            canonical = _canonical_json(values[key])
        except ContextPacketSerializationError:
            if is_required:
                raise ContextPacketSerializationError(f"required context key '{key}' is not canonical JSON")
            omissions.append(ContextPacketOmission(key=key, reason="non_json"))
            continue

        chars = len(canonical)
        digest = _sha256(canonical)
        if payload_chars + chars > budget_chars:
            if is_required:
                raise ContextPacketBudgetError(
                    f"required context key '{key}' ({chars} chars) does not fit remaining packet budget "
                    f"({budget_chars - payload_chars} chars)"
                )
            omissions.append(
                ContextPacketOmission(
                    key=key,
                    reason="budget",
                    sha256=digest,
                    chars=chars,
                )
            )
            continue

        entries.append(
            ContextPacketEntry(
                key=key,
                canonical_json=canonical,
                sha256=digest,
                chars=chars,
            )
        )
        payload_chars += chars

    body = {
        "version": PACKET_VERSION,
        "node_id": str(node_id),
        "node_name": str(node_name),
        "goal_sha256": _sha256(str(goal_context)),
        "requested_keys": list(requested),
        "required_keys": list(required),
        "budget_chars": int(budget_chars),
        "payload_chars": payload_chars,
        "entries": [entry.to_dict() for entry in entries],
        "omissions": [omission.to_dict() for omission in omissions],
    }
    packet_sha256 = _sha256(_canonical_json(body))

    return ContextPacket(
        node_id=str(node_id),
        node_name=str(node_name),
        goal_sha256=body["goal_sha256"],
        requested_keys=requested,
        required_keys=required,
        budget_chars=int(budget_chars),
        payload_chars=payload_chars,
        entries=tuple(entries),
        omissions=tuple(omissions),
        packet_sha256=packet_sha256,
    )


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
    """Render a compact worker-facing prompt block."""

    lines = [
        "--- Context Packet (bounded handoff) ---",
        f"version: {packet.version}",
        f"packet_sha256: {packet.packet_sha256}",
        f"goal_sha256: {packet.goal_sha256}",
        f"payload_chars: {packet.payload_chars}/{packet.budget_chars}",
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
