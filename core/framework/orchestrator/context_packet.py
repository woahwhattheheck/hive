"""Public context-packet API with exact shared-buffer and value authority.

The reviewed implementation is retained byte-for-byte in
``context_packet_impl``. This facade narrows the authority resolver to the
actual ``DataBuffer`` contract and snapshots selected caller values into one
strict plain-JSON generation before credential screening or serialization.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any

from . import context_packet_impl as _impl

_MISSING = object()
_NON_JSON = object()


class _SnapshotRejected(ValueError):
    """Internal signal for a value that is unsafe to inspect as JSON."""


def _authorized_buffer_keys(
    node_spec: Any,
    values: Mapping[str, Any],
) -> set[str] | None:
    """Mirror ``DataBuffer.with_permissions`` without name-based expansion."""

    del values  # Buffer contents do not define who may read them.
    input_keys = list(getattr(node_spec, "input_keys", None) or [])
    if not input_keys:
        return None
    return {str(key) for key in input_keys}


def _plain_utf8_string(value: Any) -> str:
    if type(value) is not str:
        raise _SnapshotRejected("JSON object keys and strings must be plain strings")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise _SnapshotRejected("JSON strings must be valid UTF-8") from exc
    return value


def _snapshot_json_value(value: Any, seen: set[int]) -> Any:
    """Detach one value without invoking user-defined container accessors."""

    if value is None or type(value) in (bool, int):
        return value
    if type(value) is str:
        return _plain_utf8_string(value)
    if type(value) is float:
        if not math.isfinite(value):
            raise _SnapshotRejected("non-finite numbers are not canonical JSON")
        return value

    if type(value) is dict:
        object_id = id(value)
        if object_id in seen:
            raise _SnapshotRejected("shared or cyclic JSON containers are not accepted")
        seen.add(object_id)
        copied = dict.copy(value)
        detached: dict[str, Any] = {}
        for key, child in dict.items(copied):
            plain_key = _plain_utf8_string(key)
            detached[plain_key] = _snapshot_json_value(child, seen)
        return detached

    if type(value) is list:
        object_id = id(value)
        if object_id in seen:
            raise _SnapshotRejected("shared or cyclic JSON containers are not accepted")
        seen.add(object_id)
        return [_snapshot_json_value(child, seen) for child in list.copy(value)]

    if type(value) is tuple:
        object_id = id(value)
        if object_id in seen:
            raise _SnapshotRejected("shared or cyclic JSON containers are not accepted")
        seen.add(object_id)
        return [_snapshot_json_value(child, seen) for child in value]

    raise _SnapshotRejected("custom objects and container subclasses are not accepted")


def _capture_plain_values(values: Any) -> dict[str, Any]:
    """Capture an outer context mapping without invoking custom accessors."""

    if type(values) is not dict:
        raise _impl.ContextPacketSerializationError(
            "context values must be supplied as a plain dict"
        )

    source = dict.copy(values)
    for key in dict.keys(source):
        try:
            _plain_utf8_string(key)
        except _SnapshotRejected as exc:
            raise _impl.ContextPacketSerializationError(
                "context values keys must be plain UTF-8 strings"
            ) from exc
    return source


def _detach_selected_values(
    source: dict[str, Any],
    requested: tuple[str, ...],
) -> dict[str, Any]:
    """Detach selected values while preserving optional non-JSON omissions."""

    detached: dict[str, Any] = {}
    seen: set[int] = set()
    for key in requested:
        raw = dict.get(source, key, _MISSING)
        if raw is _MISSING:
            continue
        trial_seen = set(seen)
        try:
            snapshot = _snapshot_json_value(raw, trial_seen)
        except _SnapshotRejected:
            detached[key] = _NON_JSON
        else:
            detached[key] = snapshot
            seen = trial_seen
    return detached


_unwrapped_build_context_packet = getattr(
    _impl,
    "_context_packet_unwrapped_build_context_packet",
    _impl.build_context_packet,
)
setattr(
    _impl,
    "_context_packet_unwrapped_build_context_packet",
    _unwrapped_build_context_packet,
)
_unwrapped_build_node_context_packet = getattr(
    _impl,
    "_context_packet_unwrapped_build_node_context_packet",
    _impl.build_node_context_packet,
)
setattr(
    _impl,
    "_context_packet_unwrapped_build_node_context_packet",
    _unwrapped_build_node_context_packet,
)


def build_context_packet(
    *,
    node_id: str,
    node_name: str,
    goal_context: str,
    values: Mapping[str, Any],
    context_keys: Sequence[str],
    required_keys: Sequence[str] = (),
    budget_chars: int = _impl.DEFAULT_CONTEXT_BUDGET_CHARS,
    max_packet_chars: int = _impl.DEFAULT_CONTEXT_PACKET_MAX_CHARS,
) -> Any:
    """Build from one detached generation of strict plain-JSON values."""

    requested = _impl._normalize_key_sequence(context_keys, field="context_keys")
    required = _impl._normalize_key_sequence(
        required_keys,
        field="context_required_keys",
    )
    _impl._validate_key_declarations(requested, required)
    requested_set = set(requested)
    unknown_required = [key for key in required if key not in requested_set]
    if unknown_required:
        raise _impl.ContextPacketConfigurationError(
            "required context keys must also appear in context_keys: "
            + ", ".join(unknown_required)
        )

    resolved_budget = _impl._parse_integer_bound(
        budget_chars,
        field="context packet budget_chars",
    )
    if resolved_budget <= 0:
        raise _impl.ContextPacketConfigurationError(
            "context packet budget_chars must be > 0"
        )
    resolved_max_packet = _impl._parse_integer_bound(
        max_packet_chars,
        field="context_packet_max_chars",
    )
    if resolved_max_packet <= 0:
        raise _impl.ContextPacketConfigurationError(
            "context_packet_max_chars must be > 0"
        )
    if resolved_max_packet > _impl.HARD_CONTEXT_PACKET_MAX_CHARS:
        raise _impl.ContextPacketConfigurationError(
            "context_packet_max_chars exceeds framework hard maximum "
            f"({resolved_max_packet} > {_impl.HARD_CONTEXT_PACKET_MAX_CHARS})"
        )

    source_values = _capture_plain_values(values)
    detached_values = _detach_selected_values(source_values, requested)
    return _unwrapped_build_context_packet(
        node_id=node_id,
        node_name=node_name,
        goal_context=goal_context,
        values=detached_values,
        context_keys=requested,
        required_keys=required,
        budget_chars=resolved_budget,
        max_packet_chars=resolved_max_packet,
    )


class _CapturedBuffer:
    __slots__ = ("_values",)

    def __init__(self, values: dict[str, Any]) -> None:
        self._values = values

    def read_all(self) -> dict[str, Any]:
        return dict.copy(self._values)


def build_node_context_packet(
    *,
    node_spec: Any,
    buffer: Any,
    goal_context: str,
) -> Any:
    """Build from one captured outer buffer generation."""

    source_values = _capture_plain_values(buffer.read_all())
    return _unwrapped_build_node_context_packet(
        node_spec=node_spec,
        buffer=_CapturedBuffer(source_values),
        goal_context=goal_context,
    )


# The retained implementation resolves these functions from its module globals
# at call time. Replace those seams, then expose its public/test-facing API.
_impl._authorized_buffer_keys = _authorized_buffer_keys
_impl.build_context_packet = build_context_packet
_impl.build_node_context_packet = build_node_context_packet

for _name in dir(_impl):
    if _name.startswith("__") or _name in {
        "_authorized_buffer_keys",
        "_context_packet_unwrapped_build_context_packet",
        "_context_packet_unwrapped_build_node_context_packet",
    }:
        continue
    globals()[_name] = getattr(_impl, _name)

globals()["_authorized_buffer_keys"] = _authorized_buffer_keys
globals()["build_context_packet"] = build_context_packet
globals()["build_node_context_packet"] = build_node_context_packet
__all__ = [name for name in dir(_impl) if not name.startswith("_")]
