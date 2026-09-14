"""Public context-packet API with exact shared-buffer read authority.

The reviewed implementation is retained byte-for-byte in
``context_packet_impl``.  This facade narrows the authority resolver to the
actual ``DataBuffer`` contract: explicit ``input_keys`` are the complete read
allow-set, while an empty allow-set preserves the existing unrestricted view.
A leading underscore is only a name and never creates authority.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from . import context_packet_impl as _impl


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


# ``build_node_context_packet`` is defined in the retained implementation and
# resolves this helper from that module's globals at call time.  Replace only
# that seam, then expose the original public and test-facing API unchanged.
_impl._authorized_buffer_keys = _authorized_buffer_keys

for _name in dir(_impl):
    if _name.startswith("__") or _name == "_authorized_buffer_keys":
        continue
    globals()[_name] = getattr(_impl, _name)

globals()["_authorized_buffer_keys"] = _authorized_buffer_keys
__all__ = [name for name in dir(_impl) if not name.startswith("_")]
