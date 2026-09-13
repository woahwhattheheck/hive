"""Compatibility hooks for the optional cloud-sync integration.

The cloud-sync backend is not part of this repository, but route modules still
call :func:`schedule_push` after successful local mutations.  Keep that public
hook importable and explicitly side-effect free until a real backend is added.
This preserves local route behavior without pretending remote propagation
exists.
"""

from __future__ import annotations


def schedule_push(kind: str, key: str) -> None:
    """Accept a push hint without performing unavailable cloud synchronization."""
    del kind, key
