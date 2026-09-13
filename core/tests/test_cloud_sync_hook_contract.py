"""Contract tests for optional cloud-sync integration wiring."""

from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[1]
FRAMEWORK_ROOT = CORE_ROOT / "framework"


def test_cloud_sync_hook_is_never_present_without_backend() -> None:
    """Do not advertise a fire-and-forget hook without its implementation."""
    hook = FRAMEWORK_ROOT / "cloud_sync_hooks.py"
    backend = FRAMEWORK_ROOT / "cloud_sync.py"

    assert not hook.exists() or backend.exists(), (
        "cloud_sync_hooks.py requires framework/cloud_sync.py; "
        "restore the backend and real call sites together"
    )
