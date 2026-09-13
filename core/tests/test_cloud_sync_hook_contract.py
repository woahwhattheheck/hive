"""Contract tests for optional cloud-sync integration wiring."""

from pathlib import Path

from framework.cloud_sync_hooks import schedule_push

CORE_ROOT = Path(__file__).resolve().parents[1]
FRAMEWORK_ROOT = CORE_ROOT / "framework"


def test_cloud_sync_hook_is_explicit_noop_without_backend() -> None:
    """Keep route imports safe without pretending an unavailable backend exists."""
    backend = FRAMEWORK_ROOT / "cloud_sync.py"
    hook = FRAMEWORK_ROOT / "cloud_sync_hooks.py"

    assert not backend.exists(), "update this contract when a real cloud-sync backend lands"
    assert "framework.cloud_sync" not in hook.read_text(encoding="utf-8")
    assert schedule_push("skill_override", "queen:test") is None
