import sys

from framework import cli


def test_configure_paths_does_not_trust_current_working_directory(
    monkeypatch, tmp_path
):
    attacker_core = tmp_path / "core"
    attacker_core.mkdir()
    fake_install = tmp_path / "venv" / "site-packages" / "framework" / "cli.py"

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "__file__", str(fake_install))
    monkeypatch.setattr(sys, "path", [])

    cli._configure_paths()

    assert str(attacker_core) not in sys.path
    assert sys.path == []


def test_configure_paths_adds_source_core_from_module_location(monkeypatch, tmp_path):
    framework_dir = tmp_path / "project" / "core" / "framework"
    framework_dir.mkdir(parents=True)
    fake_cli = framework_dir / "cli.py"
    fake_cli.write_text("", encoding="utf-8")

    monkeypatch.setattr(cli, "__file__", str(fake_cli))
    monkeypatch.setattr(sys, "path", [])

    cli._configure_paths()

    assert sys.path == [str(framework_dir.parent)]
