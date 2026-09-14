from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path


class ContextPacketDirectImportTests(unittest.TestCase):
    def test_direct_implementation_import_uses_authoritative_resolver(self) -> None:
        core_root = Path(__file__).resolve().parents[1]
        script = textwrap.dedent(
            """
            from types import SimpleNamespace

            from framework.orchestrator import context_packet_impl


            class FakeBuffer:
                def read_all(self):
                    return {"task": "work", "_secret": {"private": "must-not-leak"}}


            spec = SimpleNamespace(
                id="worker",
                name="Worker",
                input_keys=["task"],
                output_keys=["result"],
                context_keys=["_secret"],
            )
            try:
                context_packet_impl.build_node_context_packet(
                    node_spec=spec,
                    buffer=FakeBuffer(),
                    goal_context="goal",
                )
            except context_packet_impl.ContextPacketConfigurationError as exc:
                assert "_secret" in str(exc), exc
                assert "must-not-leak" not in str(exc), exc
            else:
                raise AssertionError(
                    "direct implementation import expanded authority to an undeclared underscore key"
                )
            """
        )
        env = os.environ.copy()
        inherited = env.get("PYTHONPATH")
        env["PYTHONPATH"] = (
            os.pathsep.join((str(core_root), inherited)) if inherited else str(core_root)
        )
        completed = subprocess.run(
            [sys.executable, "-c", script],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
            env=env,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )


if __name__ == "__main__":
    unittest.main()
