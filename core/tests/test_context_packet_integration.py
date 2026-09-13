from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from framework.orchestrator.context import build_node_context_from_graph_context
from framework.orchestrator.context_packet import MissingRequiredContextError


class FakeBuffer:
    def __init__(self, values):
        self.values = dict(values)

    def read_all(self):
        return dict(self.values)

    def read(self, key):
        return self.values.get(key)


class FakeGoal:
    def __init__(self, text="Ship the work"):
        self.text = text

    def to_prompt_context(self):
        return self.text


class ContextPacketIntegrationTests(unittest.TestCase):
    def graph_context(self, values):
        return SimpleNamespace(
            is_continuous=False,
            cumulative_tools=[],
            cumulative_tool_names=set(),
            cumulative_output_keys=[],
            continuous_conversation=None,
            graph=SimpleNamespace(max_tokens=4096, identity_prompt=""),
            buffer=FakeBuffer(values),
            goal=FakeGoal(),
            runtime=object(),
            llm=object(),
            tools=[],
            runtime_logger=None,
            accounts_prompt="",
            accounts_data=None,
            tool_provider_map=None,
            execution_id="exec-1",
            run_id="run-1",
            stream_id="worker-stream",
            dynamic_tools_provider=None,
            dynamic_prompt_provider=None,
            dynamic_memory_provider=None,
            iteration_metadata_provider=None,
            skills_catalog_prompt="",
            protocols_prompt="",
            skill_dirs=[],
        )

    def node_spec(self, **overrides):
        values = {
            "id": "writer",
            "name": "Writer",
            "tool_access_policy": "explicit",
            "tools": [],
            "input_keys": ["task"],
            "output_keys": ["draft"],
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    def capture_build(self, gc, spec, **kwargs):
        with patch("framework.orchestrator.context.build_node_context", side_effect=lambda **payload: payload):
            return build_node_context_from_graph_context(gc, node_spec=spec, **kwargs)

    def test_opt_in_packet_is_injected_into_input_and_narrative(self):
        gc = self.graph_context({"task": "write", "buyer_requirements": {"format": "PDF"}})
        spec = self.node_spec(
            context_keys=["buyer_requirements"],
            context_required_keys=["buyer_requirements"],
            context_char_budget=1000,
        )

        built = self.capture_build(gc, spec)

        self.assertEqual(built["input_data"]["task"], "write")
        packet = built["input_data"]["_context_packet"]
        self.assertEqual(packet["node_id"], "writer")
        self.assertEqual(packet["entries"][0]["key"], "buyer_requirements")
        self.assertIn("Context Packet (bounded handoff)", built["narrative"])
        self.assertFalse(built["derive_input_data_from_buffer"])

    def test_packet_prepends_without_destroying_existing_narrative(self):
        gc = self.graph_context({"brief": "bounded"})
        spec = self.node_spec(context_keys=["brief"])

        built = self.capture_build(gc, spec, narrative="existing execution narrative")

        self.assertTrue(built["narrative"].startswith("--- Context Packet"))
        self.assertTrue(built["narrative"].endswith("existing execution narrative"))

    def test_no_context_keys_preserves_legacy_derivation_path(self):
        gc = self.graph_context({"task": "write"})
        spec = self.node_spec()

        built = self.capture_build(gc, spec)

        self.assertIsNone(built["input_data"])
        self.assertTrue(built["derive_input_data_from_buffer"])
        self.assertEqual(built["narrative"], "")

    def test_missing_required_context_aborts_before_node_build(self):
        gc = self.graph_context({"task": "write"})
        spec = self.node_spec(
            context_keys=["source_ledger"],
            context_required_keys=["source_ledger"],
        )

        with patch("framework.orchestrator.context.build_node_context") as mocked:
            with self.assertRaises(MissingRequiredContextError):
                build_node_context_from_graph_context(gc, node_spec=spec)
            mocked.assert_not_called()


if __name__ == "__main__":
    unittest.main()
