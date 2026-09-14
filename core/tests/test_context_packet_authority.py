from __future__ import annotations

import json
import unittest
from types import SimpleNamespace

from framework.orchestrator.context_packet import (
    HARD_CONTEXT_PACKET_MAX_CHARS,
    ContextPacketBudgetError,
    ContextPacketConfigurationError,
    SensitiveContextKeyError,
    build_context_packet,
    build_node_context_packet,
    render_context_packet,
)


class FakeBuffer:
    def __init__(self, values):
        self.values = dict(values)

    def read_all(self):
        return dict(self.values)


class ContextPacketAuthorityTests(unittest.TestCase):
    def test_scoped_node_cannot_expand_read_authority_with_context_keys(self):
        spec = SimpleNamespace(
            id="worker",
            name="Worker",
            input_keys=["allowed"],
            output_keys=["result"],
            context_keys=["allowed", "private_record"],
        )
        with self.assertRaises(ContextPacketConfigurationError) as caught:
            build_node_context_packet(
                node_spec=spec,
                buffer=FakeBuffer({"allowed": "ok", "private_record": "must-not-leak"}),
                goal_context="goal",
            )
        self.assertIn("private_record", str(caught.exception))
        self.assertNotIn("must-not-leak", str(caught.exception))

    def test_output_only_node_preserves_existing_unrestricted_read_semantics(self):
        spec = SimpleNamespace(
            id="worker",
            name="Worker",
            input_keys=[],
            output_keys=["result"],
            context_keys=["global_record"],
        )
        packet = build_node_context_packet(
            node_spec=spec,
            buffer=FakeBuffer({"global_record": "visible-under-existing-buffer-semantics"}),
            goal_context="goal",
        )
        self.assertEqual(["global_record"], [entry.key for entry in packet.entries])

    def test_existing_framework_underscore_key_remains_in_effective_scope(self):
        spec = SimpleNamespace(
            id="worker",
            name="Worker",
            input_keys=["task"],
            output_keys=["result"],
            context_keys=["_handoff"],
        )
        packet = build_node_context_packet(
            node_spec=spec,
            buffer=FakeBuffer({"task": "work", "_handoff": {"id": 7}}),
            goal_context="goal",
        )
        self.assertEqual(["_handoff"], [entry.key for entry in packet.entries])

    def test_camel_case_top_level_secret_is_filtered_before_serialization(self):
        packet = build_context_packet(
            node_id="worker",
            node_name="Worker",
            goal_context="goal",
            values={"clientSecret": object()},
            context_keys=["clientSecret"],
        )
        self.assertEqual((), packet.entries)
        self.assertEqual("sensitive_key", packet.omissions[0].reason)

    def test_camel_case_nested_secret_is_filtered_before_serialization(self):
        packet = build_context_packet(
            node_id="worker",
            node_name="Worker",
            goal_context="goal",
            values={"config": {"auth": {"accessToken": object()}}},
            context_keys=["config"],
        )
        self.assertEqual((), packet.entries)
        self.assertEqual("sensitive_key", packet.omissions[0].reason)

    def test_nested_required_credential_field_fails_closed(self):
        with self.assertRaises(SensitiveContextKeyError):
            build_context_packet(
                node_id="worker",
                node_name="Worker",
                goal_context="goal",
                values={"integration_config": {"authorization": "Bearer x"}},
                context_keys=["integration_config"],
                required_keys=["integration_config"],
            )

    def test_metadata_only_growth_cannot_escape_complete_packet_bound(self):
        with self.assertRaises(ContextPacketBudgetError):
            build_context_packet(
                node_id="worker",
                node_name="Worker",
                goal_context="goal",
                values={},
                context_keys=[f"missing_{index}" for index in range(60)],
                budget_chars=4096,
                max_packet_chars=512,
            )

    def test_structured_and_rendered_forms_stay_within_declared_ceiling(self):
        packet = build_context_packet(
            node_id="worker",
            node_name="Worker",
            goal_context="goal",
            values={"brief": {"a": 1}, "source": "https://example.test"},
            context_keys=["brief", "source"],
            required_keys=["brief"],
            max_packet_chars=4096,
        )
        structured = json.dumps(
            packet.to_dict(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        self.assertLessEqual(len(structured), packet.max_packet_chars)
        self.assertLessEqual(len(render_context_packet(packet)), packet.max_packet_chars)

    def test_configured_ceiling_cannot_exceed_framework_hard_maximum(self):
        with self.assertRaises(ContextPacketConfigurationError):
            build_context_packet(
                node_id="worker",
                node_name="Worker",
                goal_context="goal",
                values={},
                context_keys=[],
                max_packet_chars=HARD_CONTEXT_PACKET_MAX_CHARS + 1,
            )

    def test_context_key_count_is_bounded_before_packet_metadata_build(self):
        with self.assertRaises(ContextPacketConfigurationError):
            build_context_packet(
                node_id="worker",
                node_name="Worker",
                goal_context="goal",
                values={},
                context_keys=[f"k{index}" for index in range(129)],
            )

    def test_context_key_declaration_chars_have_framework_hard_ceiling(self):
        with self.assertRaises(ContextPacketConfigurationError):
            build_context_packet(
                node_id="worker",
                node_name="Worker",
                goal_context="goal",
                values={},
                context_keys=[f"k{index}_" + ("x" * 9000) for index in range(4)],
            )

    def test_default_complete_ceiling_rejects_pathological_repeated_key_metadata(self):
        key = "k" * 8000
        with self.assertRaises(ContextPacketBudgetError):
            build_context_packet(
                node_id="worker",
                node_name="Worker",
                goal_context="goal",
                values={key: "tiny"},
                context_keys=[key],
                budget_chars=700,
            )


if __name__ == "__main__":
    unittest.main()
