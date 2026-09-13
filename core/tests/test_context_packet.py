from __future__ import annotations

import math
import unittest
from types import SimpleNamespace

from framework.orchestrator.context_packet import (
    ContextPacketBudgetError,
    ContextPacketConfigurationError,
    ContextPacketSerializationError,
    MissingRequiredContextError,
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


class ContextPacketTests(unittest.TestCase):
    def packet(self, **overrides):
        kwargs = {
            "node_id": "researcher",
            "node_name": "Researcher",
            "goal_context": "Ship a sourced answer",
            "values": {"brief": {"b": 2, "a": 1}, "source": "https://example.test"},
            "context_keys": ["brief", "source"],
            "required_keys": ["brief"],
            "budget_chars": 10_000,
        }
        kwargs.update(overrides)
        return build_context_packet(**kwargs)

    def test_digest_is_deterministic_across_mapping_order(self):
        first = self.packet(values={"brief": {"b": 2, "a": 1}, "source": "https://example.test"})
        second = self.packet(values={"source": "https://example.test", "brief": {"a": 1, "b": 2}})
        self.assertEqual(first.packet_sha256, second.packet_sha256)
        self.assertEqual(first.entries[0].canonical_json, '{"a":1,"b":2}')

    def test_goal_is_bound_into_packet_digest(self):
        first = self.packet(goal_context="Goal A")
        second = self.packet(goal_context="Goal B")
        self.assertNotEqual(first.goal_sha256, second.goal_sha256)
        self.assertNotEqual(first.packet_sha256, second.packet_sha256)

    def test_context_key_order_controls_optional_admission_priority(self):
        packet = self.packet(
            values={"a": "1234", "b": "5678"},
            context_keys=["b", "a"],
            required_keys=[],
            budget_chars=6,
        )
        self.assertEqual([entry.key for entry in packet.entries], ["b"])
        self.assertEqual(packet.omissions[0].key, "a")
        self.assertEqual(packet.omissions[0].reason, "budget")

    def test_required_keys_are_admitted_before_optional_keys(self):
        packet = self.packet(
            values={"optional": "123456", "required": "ok"},
            context_keys=["optional", "required"],
            required_keys=["required"],
            budget_chars=6,
        )
        self.assertEqual([entry.key for entry in packet.entries], ["required"])
        self.assertEqual(packet.omissions[0].key, "optional")

    def test_missing_required_context_fails_closed(self):
        with self.assertRaises(MissingRequiredContextError):
            self.packet(values={}, context_keys=["brief"], required_keys=["brief"])

    def test_required_key_must_be_declared(self):
        with self.assertRaises(ContextPacketConfigurationError):
            self.packet(context_keys=["brief"], required_keys=["other"])

    def test_required_entry_that_cannot_fit_fails_closed(self):
        with self.assertRaises(ContextPacketBudgetError):
            self.packet(values={"brief": "too large"}, context_keys=["brief"], required_keys=["brief"], budget_chars=3)

    def test_optional_entry_is_omitted_whole_not_truncated(self):
        factual_sentence = "full factual sentence that must not be sliced"
        packet = self.packet(
            values={"large": factual_sentence},
            context_keys=["large"],
            required_keys=[],
            budget_chars=4,
        )
        rendered = render_context_packet(packet)
        self.assertEqual(packet.entries, ())
        self.assertEqual(packet.omissions[0].reason, "budget")
        self.assertNotIn(factual_sentence, rendered)
        self.assertIsNotNone(packet.omissions[0].sha256)

    def test_sensitive_optional_key_is_never_emitted(self):
        packet = self.packet(
            values={"access_token": "super-secret-token", "brief": "safe"},
            context_keys=["access_token", "brief"],
            required_keys=[],
        )
        rendered = render_context_packet(packet)
        self.assertEqual([entry.key for entry in packet.entries], ["brief"])
        self.assertEqual(packet.omissions[0].reason, "sensitive_key")
        self.assertNotIn("super-secret-token", rendered)
        self.assertNotIn("super-secret-token", str(packet.to_dict()))

    def test_sensitive_required_key_fails_closed(self):
        with self.assertRaises(SensitiveContextKeyError):
            self.packet(values={"api_key": "x"}, context_keys=["api_key"], required_keys=["api_key"])

    def test_non_json_optional_value_is_omitted(self):
        packet = self.packet(values={"obj": object()}, context_keys=["obj"], required_keys=[])
        self.assertEqual(packet.entries, ())
        self.assertEqual(packet.omissions[0].reason, "non_json")

    def test_non_json_required_value_fails_closed(self):
        with self.assertRaises(ContextPacketSerializationError):
            self.packet(values={"obj": object()}, context_keys=["obj"], required_keys=["obj"])

    def test_non_finite_float_is_not_canonical_json(self):
        for value in (math.nan, math.inf, -math.inf):
            with self.assertRaises(ContextPacketSerializationError):
                self.packet(values={"n": value}, context_keys=["n"], required_keys=["n"])

    def test_duplicate_keys_are_deduplicated_preserving_priority(self):
        packet = self.packet(
            values={"a": 1, "b": 2},
            context_keys=["a", "b", "a"],
            required_keys=[],
        )
        self.assertEqual(packet.requested_keys, ("a", "b"))
        self.assertEqual([entry.key for entry in packet.entries], ["a", "b"])

    def test_node_helper_is_opt_in(self):
        spec = SimpleNamespace(id="worker", name="Worker")
        self.assertIsNone(build_node_context_packet(node_spec=spec, buffer=FakeBuffer({"a": 1}), goal_context="goal"))

    def test_node_helper_reads_extra_fields(self):
        spec = SimpleNamespace(
            id="worker",
            name="Worker",
            context_keys=["must", "nice"],
            context_required_keys=["must"],
            context_char_budget="50",
        )
        packet = build_node_context_packet(
            node_spec=spec,
            buffer=FakeBuffer({"must": {"x": 1}, "nice": "y"}),
            goal_context="goal",
        )
        self.assertIsNotNone(packet)
        assert packet is not None
        self.assertEqual(packet.required_keys, ("must",))
        self.assertEqual([entry.key for entry in packet.entries], ["must", "nice"])

    def test_render_includes_integrity_and_omission_semantics(self):
        packet = self.packet(values={"brief": {"a": 1}}, context_keys=["brief", "later"], required_keys=["brief"])
        rendered = render_context_packet(packet)
        self.assertIn(packet.packet_sha256, rendered)
        self.assertIn(packet.goal_sha256, rendered)
        self.assertIn("omission hashes prove identity, not content", rendered)
        self.assertIn("later [reason=missing]", rendered)


if __name__ == "__main__":
    unittest.main()
