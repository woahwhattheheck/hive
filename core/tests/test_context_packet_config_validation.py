from __future__ import annotations

import unittest
from types import SimpleNamespace

from framework.orchestrator.context_packet import (
    ContextPacketConfigurationError,
    build_context_packet,
    build_node_context_packet,
)


class FakeBuffer:
    def __init__(self, values):
        self.values = dict(values)

    def read_all(self):
        return dict(self.values)


def build_packet(**overrides):
    arguments = {
        "node_id": "worker",
        "node_name": "Worker",
        "goal_context": "goal",
        "values": {"brief": {"ok": True}},
        "context_keys": ["brief"],
        "required_keys": ["brief"],
        "budget_chars": 2_000,
        "max_packet_chars": 4_096,
    }
    arguments.update(overrides)
    return build_context_packet(**arguments)


class ContextPacketConfigValidationTests(unittest.TestCase):
    def test_public_builder_rejects_scalar_context_keys(self):
        with self.assertRaisesRegex(ContextPacketConfigurationError, "sequence of strings"):
            build_packet(context_keys="brief")

    def test_node_helper_rejects_scalar_context_keys(self):
        spec = SimpleNamespace(id="worker", name="Worker", context_keys="brief")
        with self.assertRaisesRegex(ContextPacketConfigurationError, "sequence of strings"):
            build_node_context_packet(
                node_spec=spec,
                buffer=FakeBuffer({"brief": {"ok": True}}),
                goal_context="goal",
            )

    def test_non_string_key_is_rejected_without_echoing_value(self):
        marker = {"private": "do-not-echo"}
        with self.assertRaises(ContextPacketConfigurationError) as caught:
            build_packet(context_keys=["brief", marker])
        message = str(caught.exception)
        self.assertIn("context_keys[1]", message)
        self.assertNotIn("do-not-echo", message)

    def test_scalar_required_keys_are_rejected(self):
        with self.assertRaisesRegex(ContextPacketConfigurationError, "sequence of strings"):
            build_packet(required_keys="brief")

    def test_bool_and_float_render_budget_are_rejected(self):
        for value in (True, False, 1_000.5):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ContextPacketConfigurationError, "must be an integer"):
                    build_packet(budget_chars=value)

    def test_bool_and_float_packet_ceiling_are_rejected(self):
        for value in (True, False, 4_096.5):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ContextPacketConfigurationError, "must be an integer"):
                    build_packet(max_packet_chars=value)

    def test_digit_strings_remain_supported_by_node_helper(self):
        spec = SimpleNamespace(
            id="worker",
            name="Worker",
            input_keys=[],
            context_keys=["brief"],
            context_required_keys=["brief"],
            context_char_budget="2000",
            context_packet_max_chars="4096",
        )
        packet = build_node_context_packet(
            node_spec=spec,
            buffer=FakeBuffer({"brief": {"ok": True}}),
            goal_context="goal",
        )
        self.assertEqual(packet.budget_chars, 2_000)
        self.assertEqual(packet.max_packet_chars, 4_096)

    def test_clean_tuple_and_list_declarations_still_work(self):
        packet = build_packet(
            context_keys=("brief",),
            required_keys=["brief"],
        )
        self.assertEqual(packet.requested_keys, ("brief",))
        self.assertEqual(packet.required_keys, ("brief",))


if __name__ == "__main__":
    unittest.main()
