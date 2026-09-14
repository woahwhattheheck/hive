from __future__ import annotations

import unittest
from types import SimpleNamespace

from framework.orchestrator import context_packet
from framework.orchestrator import context_packet_impl
from framework.orchestrator.context_packet import (
    ContextPacketConfigurationError,
    build_node_context_packet,
)


class FakeBuffer:
    def __init__(self, values):
        self.values = dict(values)

    def read_all(self):
        return dict(self.values)


class ContextPacketAuthorityPrefixTests(unittest.TestCase):
    def test_arbitrary_underscore_key_does_not_expand_scoped_read_authority(self):
        spec = SimpleNamespace(
            id="worker",
            name="Worker",
            input_keys=["task"],
            output_keys=["result"],
            context_keys=["_secret"],
        )
        buffer = FakeBuffer({"task": "work", "_secret": {"private": "leak"}})

        with self.assertRaisesRegex(
            ContextPacketConfigurationError,
            "context_keys exceed node buffer read authority: _secret",
        ):
            build_node_context_packet(
                node_spec=spec,
                buffer=buffer,
                goal_context="goal",
            )

    def test_explicit_underscore_input_key_remains_available(self):
        spec = SimpleNamespace(
            id="worker",
            name="Worker",
            input_keys=["task", "_handoff"],
            output_keys=["result"],
            context_keys=["_handoff"],
        )
        packet = build_node_context_packet(
            node_spec=spec,
            buffer=FakeBuffer({"task": "work", "_handoff": {"id": 7}}),
            goal_context="goal",
        )

        self.assertEqual(["_handoff"], [entry.key for entry in packet.entries])

    def test_empty_input_allow_set_preserves_unrestricted_buffer_contract(self):
        spec = SimpleNamespace(
            id="worker",
            name="Worker",
            input_keys=[],
            output_keys=[],
            context_keys=["any_key"],
        )
        packet = build_node_context_packet(
            node_spec=spec,
            buffer=FakeBuffer({"any_key": "visible"}),
            goal_context="goal",
        )

        self.assertEqual(["any_key"], [entry.key for entry in packet.entries])

    def test_retained_implementation_uses_facade_authority_resolver(self):
        self.assertIs(
            context_packet_impl._authorized_buffer_keys,
            context_packet._authorized_buffer_keys,
        )


if __name__ == "__main__":
    unittest.main()
