from __future__ import annotations

import unittest

from framework.orchestrator import context_packet_impl
from framework.orchestrator.context_packet import (
    ContextPacketSerializationError,
    build_context_packet,
    build_node_context_packet,
)


class TwoGenerationDict(dict):
    def __init__(self) -> None:
        super().__init__({"api_key": "SECRET"})
        self.reads = 0

    def items(self):
        self.reads += 1
        if self.reads == 1:
            return [("safe", "ok")]
        return [("api_key", "SECRET")]


class StatefulValues(dict):
    def __init__(self) -> None:
        super().__init__({"brief": {"safe": "ok"}})
        self.reads = 0

    def __getitem__(self, key):
        self.reads += 1
        return super().__getitem__(key)

    def get(self, key, default=None):
        self.reads += 1
        return super().get(key, default)

    def items(self):
        self.reads += 1
        return super().items()


class StatefulBuffer:
    def __init__(self) -> None:
        self.calls = 0
        self.values = StatefulValues()

    def read_all(self):
        self.calls += 1
        return self.values


class ContextPacketSnapshotTests(unittest.TestCase):
    def packet(self, *, values, required=True):
        return build_context_packet(
            node_id="worker",
            node_name="Worker",
            goal_context="goal",
            values=values,
            context_keys=["brief"],
            required_keys=["brief"] if required else [],
        )

    def test_stateful_dict_cannot_split_scanner_from_serializer(self) -> None:
        value = TwoGenerationDict()
        with self.assertRaises(ContextPacketSerializationError) as caught:
            self.packet(values={"brief": value})
        self.assertEqual(value.reads, 0)
        self.assertNotIn("SECRET", str(caught.exception))

    def test_optional_custom_container_is_omitted_without_access(self) -> None:
        value = TwoGenerationDict()
        packet = self.packet(values={"brief": value}, required=False)
        self.assertEqual(packet.entries, ())
        self.assertEqual(packet.omissions[0].reason, "non_json")
        self.assertEqual(value.reads, 0)

    def test_outer_mapping_subclass_is_rejected_before_access(self) -> None:
        values = StatefulValues()
        with self.assertRaises(ContextPacketSerializationError):
            self.packet(values=values)
        self.assertEqual(values.reads, 0)

    def test_node_helper_rejects_outer_mapping_subclass_before_access(self) -> None:
        buffer = StatefulBuffer()
        spec = type(
            "Spec",
            (),
            {
                "id": "worker",
                "name": "Worker",
                "input_keys": [],
                "context_keys": ["brief"],
            },
        )()
        with self.assertRaises(ContextPacketSerializationError):
            context_packet_impl.build_node_context_packet(
                node_spec=spec,
                buffer=buffer,
                goal_context="goal",
            )
        self.assertEqual(buffer.calls, 1)
        self.assertEqual(buffer.values.reads, 0)

    def test_shared_mutable_alias_is_rejected(self) -> None:
        shared = {"safe": "ok"}
        with self.assertRaises(ContextPacketSerializationError):
            build_context_packet(
                node_id="worker",
                node_name="Worker",
                goal_context="goal",
                values={"first": shared, "second": shared},
                context_keys=["first", "second"],
                required_keys=["first", "second"],
            )

    def test_cyclic_container_is_rejected(self) -> None:
        cycle = []
        cycle.append(cycle)
        with self.assertRaises(ContextPacketSerializationError):
            self.packet(values={"brief": cycle})

    def test_clean_plain_json_graph_is_detached_and_admitted(self) -> None:
        source = {"safe": (1, 2, True, None)}
        packet = self.packet(values={"brief": source})
        source["safe"] = ("changed",)
        self.assertEqual(packet.entries[0].value, {"safe": [1, 2, True, None]})

    def test_direct_implementation_surface_uses_snapshot_wrapper(self) -> None:
        self.assertIs(context_packet_impl.build_context_packet, build_context_packet)
        self.assertIs(
            context_packet_impl.build_node_context_packet,
            build_node_context_packet,
        )


if __name__ == "__main__":
    unittest.main()
