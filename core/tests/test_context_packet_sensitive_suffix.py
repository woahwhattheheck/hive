from __future__ import annotations

import unittest

from framework.orchestrator.context_packet import (
    SensitiveContextKeyError,
    build_context_packet,
)


class ContextPacketSensitiveSuffixTests(unittest.TestCase):
    def packet(self, *, values, context_keys, required_keys=()):
        return build_context_packet(
            node_id="worker",
            node_name="Worker",
            goal_context="Preserve the context security boundary",
            values=values,
            context_keys=context_keys,
            required_keys=required_keys,
            budget_chars=10_000,
        )

    def test_numbered_sensitive_top_level_keys_are_fenced(self):
        for key in (
            "apiKey2",
            "accessToken2",
            "password2",
            "clientSecret2",
            "refreshToken3",
            "privateKey4",
        ):
            with self.subTest(key=key):
                packet = self.packet(
                    values={key: "must-not-cross-boundary"},
                    context_keys=[key],
                )
                self.assertEqual(packet.entries, ())
                self.assertEqual(packet.omissions[0].reason, "sensitive_key")
                self.assertNotIn("must-not-cross-boundary", str(packet.to_dict()))

    def test_numbered_sensitive_nested_key_is_fenced_whole(self):
        packet = self.packet(
            values={
                "config": {
                    "provider": {
                        "accessToken2": "nested-secret",
                    },
                    "safe": True,
                }
            },
            context_keys=["config"],
        )
        self.assertEqual(packet.entries, ())
        self.assertEqual(packet.omissions[0].reason, "sensitive_key")
        self.assertNotIn("nested-secret", str(packet.to_dict()))

    def test_numbered_sensitive_required_keys_fail_closed(self):
        with self.assertRaises(SensitiveContextKeyError):
            self.packet(
                values={"apiKey2": "required-secret"},
                context_keys=["apiKey2"],
                required_keys=["apiKey2"],
            )

        with self.assertRaises(SensitiveContextKeyError):
            self.packet(
                values={"config": {"password2": "required-nested-secret"}},
                context_keys=["config"],
                required_keys=["config"],
            )

    def test_numeric_suffixes_on_safe_names_do_not_false_positive(self):
        safe = {
            "phase2": "alpha",
            "model2d": "beta",
            "hockeyScore3": 4,
            "monkey2": "banana",
        }
        packet = self.packet(values={"config": safe}, context_keys=["config"], required_keys=["config"])
        self.assertEqual([entry.key for entry in packet.entries], ["config"])


if __name__ == "__main__":
    unittest.main()
