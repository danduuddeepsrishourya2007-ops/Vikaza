import json
import unittest

from simulation.events import Event


class TestEvent(unittest.TestCase):

    def test_event_creation(self):
        event = Event(
            event_id=1,
            tick=10,
            event_type="HostCompromised",
            actor_id="attacker",
            payload={"host_id": "host-1"},
            visibility_tags=frozenset({"security", "executive"}),
        )

        self.assertEqual(event.event_id, 1)
        self.assertEqual(event.tick, 10)
        self.assertEqual(event.event_type, "HostCompromised")
        self.assertEqual(event.actor_id, "attacker")
        self.assertEqual(event.payload, {"host_id": "host-1"})
        self.assertEqual(
            event.visibility_tags,
            frozenset({"security", "executive"}),
        )

    def test_event_defaults(self):
        event = Event(
            event_id=2,
            tick=0,
            event_type="TickCompleted",
        )

        self.assertIsNone(event.actor_id)
        self.assertEqual(event.payload, {})
        self.assertEqual(event.visibility_tags, frozenset())

    def test_event_to_dict(self):
        event = Event(
            event_id=3,
            tick=5,
            event_type="HostIsolated",
            actor_id="security-1",
            payload={"host_id": "host-2"},
            visibility_tags=frozenset({"security", "admin"}),
        )

        result = event.to_dict()

        self.assertEqual(result["event_id"], 3)
        self.assertEqual(result["tick"], 5)
        self.assertEqual(result["event_type"], "HostIsolated")
        self.assertEqual(result["actor_id"], "security-1")
        self.assertEqual(result["payload"], {"host_id": "host-2"})

        # Must be deterministic rather than relying on set iteration order.
        self.assertEqual(
            result["visibility_tags"],
            ["admin", "security"],
        )

    def test_event_from_dict(self):
        data = {
            "event_id": 4,
            "tick": 7,
            "event_type": "DataExfiltrated",
            "actor_id": "attacker",
            "payload": {
                "store_id": "customer-db",
                "bytes": 1024,
            },
            "visibility_tags": ["attacker", "security"],
        }

        event = Event.from_dict(data)

        self.assertEqual(event.event_id, 4)
        self.assertEqual(event.tick, 7)
        self.assertEqual(event.event_type, "DataExfiltrated")
        self.assertEqual(event.actor_id, "attacker")
        self.assertEqual(
            event.payload,
            {
                "store_id": "customer-db",
                "bytes": 1024,
            },
        )
        self.assertEqual(
            event.visibility_tags,
            frozenset({"attacker", "security"}),
        )

    def test_json_round_trip(self):
        original = Event(
            event_id=5,
            tick=12,
            event_type="ServiceDown",
            actor_id="engine",
            payload={"host_id": "app-1", "service": "api"},
            visibility_tags=frozenset({"security"}),
        )

        encoded = original.to_json()
        restored = Event.from_json(encoded)

        self.assertEqual(restored, original)

    def test_json_is_deterministic(self):
        event = Event(
            event_id=6,
            tick=20,
            event_type="PolicyChanged",
            payload={"policy": "gradual"},
            visibility_tags=frozenset({"executive", "security"}),
        )

        first = event.to_json()
        second = event.to_json()

        self.assertEqual(first, second)

        parsed = json.loads(first)
        self.assertEqual(
            parsed["visibility_tags"],
            ["executive", "security"],
        )

    def test_event_is_frozen(self):
        event = Event(
            event_id=7,
            tick=1,
            event_type="TickCompleted",
        )

        with self.assertRaises(AttributeError):
            event.tick = 2


if __name__ == "__main__":
    unittest.main()