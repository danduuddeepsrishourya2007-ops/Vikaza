"""
Unit tests for the Events class in NEXUS Core.
"""

import unittest
import json
from simulation.events import Event


class TestEvent(unittest.TestCase):
    """Test cases for the Event class."""

    def test_event_creation(self):
        """Test creating an event with basic parameters."""
        event = Event(timestamp=10.5, event_type="test_event", data={"key": "value"})

        self.assertEqual(event.timestamp, 10.5)
        self.assertEqual(event.event_type, "test_event")
        self.assertEqual(event.data, {"key": "value"})

    def test_event_creation_with_none_data(self):
        """Test creating an event with None data (should become empty dict)."""
        event = Event(timestamp=5.0, event_type="test_event", data=None)

        self.assertEqual(event.timestamp, 5.0)
        self.assertEqual(event.event_type, "test_event")
        self.assertEqual(event.data, {})

    def test_event_to_dict(self):
        """Test converting event to dictionary."""
        original_data = {"entity_id": "test", "value": 42}
        event = Event(timestamp=15.0, event_type="entity_update", data=original_data)

        event_dict = event.to_dict()

        self.assertEqual(event_dict["timestamp"], 15.0)
        self.assertEqual(event_dict["event_type"], "entity_update")
        self.assertEqual(event_dict["data"], original_data)

    def test_event_from_dict(self):
        """Test creating event from dictionary."""
        event_data = {
            "timestamp": 20.0,
            "event_type": "resource_add",
            "data": {"resource": "gold", "amount": 100}
        }

        event = Event.from_dict(event_data)

        self.assertEqual(event.timestamp, 20.0)
        self.assertEqual(event.event_type, "resource_add")
        self.assertEqual(event.data, {"resource": "gold", "amount": 100})

    def test_event_to_json(self):
        """Test converting event to JSON string."""
        event = Event(timestamp=7.5, event_type="test_json", data={"test": True})

        json_str = event.to_json()
        parsed = json.loads(json_str)

        self.assertEqual(parsed["timestamp"], 7.5)
        self.assertEqual(parsed["event_type"], "test_json")
        self.assertEqual(parsed["data"], {"test": True})

    def test_event_from_json(self):
        """Test creating event from JSON string."""
        json_str = '{"timestamp": 12.0, "event_type": "test_from_json", "data": {"number": 42}}'

        event = Event.from_json(json_str)

        self.assertEqual(event.timestamp, 12.0)
        self.assertEqual(event.event_type, "test_from_json")
        self.assertEqual(event.data, {"number": 42})

    def test_event_string_representation(self):
        """Test string representation of event."""
        event = Event(timestamp=3.14, event_type="pi_event", data={"approx": True})

        str_repr = str(event)
        self.assertIn("3.14", str_repr)
        self.assertIn("pi_event", str_repr)
        self.assertIn("approx", str_repr)


if __name__ == '__main__':
    unittest.main()