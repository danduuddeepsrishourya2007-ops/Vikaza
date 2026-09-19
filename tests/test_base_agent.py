import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from simulation.agents.base_agent import BaseAgent
from simulation.events import Event


class TestBaseAgent(unittest.TestCase):
    """Test cases for the BaseAgent class."""

    def setUp(self):
        self.agent = BaseAgent(
            agent_id="test_agent",
            role="security_engineer",
            goals=["protect the network"],
            resources={"analyst_hours": 10},
            permissions={"scan", "isolate"},
        )

    def test_initialization(self):
        """Test BaseAgent initialization."""
        self.assertEqual(self.agent.agent_id, "test_agent")
        self.assertEqual(self.agent.role, "security_engineer")
        self.assertEqual(self.agent.goals, ["protect the network"])
        self.assertEqual(
            self.agent.resources,
            {"analyst_hours": 10},
        )
        self.assertEqual(
            self.agent.permissions,
            {"scan", "isolate"},
        )

    def test_agent_state_initialization(self):
        """Test initial agent state."""
        self.assertIsNotNone(self.agent.state)
        self.assertEqual(self.agent.state.health, 1.0)
        self.assertEqual(self.agent.state.energy, 1.0)
        self.assertEqual(self.agent.state.status, "active")

    def test_memory_initialization(self):
        """Test agent memory initialization."""
        self.assertIsNotNone(self.agent.memory)
        self.assertEqual(len(self.agent.memory.short_term), 0)
        self.assertEqual(len(self.agent.memory.long_term), 0)

    def test_receive_event(self):
        """Test receiving and storing an authoritative event."""
        event = Event(
            event_id=1,
            tick=5,
            event_type="HostCompromised",
            actor_id="attacker",
            payload={"host_id": "host-1"},
            visibility_tags=frozenset({"security"}),
        )

        self.agent.receive_event(event)

        self.assertEqual(len(self.agent.memory.short_term), 1)

        memory_entry = self.agent.memory.short_term[0]

        self.assertEqual(memory_entry["type"], "event")
        self.assertEqual(
            memory_entry["event"],
            {
                "event_id": 1,
                "tick": 5,
                "event_type": "HostCompromised",
                "actor_id": "attacker",
                "payload": {"host_id": "host-1"},
                "visibility_tags": ["security"],
            },
        )
        self.assertEqual(memory_entry["world_time"], 5)

    def test_perceive(self):
        """Test perceive using a mock world."""

        class MockWorld:
            def get_state(self):
                return {
                    "tick": 0,
                    "status": "active",
                }

        result = self.agent.perceive(MockWorld())

        self.assertIsNotNone(result)

    def test_act(self):
        """Test act with the existing BaseAgent action API."""
        result = self.agent.act(None, None)

        self.assertIsNone(result)

    def test_step(self):
        """Test step with the existing BaseAgent API."""
        result = self.agent.step(None)

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()