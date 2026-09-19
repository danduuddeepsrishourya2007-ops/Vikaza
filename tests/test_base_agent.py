"""
Unit tests for the BaseAgent class in NEXUS Core.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import unittest
from simulation.agents.base_agent import BaseAgent, AgentState, AgentMemory
from simulation.world import World
from simulation.events import Event


class TestBaseAgent(unittest.TestCase):
    """Test cases for the BaseAgent class."""

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.agent = BaseAgent(agent_id="test_agent", role="tester",
                              goals=["test_goal"], resources={"test_resource": 100})

    def test_agent_initialization(self):
        """Test that the agent initializes correctly."""
        self.assertIsNotNone(self.agent)
        self.assertEqual(self.agent.agent_id, "test_agent")
        self.assertEqual(self.agent.role, "tester")
        self.assertEqual(self.agent.goals, ["test_goal"])
        self.assertEqual(self.agent.resources, {"test_resource": 100})
        self.assertIsInstance(self.agent.state, AgentState)
        self.assertIsInstance(self.agent.memory, AgentMemory)

    def test_agent_initialization_without_id(self):
        """Test that agent gets auto-generated ID when none provided."""
        agent = BaseAgent(role="tester")
        self.assertIsNotNone(agent.agent_id)
        self.assertEqual(agent.role, "tester")

    def test_agent_default_state(self):
        """Test that agent gets default state values."""
        # Agent with zero/negative values should get defaults
        agent = BaseAgent()
        self.assertEqual(agent.state.health, 1.0)
        self.assertEqual(agent.state.energy, 1.0)
        self.assertEqual(agent.state.status, "active")

    def test_step_method(self):
        """Test that step method exists and can be called."""
        world = World(seed=42)
        # Should not raise an exception
        self.agent.step(world)

    def test_perceive_method(self):
        """Test the perceive method."""
        world = World(seed=42)
        world.add_entity("test_agent", {"health": 100})
        world.add_resource("budget", 5000)

        perception = self.agent.perceive(world)

        self.assertIn('time', perception)
        self.assertIn('entities', perception)
        self.assertIn('resources', perception)
        self.assertIn('metadata', perception)
        self.assertEqual(perception['time'], 0.0)
        self.assertEqual(perception['resources']['budget'], 5000)

    def test_act_method(self):
        """Test the act method."""
        world = World(seed=42)

        # Test communicate action
        self.agent.act(world, {"type": "communicate", "data": {"message": "hello"}})
        self.assertEqual(len(self.agent.memory.short_term), 1)
        self.assertEqual(self.agent.memory.short_term[0]['type'], 'communication')

        # Test modify_self action
        self.agent.act(world, {"type": "modify_self", "data": {"health": 0.5}})
        self.assertEqual(self.agent.state.health, 0.5)

        # Test use_resource action
        self.agent.act(world, {"type": "use_resource", "resource": "test_resource", "amount": 50})
        self.assertEqual(self.agent.resources["test_resource"], 50)

    def test_get_state_dict(self):
        """Test getting agent state as dictionary."""
        state_dict = self.agent.get_state_dict()

        self.assertIn('agent_id', state_dict)
        self.assertIn('role', state_dict)
        self.assertIn('goals', state_dict)
        self.assertIn('resources', state_dict)
        self.assertIn('permissions', state_dict)
        self.assertIn('state', state_dict)
        self.assertIn('memory', state_dict)

        self.assertEqual(state_dict['agent_id'], "test_agent")
        self.assertEqual(state_dict['role'], "tester")
        self.assertEqual(state_dict['goals'], ["test_goal"])
        self.assertEqual(state_dict['resources'], {"test_resource": 100})

    def test_can_perform_method(self):
        """Test permission checking."""
        # Agent with no permissions
        agent_no_perms = BaseAgent()
        self.assertFalse(agent_no_perms.can_perform("test_permission"))

        # Agent with specific permission
        agent_with_perms = BaseAgent(permissions=["read", "write", "execute"])
        self.assertTrue(agent_with_perms.can_perform("read"))
        self.assertTrue(agent_with_perms.can_perform("write"))
        self.assertFalse(agent_with_perms.can_perform("delete"))

    def test_receive_event(self):
        """Test receiving and storing events."""
        event = Event(timestamp=5.0, event_type="test_event", data={"info": "test"})
        self.agent.receive_event(event)

        self.assertEqual(len(self.agent.memory.short_term), 1)
        memory_entry = self.agent.memory.short_term[0]
        self.assertEqual(memory_entry['type'], 'event')
        self.assertEqual(memory_entry['event']['timestamp'], 5.0)
        self.assertEqual(memory_entry['event']['event_type'], "test_event")
        self.assertEqual(memory_entry['event']['data'], {"info": "test"})

    def test_string_representations(self):
        """Test string representations of agent."""
        agent_str = str(self.agent)
        agent_repr = repr(self.agent)

        self.assertIn("test_agent", agent_str)
        self.assertIn("tester", agent_str)
        self.assertIn("active", agent_str)

        self.assertIn("test_agent", agent_repr)
        self.assertIn("tester", agent_repr)
        self.assertIn("active", agent_repr)


class TestAgentState(unittest.TestCase):
    """Test cases for the AgentState dataclass."""

    def test_agent_state_initialization(self):
        """Test AgentState initialization."""
        state = AgentState()
        self.assertEqual(state.health, 1.0)
        self.assertEqual(state.energy, 1.0)
        self.assertEqual(state.status, "active")
        self.assertEqual(state.resources, {})
        self.assertIsNone(state.position)
        self.assertEqual(state.metadata, {})

    def test_agent_state_custom_values(self):
        """Test AgentState with custom values."""
        state = AgentState(
            health=0.5,
            energy=0.8,
            resources={"gold": 100},
            status="injured",
            position=[10.0, 20.0, 0.0],
            metadata={"level": 5}
        )

        self.assertEqual(state.health, 0.5)
        self.assertEqual(state.energy, 0.8)
        self.assertEqual(state.resources, {"gold": 100})
        self.assertEqual(state.status, "injured")
        self.assertEqual(state.position, [10.0, 20.0, 0.0])
        self.assertEqual(state.metadata, {"level": 5})


class TestAgentMemory(unittest.TestCase):
    """Test cases for the AgentMemory dataclass."""

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.memory = AgentMemory(max_short_term=3, max_long_term=5)

    def test_agent_memory_initialization(self):
        """Test AgentMemory initialization."""
        self.assertEqual(self.memory.short_term, [])
        self.assertEqual(self.memory.long_term, [])
        self.assertEqual(self.memory.max_short_term, 3)
        self.assertEqual(self.memory.max_long_term, 5)

    def test_add_short_term_memory(self):
        """Test adding items to short-term memory."""
        # Add items within limit
        self.memory.add_short_term({"id": 1})
        self.memory.add_short_term({"id": 2})
        self.assertEqual(len(self.memory.short_term), 2)

        # Add items exceeding limit
        self.memory.add_short_term({"id": 3})
        self.memory.add_short_term({"id": 4})  # This should remove the first item

        self.assertEqual(len(self.memory.short_term), 3)
        self.assertEqual(self.memory.short_term[0]['id'], 2)  # First item should now be id 2
        self.assertEqual(self.memory.short_term[-1]['id'], 4)  # Last item should be id 4

    def test_add_long_term_memory(self):
        """Test adding items to long-term memory."""
        # Add items within limit
        self.memory.add_long_term({"id": "a"})
        self.memory.add_long_term({"id": "b"})
        self.assertEqual(len(self.memory.long_term), 2)

        # Add items exceeding limit
        for i in range(2, 7):  # Add items c, d, e, f, g
            self.memory.add_long_term({"id": chr(ord('a') + i)})

        self.assertEqual(len(self.memory.long_term), 5)
        # Should contain c, d, e, f, g (a and b were removed as oldest)
        self.assertEqual(self.memory.long_term[0]['id'], 'c')
        self.assertEqual(self.memory.long_term[-1]['id'], 'g')

    def test_get_recent_memories(self):
        """Test getting recent memories."""
        # Add some memories
        self.memory.add_short_term({"id": 1})
        self.memory.add_short_term({"id": 2})
        self.memory.add_short_term({"id": 3})

        recent = self.memory.get_recent_memories(2)
        self.assertEqual(len(recent), 2)
        self.assertEqual(recent[0]['id'], 2)
        self.assertEqual(recent[1]['id'], 3)

        # Test getting more than available
        recent_all = self.memory.get_recent_memories(10)
        self.assertEqual(len(recent_all), 3)

        # Test with empty memory
        empty_memory = AgentMemory()
        self.assertEqual(empty_memory.get_recent_memories(5), [])

    def test_clear_memory(self):
        """Test clearing memory."""
        self.memory.add_short_term({"id": 1})
        self.memory.add_long_term({"id": "a"})

        self.assertEqual(len(self.memory.short_term), 1)
        self.assertEqual(len(self.memory.long_term), 1)

        self.memory.clear()

        self.assertEqual(len(self.memory.short_term), 0)
        self.assertEqual(len(self.memory.long_term), 0)


if __name__ == '__main__':
    unittest.main()