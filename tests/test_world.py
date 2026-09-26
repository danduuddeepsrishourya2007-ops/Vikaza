"""
Unit tests for the World class in NEXUS Core.
"""

import unittest
from simulation.world import World, HostState, AgentState, DataStoreState
from simulation.events import Event


class TestWorld(unittest.TestCase):
    """Test cases for the World class."""

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.world = World(seed=42)

    def test_initialization(self):
        """Test that the world initializes correctly."""
        self.assertIsNotNone(self.world)
        self.assertEqual(self.world.seed, 42)
        self.assertEqual(self.world.get_time(), 0.0)
        state = self.world.get_state()
        self.assertIsInstance(state, dict)
        self.assertIn('hosts', state)
        self.assertIn('agents', state)
        self.assertIn('data_stores', state)
        self.assertIn('resource_pool', state)

    def test_step_advances_tick(self):
        """Test that stepping advances the simulation tick."""
        initial_tick = self.world.state.tick
        new_tick = self.world.step()
        self.assertEqual(new_tick, initial_tick + 1)
        self.assertEqual(self.world.state.tick, 1)
        self.assertEqual(self.world.get_time(), 1.0)

    def test_multiple_steps(self):
        """Test that multiple steps advance the tick correctly."""
        self.assertEqual(self.world.state.tick, 0)

        tick1 = self.world.step()
        self.assertEqual(tick1, 1)

        tick2 = self.world.step()
        self.assertEqual(tick2, 2)

        tick3 = self.world.step()
        self.assertEqual(tick3, 3)

        self.assertEqual(self.world.state.tick, 3)

    def test_deterministic_with_seed(self):
        """Test that the same seed produces the same random sequence."""
        world1 = World(seed=123)
        world2 = World(seed=123)

        # Generate some random numbers from both worlds
        rand1_a = world1.random()
        rand1_b = world1.random()

        rand2_a = world2.random()
        rand2_b = world2.random()

        # They should be identical
        self.assertEqual(rand1_a, rand2_a)
        self.assertEqual(rand1_b, rand2_b)

    def test_different_seeds_produce_different_sequences(self):
        """Test that different seeds produce different random sequences."""
        world1 = World(seed=123)
        world2 = World(seed=456)

        rand1 = world1.random()
        rand2 = world2.random()

        # They should be different (extremely unlikely to be the same)
        self.assertNotEqual(rand1, rand2)

    def test_get_state_structure(self):
        """Test that get_state returns the correct WorldState structure."""
        state = self.world.get_state()

        # Check that all expected keys are present
        expected_keys = {
            'tick', 'rng_seed', 'scenario_id', 'hosts', 'network',
            'agents', 'data_stores', 'resource_pool', 'active_policy',
            'events', 'metrics_snapshot'
        }
        self.assertEqual(set(state.keys()), expected_keys)

        # Check initial values
        self.assertEqual(state['tick'], 0)
        self.assertEqual(state['rng_seed'], 42)
        self.assertEqual(state['scenario_id'], "")
        self.assertEqual(state['hosts'], {})
        self.assertEqual(state['network'], {})
        self.assertEqual(state['agents'], {})
        self.assertEqual(state['data_stores'], {})
        self.assertIsInstance(state['resource_pool'], dict)
        self.assertIsNone(state['active_policy'])
        self.assertEqual(state['events'], [])
        self.assertEqual(state['metrics_snapshot'], {})

    def test_resource_pool_operations(self):
        """Test resource pool operations."""
        # Test initial resource pool
        state = self.world.get_state()
        self.assertIn('cpu_cycles', state['resource_pool'])
        self.assertIn('memory_mb', state['resource_pool'])
        self.assertIn('bandwidth_mbps', state['resource_pool'])

        # Test adding custom resources
        self.world.add_resource("test_resource", 100)
        self.assertEqual(self.world.get_resource("test_resource"), 100)

        # Test updating resources
        self.world.add_resource("test_resource", 200)
        self.assertEqual(self.world.get_resource("test_resource"), 200)

        # Test getting non-existent resource
        self.assertIsNone(self.world.get_resource("non_existent"))

    def test_host_operations(self):
        """Test host-specific operations."""
        # Test adding a host
        host_data = {
            "host_id": "host1",
            "hostname": "test-host",
            "os_type": "Linux",
            "os_version": "5.4.0",
            "ip_address": "192.168.1.100"
        }

        self.world.add_entity("host1", host_data)

        # Verify host was added
        state = self.world.get_state()
        self.assertIn("host1", state['hosts'])

        host = state['hosts']['host1']
        self.assertEqual(host['host_id'], "host1")
        self.assertEqual(host['hostname'], "test-host")
        self.assertEqual(host['os_type'], "Linux")
        self.assertEqual(host['ip_address'], "192.168.1.100")
        self.assertFalse(host['is_compromised'])  # Default value

        # Test updating a host
        self.world.update_entity("host1", {"is_compromised": True, "cpu_usage": 75.5})

        state = self.world.get_state()
        host = state['hosts']['host1']
        self.assertTrue(host['is_compromised'])
        self.assertEqual(host['cpu_usage'], 75.5)

        # Test getting a host
        retrieved_host = self.world.get_entity("host1")
        self.assertIsNotNone(retrieved_host)
        self.assertTrue(retrieved_host['is_compromised'])
        self.assertEqual(retrieved_host['cpu_usage'], 75.5)

        # Test getting non-existent host
        self.assertIsNone(self.world.get_entity("non_existent"))

    def test_agent_operations(self):
        """Test agent-specific operations."""
        # Test adding an agent
        agent_data = {
            "agent_id": "agent1",
            "role": "attacker",
            "current_host": "host1"
        }

        # Need to add a host first for the agent to reference
        host_data = {
            "host_id": "host1",
            "hostname": "test-host"
        }
        self.world.add_entity("host1", host_data)
        self.world.add_entity("agent1", agent_data)

        # Verify agent was added
        state = self.world.get_state()
        self.assertIn("agent1", state['agents'])

        agent = state['agents']['agent1']
        self.assertEqual(agent['agent_id'], "agent1")
        self.assertEqual(agent['role'], "attacker")
        self.assertEqual(agent['current_host'], "host1")

        # Test updating an agent
        self.world.update_entity("agent1", {"current_host": "host2"})

        # Add host2 for reference
        host2_data = {
            "host_id": "host2",
            "hostname": "target-host"
        }
        self.world.add_entity("host2", host2_data)

        state = self.world.get_state()
        agent = state['agents']['agent1']
        self.assertEqual(agent['current_host'], "host2")

        # Test getting an agent
        retrieved_agent = self.world.get_entity("agent1")
        self.assertIsNotNone(retrieved_agent)
        self.assertEqual(retrieved_agent['current_host'], "host2")

    def test_datastore_operations(self):
        """Test data store-specific operations."""
        # Test adding a data store
        datastore_data = {
            "store_id": "ds1",
            "name": "Primary Database",
            "store_type": "database",
            "location_host": "host1",
            "size_gb": 100.0,
            "sensitivity_level": "high",
            "encryption_enabled": True
        }

        # Need to add a host first for the data store to reference
        host_data = {
            "host_id": "host1",
            "hostname": "db-host"
        }
        self.world.add_entity("host1", host_data)
        self.world.add_entity("ds1", datastore_data)

        # Verify data store was added
        state = self.world.get_state()
        self.assertIn("ds1", state['data_stores'])

        datastore = state['data_stores']['ds1']
        self.assertEqual(datastore['store_id'], "ds1")
        self.assertEqual(datastore['name'], "Primary Database")
        self.assertEqual(datastore['store_type'], "database")
        self.assertEqual(datastore['location_host'], "host1")
        self.assertEqual(datastore['size_gb'], 100.0)
        self.assertEqual(datastore['sensitivity_level'], "high")
        self.assertTrue(datastore['encryption_enabled'])
        self.assertFalse(datastore['is_exfiltrated'])  # Default value

        # Test updating a data store
        self.world.update_entity("ds1", {"size_gb": 150.0, "is_exfiltrated": True})

        state = self.world.get_state()
        datastore = state['data_stores']['ds1']
        self.assertEqual(datastore['size_gb'], 150.0)
        self.assertTrue(datastore['is_exfiltrated'])

        # Test getting a data store
        retrieved_datastore = self.world.get_entity("ds1")
        self.assertIsNotNone(retrieved_datastore)
        self.assertEqual(retrieved_datastore['size_gb'], 150.0)
        self.assertTrue(retrieved_datastore['is_exfiltrated'])

    def test_reset_functionality(self):
        """Test that reset properly resets the world state."""
        # Modify the world
        host_data = {"host_id": "test", "hostname": "test-host"}
        self.world.add_entity("test", host_data)
        self.world.add_resource("test_res", 42)
        old_tick = self.world.step()  # Advance time

        # Verify changes
        self.assertGreater(self.world.state.tick, 0)
        self.assertIsNotNone(self.world.get_entity("test"))
        self.assertEqual(self.world.get_resource("test_res"), 42)

        # Reset the world
        self.world.reset(seed=42)

        # Verify reset state
        self.assertEqual(self.world.state.tick, 0)
        self.assertEqual(self.world.state.rng_seed, 42)
        self.assertIsNone(self.world.get_entity("test"))
        self.assertIsNone(self.world.get_resource("test_res"))

        # Verify default resource pool is restored
        state = self.world.get_state()
        self.assertEqual(state['resource_pool']['cpu_cycles'], 1000.0)
        self.assertEqual(state['resource_pool']['memory_mb'], 4096.0)
        self.assertEqual(state['resource_pool']['bandwidth_mbps'], 100.0)

    def test_random_methods(self):
        """Test the random number generation methods."""
        # Test random float
        rand_float = self.world.random()
        self.assertGreaterEqual(rand_float, 0.0)
        self.assertLess(rand_float, 1.0)

        # Test randint
        rand_int = self.world.randint(1, 10)
        self.assertGreaterEqual(rand_int, 1)
        self.assertLessEqual(rand_int, 10)

        # Test choice
        test_list = ['a', 'b', 'c']
        choice_result = self.world.choice(test_list)
        self.assertIn(choice_result, test_list)

    def test_world_state_immutability_via_get_state(self):
        """Test that modifications to get_state don't affect internal state."""
        # Get state twice
        state1 = self.world.get_state()
        state2 = self.world.get_state()

        # They should be equal but not the same object
        self.assertEqual(state1, state2)
        self.assertIsNot(state1, state2)

        # Modifying the returned state shouldn't affect the world
        original_tick = self.world.state.tick
        state1['tick'] = 999
        self.assertEqual(self.world.state.tick, original_tick)


if __name__ == '__main__':
    unittest.main()