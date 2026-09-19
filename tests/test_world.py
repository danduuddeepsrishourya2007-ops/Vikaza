"""
Unit tests for the World class in NEXUS Core.
"""

import unittest
from simulation.world import World
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
        self.assertIsInstance(self.world.get_state(), dict)

    def test_step_advances_time(self):
        """Test that stepping advances the simulation time."""
        initial_time = self.world.get_time()
        new_time = self.world.step()
        self.assertEqual(new_time, initial_time + 1.0)
        self.assertEqual(self.world.get_time(), 1.0)

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

    def test_add_and_get_entity(self):
        """Test adding and retrieving entities."""
        entity_id = "test_entity"
        entity_data = {"health": 100, "role": "defender"}

        self.world.add_entity(entity_id, entity_data)
        retrieved = self.world.get_entity(entity_id)

        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["health"], 100)
        self.assertEqual(retrieved["role"], "defender")

    def test_update_entity(self):
        """Test updating entity data."""
        entity_id = "test_entity"
        initial_data = {"health": 100, "status": "active"}
        update_data = {"health": 80, "status": "damaged"}

        self.world.add_entity(entity_id, initial_data)
        self.world.update_entity(entity_id, update_data)

        retrieved = self.world.get_entity(entity_id)
        self.assertEqual(retrieved["health"], 80)
        self.assertEqual(retrieved["status"], "damaged")

    def test_add_and_get_resource(self):
        """Test adding and retrieving resources."""
        resource_key = "budget"
        resource_value = 1000000

        self.world.add_resource(resource_key, resource_value)
        retrieved = self.world.get_resource(resource_key)

        self.assertEqual(retrieved, resource_value)

    def test_reset_functionality(self):
        """Test that reset properly resets the world state."""
        # Modify the world
        self.world.add_entity("test", {"data": "value"})
        self.world.add_resource("test_res", 42)
        self.world.step()  # Advance time

        # Verify changes
        self.assertGreater(self.world.get_time(), 0)
        self.assertIsNotNone(self.world.get_entity("test"))

        # Reset the world
        self.world.reset(seed=42)

        # Verify reset state
        self.assertEqual(self.world.get_time(), 0.0)
        self.assertIsNone(self.world.get_entity("test"))
        self.assertIsNone(self.world.get_resource("test_res"))

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


if __name__ == '__main__':
    unittest.main()