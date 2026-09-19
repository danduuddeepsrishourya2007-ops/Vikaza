"""
Unit tests for the Scheduler class in NEXUS Core.
"""

import unittest
from simulation.scheduler import Scheduler
from simulation.events import Event


class TestScheduler(unittest.TestCase):
    """Test cases for the Scheduler class."""

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.scheduler = Scheduler()

    def test_scheduler_initialization(self):
        """Test that the scheduler initializes correctly."""
        self.assertIsNotNone(self.scheduler)
        self.assertEqual(self.scheduler.get_event_count(), 0)

    def test_schedule_event(self):
        """Test scheduling an event."""
        event = Event(timestamp=10.0, event_type="test_event")
        event_id = self.scheduler.schedule_event(10.0, event)

        self.assertIsNotNone(event_id)
        self.assertEqual(self.scheduler.get_event_count(), 1)
        self.assertTrue(event_id.startswith("event_"))

    def test_schedule_event_with_custom_id(self):
        """Test scheduling an event with a custom event ID."""
        event = Event(timestamp=5.0, event_type="test_event")
        custom_id = "custom_event_1"
        event_id = self.scheduler.schedule_event(5.0, event, custom_id)

        self.assertEqual(event_id, custom_id)
        self.assertEqual(self.scheduler.get_event_count(), 1)

    def test_process_events_empty_scheduler(self):
        """Test processing events when scheduler is empty."""
        processed = self.scheduler.process_events(10.0)
        self.assertEqual(len(processed), 0)

    def test_process_events_single_event(self):
        """Test processing a single event."""
        event = Event(timestamp=5.0, event_type="test_event")
        self.scheduler.schedule_event(5.0, event)

        processed = self.scheduler.process_events(10.0)
        self.assertEqual(len(processed), 1)
        self.assertEqual(processed[0].timestamp, 5.0)
        self.assertEqual(processed[0].event_type, "test_event")

    def test_process_events_multiple_events(self):
        """Test processing multiple events in correct order."""
        event1 = Event(timestamp=1.0, event_type="first")
        event2 = Event(timestamp=3.0, event_type="second")
        event3 = Event(timestamp=2.0, event_type="third")

        self.scheduler.schedule_event(1.0, event1)
        self.scheduler.schedule_event(3.0, event2)
        self.scheduler.schedule_event(2.0, event3)

        # Process events up to time 2.5
        processed = self.scheduler.process_events(2.5)
        self.assertEqual(len(processed), 2)
        self.assertEqual(processed[0].timestamp, 1.0)
        self.assertEqual(processed[0].event_type, "first")
        self.assertEqual(processed[1].timestamp, 2.0)
        self.assertEqual(processed[1].event_type, "third")

        # Process remaining events
        processed = self.scheduler.process_events(10.0)
        self.assertEqual(len(processed), 1)
        self.assertEqual(processed[0].timestamp, 3.0)
        self.assertEqual(processed[0].event_type, "second")

    def test_process_events_future_events(self):
        """Test that future events are not processed."""
        event = Event(timestamp=10.0, event_type="future_event")
        self.scheduler.schedule_event(10.0, event)

        # Process events up to time 5.0 (before the event)
        processed = self.scheduler.process_events(5.0)
        self.assertEqual(len(processed), 0)
        self.assertEqual(self.scheduler.get_event_count(), 1)  # Event still scheduled

    def test_schedule_event_callback(self):
        """Test scheduling a callback event."""
        def test_callback(world, data):
            pass

        event_data = {"test": "data"}
        event_id = self.scheduler.schedule_event_callback(5.0, test_callback, event_data)

        self.assertIsNotNone(event_id)
        self.assertEqual(self.scheduler.get_event_count(), 1)

    def test_cancel_event(self):
        """Test cancelling a scheduled event."""
        event = Event(timestamp=5.0, event_type="test_event")
        event_id = self.scheduler.schedule_event(5.0, event)

        # Verify event is scheduled
        self.assertEqual(self.scheduler.get_event_count(), 1)

        # Cancel the event
        result = self.scheduler.cancel_event(event_id)
        self.assertTrue(result)
        self.assertEqual(self.scheduler.get_event_count(), 0)

        # Try to cancel non-existent event
        result = self.scheduler.cancel_event("non_existent")
        self.assertFalse(result)

    def test_get_upcoming_events(self):
        """Test getting upcoming events without processing them."""
        event1 = Event(timestamp=1.0, event_type="first")
        event2 = Event(timestamp=3.0, event_type="second")
        event3 = Event(timestamp=2.0, event_type="third")

        self.scheduler.schedule_event(1.0, event1)
        self.scheduler.schedule_event(3.0, event2)
        self.scheduler.schedule_event(2.0, event3)

        upcoming = self.scheduler.get_upcoming_events(2)
        self.assertEqual(len(upcoming), 2)
        self.assertEqual(upcoming[0].timestamp, 1.0)
        self.assertEqual(upcoming[1].timestamp, 2.0)

        # Verify events are still in queue
        self.assertEqual(self.scheduler.get_event_count(), 3)

    def test_clear_scheduler(self):
        """Test clearing all scheduled events."""
        event1 = Event(timestamp=1.0, event_type="first")
        event2 = Event(timestamp=2.0, event_type="second")

        self.scheduler.schedule_event(1.0, event1)
        self.scheduler.schedule_event(2.0, event2)

        self.assertEqual(self.scheduler.get_event_count(), 2)

        self.scheduler.clear()
        self.assertEqual(self.scheduler.get_event_count(), 0)


if __name__ == '__main__':
    unittest.main()