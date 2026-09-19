"""
Unit tests for the deterministic NEXUS Scheduler.
"""

import unittest

from simulation.events import Event
from simulation.scheduler import Scheduler


class TestScheduler(unittest.TestCase):

    def setUp(self):
        self.scheduler = Scheduler()

    def make_event(
        self,
        event_id: int,
        tick: int,
        event_type: str = "TickCompleted",
    ) -> Event:
        return Event(
            event_id=event_id,
            tick=tick,
            event_type=event_type,
        )

    def test_scheduler_initialization(self):
        self.assertEqual(self.scheduler.get_event_count(), 0)

    def test_schedule_event(self):
        event = self.make_event(1, 10)

        schedule_id = self.scheduler.schedule_event(10, event)

        self.assertEqual(schedule_id, "event_0")
        self.assertEqual(self.scheduler.get_event_count(), 1)

    def test_schedule_event_with_custom_id(self):
        event = self.make_event(1, 5)

        schedule_id = self.scheduler.schedule_event(
            5,
            event,
            "custom_event",
        )

        self.assertEqual(schedule_id, "custom_event")
        self.assertEqual(self.scheduler.get_event_count(), 1)

    def test_event_tick_must_match_schedule_tick(self):
        event = self.make_event(1, 5)

        with self.assertRaises(ValueError):
            self.scheduler.schedule_event(10, event)

    def test_duplicate_schedule_id_rejected(self):
        event1 = self.make_event(1, 5)
        event2 = self.make_event(2, 6)

        self.scheduler.schedule_event(5, event1, "same-id")

        with self.assertRaises(ValueError):
            self.scheduler.schedule_event(6, event2, "same-id")

    def test_process_events_empty_scheduler(self):
        processed = self.scheduler.process_events(10)

        self.assertEqual(processed, [])

    def test_process_events_single_event(self):
        event = self.make_event(1, 5, "HostCompromised")

        self.scheduler.schedule_event(5, event)

        processed = self.scheduler.process_events(10)

        self.assertEqual(processed, [event])
        self.assertEqual(processed[0].tick, 5)
        self.assertEqual(
            processed[0].event_type,
            "HostCompromised",
        )

    def test_process_events_respects_tick_order(self):
        event1 = self.make_event(1, 1, "IntrusionDetected")
        event2 = self.make_event(2, 3, "HostCompromised")
        event3 = self.make_event(3, 2, "HostIsolated")

        self.scheduler.schedule_event(1, event1)
        self.scheduler.schedule_event(3, event2)
        self.scheduler.schedule_event(2, event3)

        processed = self.scheduler.process_events(2)

        self.assertEqual(
            [event.event_id for event in processed],
            [1, 3],
        )

        processed = self.scheduler.process_events(10)

        self.assertEqual(
            [event.event_id for event in processed],
            [2],
        )

    def test_same_tick_order_is_deterministic(self):
        event1 = self.make_event(1, 5)
        event2 = self.make_event(2, 5)
        event3 = self.make_event(3, 5)

        self.scheduler.schedule_event(5, event1)
        self.scheduler.schedule_event(5, event2)
        self.scheduler.schedule_event(5, event3)

        processed = self.scheduler.process_events(5)

        self.assertEqual(
            [event.event_id for event in processed],
            [1, 2, 3],
        )

    def test_future_events_are_not_processed(self):
        event = self.make_event(1, 10)

        self.scheduler.schedule_event(10, event)

        processed = self.scheduler.process_events(5)

        self.assertEqual(processed, [])
        self.assertEqual(self.scheduler.get_event_count(), 1)

    def test_schedule_callback(self):
        calls = []

        def callback(world, data):
            calls.append((world, data))

        schedule_id = self.scheduler.schedule_event_callback(
            5,
            callback,
            {"test": "data"},
        )

        self.assertEqual(schedule_id, "event_0")
        self.assertEqual(self.scheduler.get_event_count(), 1)

    def test_process_callback(self):
        calls = []

        def callback(world, data):
            calls.append((world, data))

        self.scheduler.schedule_event_callback(
            5,
            callback,
            {"test": "data"},
        )

        world = object()

        count = self.scheduler.process_callbacks(5, world)

        self.assertEqual(count, 1)
        self.assertEqual(calls, [(world, {"test": "data"})])
        self.assertEqual(self.scheduler.get_event_count(), 0)

    def test_cancel_event(self):
        event = self.make_event(1, 5)

        schedule_id = self.scheduler.schedule_event(5, event)

        self.assertTrue(
            self.scheduler.cancel_event(schedule_id)
        )
        self.assertEqual(
            self.scheduler.get_event_count(),
            0,
        )

        self.assertFalse(
            self.scheduler.cancel_event(schedule_id)
        )

    def test_get_upcoming_events(self):
        event1 = self.make_event(1, 1)
        event2 = self.make_event(2, 3)
        event3 = self.make_event(3, 2)

        self.scheduler.schedule_event(1, event1)
        self.scheduler.schedule_event(3, event2)
        self.scheduler.schedule_event(2, event3)

        upcoming = self.scheduler.get_upcoming_events(2)

        self.assertEqual(
            [event.event_id for event in upcoming],
            [1, 3],
        )

        self.assertEqual(
            self.scheduler.get_event_count(),
            3,
        )

    def test_clear_scheduler(self):
        self.scheduler.schedule_event(
            1,
            self.make_event(1, 1),
        )
        self.scheduler.schedule_event(
            2,
            self.make_event(2, 2),
        )

        self.scheduler.clear()

        self.assertEqual(
            self.scheduler.get_event_count(),
            0,
        )


if __name__ == "__main__":
    unittest.main()