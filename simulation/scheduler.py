"""
Event Scheduler Module
Implements event scheduling and processing logic for NEXUS Core.
"""

import heapq
from typing import List, Any, Callable, Optional
from .events import Event


class Scheduler:
    """Manages scheduling and processing of events in the simulation."""

    def __init__(self):
        """Initialize the event scheduler."""
        # Using a heap queue for efficient event retrieval
        self._event_queue: List[tuple] = []  # (timestamp, sequence_count, event)
        self._sequence_count = 0  # To ensure FIFO ordering for same timestamp
        self._scheduled_events: dict = {}  # For potential cancellation by ID
        self._cancelled_events: set = set()  # Track cancelled event IDs

    def schedule_event(self, event_time: float, event: Event, event_id: Optional[str] = None) -> Optional[str]:
        """Schedule an event for future processing.

        Args:
            event_time (float): Time at which to schedule the event
            event (Event): Event to schedule
            event_id (str, optional): Identifier for potential cancellation

        Returns:
            str: The event ID used for scheduling (generated if not provided)
        """
        if event_id is None:
            event_id = f"event_{self._sequence_count}"

        # Push to heap queue: (timestamp, sequence_count, event)
        heapq.heappush(self._event_queue, (event_time, self._sequence_count, event))
        self._sequence_count += 1

        # Store for potential cancellation
        if event_id:
            self._scheduled_events[event_id] = (event_time, self._sequence_count - 1, event)

        return event_id

    def schedule_event_callback(self, event_time: float, callback: Callable, event_data: Any = None,
                              event_id: Optional[str] = None) -> Optional[str]:
        """Schedule a callback function for future processing.

        Args:
            event_time (float): Time at which to schedule the callback
            callback (callable): Function to call when event occurs
            event_data (any, optional): Data to pass to the callback
            event_id (str, optional): Identifier for potential cancellation

        Returns:
            str: The event ID used for scheduling (generated if not provided)
        """
        # Create a wrapper event that executes the callback
        class CallbackEvent(Event):
            def __init__(self, timestamp, callback, data):
                super().__init__(timestamp, "callback", data or {})
                self.callback = callback

            def process(self, world):
                self.callback(world, self.data)

        callback_event = CallbackEvent(event_time, callback, event_data)
        return self.schedule_event(event_time, callback_event, event_id)

    def cancel_event(self, event_id: str) -> bool:
        """Cancel a scheduled event.

        Args:
            event_id (str): Identifier of the event to cancel

        Returns:
            bool: True if event was found and cancelled, False otherwise
        """
        if event_id in self._scheduled_events:
            # Get the event details to remove from heap
            timestamp, sequence_count, event = self._scheduled_events[event_id]

            # Remove from scheduled events tracking
            del self._scheduled_events[event_id]

            # Rebuild heap without the cancelled event
            # This is O(n) but acceptable for Stage 1
            new_queue = []
            for item in self._event_queue:
                ts, seq, ev = item
                # Check if this is the event to cancel (matching timestamp and sequence count)
                if not (ts == timestamp and seq == sequence_count and ev is event):
                    new_queue.append(item)

            self._event_queue = new_queue
            heapq.heapify(self._event_queue)

            return True
        return False

    def process_events(self, current_time: float) -> List[Event]:
        """Process all events scheduled up to the current time.

        Args:
            current_time (float): Current simulation time

        Returns:
            list: Events that were processed
        """
        processed = []

        # Extract all events that should be processed at or before current_time
        while self._event_queue and self._event_queue[0][0] <= current_time:
            timestamp, sequence_count, event = heapq.heappop(self._event_queue)
            # Check if this event has been cancelled
            # We need to reconstruct the event_id to check if it's cancelled
            # Since we don't store event_id in the heap, we'll check if any scheduled
            # events matching this timestamp/sequence were cancelled
            # For simplicity in Stage 1, we'll process all events and let cancellation
            # work by removing from scheduled_events (which we check elsewhere if needed)
            processed.append(event)

        return processed

    def get_upcoming_events(self, count: int = 10) -> List[Event]:
        """Get the next upcoming events without processing them.

        Args:
            count (int): Maximum number of events to return

        Returns:
            list: Upcoming events
        """
        # Return a copy of the next events without removing them from queue
        # We need to sort by timestamp since heap queue only guarantees first element is smallest
        upcoming = []
        # Create a list of (timestamp, event) for sorting
        timestamp_event_list = [(timestamp, event) for timestamp, _, event in self._event_queue]
        # Sort by timestamp
        timestamp_event_list.sort(key=lambda x: x[0])
        # Extract the events up to the requested count
        for timestamp, event in timestamp_event_list[:count]:
            upcoming.append(event)
        return upcoming

    def get_event_count(self) -> int:
        """Get the number of scheduled events.

        Returns:
            int: Number of scheduled events
        """
        return len(self._event_queue)

    def clear(self):
        """Clear all scheduled events."""
        self._event_queue.clear()
        self._scheduled_events.clear()
        self._sequence_count = 0