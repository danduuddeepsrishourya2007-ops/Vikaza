"""
Deterministic event scheduler for the NEXUS simulation engine.

The scheduler is responsible only for ordering scheduled work.
Authoritative simulation Events remain immutable records and are never
responsible for mutating WorldState themselves.
"""

import heapq
from dataclasses import dataclass
from typing import Any, Callable

from .events import Event


@dataclass(frozen=True)
class _ScheduledItem:
    """Internal scheduler entry."""

    event: Event | None
    callback: Callable[[Any, Any], None] | None
    callback_data: Any
    schedule_id: str
    tick: int
    sequence: int


class Scheduler:
    """Deterministic tick-based scheduler."""

    def __init__(self) -> None:
        self._event_queue: list[tuple[int, int, _ScheduledItem]] = []
        self._sequence_count = 0
        self._scheduled_events: dict[str, _ScheduledItem] = {}

    def _next_id(self) -> str:
        schedule_id = f"event_{self._sequence_count}"
        return schedule_id

    def schedule_event(
        self,
        event_time: int,
        event: Event,
        event_id: str | None = None,
    ) -> str:
        """
        Schedule an authoritative Event.

        Events are ordered by tick and then insertion sequence.
        """

        if event_time < 0:
            raise ValueError("event_time must be non-negative")

        if event.tick != event_time:
            raise ValueError(
                "event.tick must match the scheduler event_time"
            )

        if event_id is None:
            event_id = self._next_id()

        if event_id in self._scheduled_events:
            raise ValueError(f"Duplicate schedule ID: {event_id}")

        sequence = self._sequence_count
        self._sequence_count += 1

        item = _ScheduledItem(
            event=event,
            callback=None,
            callback_data=None,
            schedule_id=event_id,
            tick=event_time,
            sequence=sequence,
        )

        heapq.heappush(
            self._event_queue,
            (event_time, sequence, item),
        )

        self._scheduled_events[event_id] = item

        return event_id

    def schedule_event_callback(
        self,
        event_time: int,
        callback: Callable[[Any, Any], None],
        event_data: Any = None,
        event_id: str | None = None,
    ) -> str:
        """
        Schedule an internal callback.

        Callback work is deliberately not represented as an Event because
        callbacks are execution mechanics, not authoritative simulation
        history.
        """

        if event_time < 0:
            raise ValueError("event_time must be non-negative")

        if event_id is None:
            event_id = self._next_id()

        if event_id in self._scheduled_events:
            raise ValueError(f"Duplicate schedule ID: {event_id}")

        sequence = self._sequence_count
        self._sequence_count += 1

        item = _ScheduledItem(
            event=None,
            callback=callback,
            callback_data=event_data,
            schedule_id=event_id,
            tick=event_time,
            sequence=sequence,
        )

        heapq.heappush(
            self._event_queue,
            (event_time, sequence, item),
        )

        self._scheduled_events[event_id] = item

        return event_id

    def cancel_event(self, event_id: str) -> bool:
        """
        Cancel a scheduled item.

        Cancellation removes the item from the tracking map. The heap is
        rebuilt so cancelled work cannot later be processed.
        """

        item = self._scheduled_events.pop(event_id, None)

        if item is None:
            return False

        self._event_queue = [
            queued
            for queued in self._event_queue
            if queued[2] is not item
        ]
        heapq.heapify(self._event_queue)

        return True

    def process_events(self, current_time: int) -> list[Event]:
        """
        Process all scheduled authoritative Events up to current_time.

        Callback tasks execute against the supplied world through
        process_callbacks(); they are not returned as Events.
        """

        processed: list[Event] = []

        while self._event_queue and self._event_queue[0][0] <= current_time:
            _, _, item = heapq.heappop(self._event_queue)
            self._scheduled_events.pop(item.schedule_id, None)

            if item.event is not None:
                processed.append(item.event)

        return processed

    def process_callbacks(self, current_time: int, world: Any) -> int:
        """
        Execute scheduled callbacks up to current_time.

        Returns the number of callbacks executed.

        Authoritative Events are left untouched by this method.
        """

        ready_callbacks: list[_ScheduledItem] = []
        remaining: list[tuple[int, int, _ScheduledItem]] = []

        while self._event_queue:
            tick, sequence, item = heapq.heappop(self._event_queue)

            if tick <= current_time and item.callback is not None:
                ready_callbacks.append(item)
                self._scheduled_events.pop(item.schedule_id, None)
            else:
                remaining.append((tick, sequence, item))

        for entry in remaining:
            heapq.heappush(self._event_queue, entry)

        for item in ready_callbacks:
            item.callback(world, item.callback_data)

        return len(ready_callbacks)

    def get_upcoming_events(self, count: int = 10) -> list[Event]:
        """Return upcoming authoritative Events without consuming them."""

        if count < 0:
            raise ValueError("count must be non-negative")

        upcoming = [
            item
            for _, _, item in sorted(self._event_queue)
            if item.event is not None
        ]

        return [
            item.event
            for item in upcoming[:count]
            if item.event is not None
        ]

    def get_event_count(self) -> int:
        """Return the number of scheduled items."""

        return len(self._event_queue)

    def clear(self) -> None:
        """Remove all scheduled work and reset deterministic sequencing."""

        self._event_queue.clear()
        self._scheduled_events.clear()
        self._sequence_count = 0