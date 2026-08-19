"""
Asynchronous Cowrie Log Collector Service.
Monitors cowrie.json in real time, buffers incomplete lines, normalizes incoming events,
and emits them to registered callbacks and the SessionAggregator.
"""

import asyncio
import logging
import os
from pathlib import Path
from typing import Any, Callable, Coroutine, List, Optional, Set, Union

from backend.app.models.events import NormalizedEvent
from backend.app.services.event_normalizer import EventNormalizer
from backend.app.services.session_aggregator import SessionAggregator

logger = logging.getLogger(__name__)

# Callback type accepting (NormalizedEvent, SessionFeatures)
EventCallback = Callable[[NormalizedEvent, Any], Union[None, Coroutine[Any, Any, None]]]


class AsyncLogCollector:
    """
    Asynchronous file tailer and event emitter for Cowrie JSON telemetry.
    """

    def __init__(
        self,
        log_path: Union[str, Path],
        aggregator: Optional[SessionAggregator] = None,
        from_beginning: bool = False,
        poll_interval: float = 0.2
    ):
        self.log_path = Path(log_path).resolve()
        self.aggregator = aggregator or SessionAggregator()
        self.from_beginning = from_beginning
        self.poll_interval = poll_interval
        self._running = False
        self._stop_event = asyncio.Event()
        self._callbacks: List[EventCallback] = []
        self._processed_event_ids: Set[str] = set()
        self._current_offset: int = 0
        self._buffer: str = ""

    def register_callback(self, callback: EventCallback) -> None:
        """
        Registers an async or sync callback to receive normalized events and updated session features.
        """
        if callback not in self._callbacks:
            self._callbacks.append(callback)

    async def _emit(self, event: NormalizedEvent) -> None:
        """
        Emits normalized events to the SessionAggregator and all registered listeners.
        """
        # Incrementally update session aggregator
        session_features = self.aggregator.add_event(event)

        # Notify registered callbacks
        for cb in self._callbacks:
            try:
                res = cb(event, session_features)
                if asyncio.iscoroutine(res):
                    await res
            except Exception as e:
                logger.error("Error in event callback: %s", e, exc_info=True)

    def _process_line(self, line: str) -> Optional[NormalizedEvent]:
        """
        Parses a single raw line, normalizes it, and returns the NormalizedEvent if unique.
        """
        clean_line = line.strip()
        if not clean_line:
            return None

        event = EventNormalizer.normalize(clean_line)
        if event is None:
            return None

        # Duplicate event check
        if event.event_id in self._processed_event_ids:
            logger.debug("Skipping duplicate event_id: %s", event.event_id)
            return None

        self._processed_event_ids.add(event.event_id)
        return event

    async def start(self) -> None:
        """
        Starts the asynchronous log tailing loop.
        """
        self._running = True
        self._stop_event.clear()

        logger.info("Starting AsyncLogCollector on %s (from_beginning=%s)", self.log_path, self.from_beginning)

        # Wait for file to exist if not present at startup
        while self._running and not self.log_path.exists():
            logger.debug("Waiting for log file to be created: %s", self.log_path)
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self.poll_interval)
                break
            except asyncio.TimeoutError:
                pass

        if not self._running:
            return

        # Initialize read offset
        file_size = os.path.getsize(self.log_path) if self.log_path.exists() else 0
        if self.from_beginning:
            self._current_offset = 0
        else:
            self._current_offset = file_size

        logger.info("AsyncLogCollector initialized at offset %d bytes", self._current_offset)

        try:
            with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self._current_offset)

                while self._running:
                    # Check for file truncation/rotation
                    try:
                        current_file_size = os.path.getsize(self.log_path)
                        if current_file_size < self._current_offset:
                            logger.warning("Log file truncated or rotated. Resetting offset to 0.")
                            f.seek(0)
                            self._current_offset = 0
                            self._buffer = ""
                    except OSError:
                        pass

                    chunk = f.read(65536)
                    if chunk:
                        self._buffer += chunk
                        # Process complete lines terminated by newline
                        if "\n" in self._buffer:
                            lines = self._buffer.split("\n")
                            # The last element is the leftover partial line buffer
                            self._buffer = lines[-1]
                            for line in lines[:-1]:
                                event = self._process_line(line)
                                if event:
                                    await self._emit(event)

                        self._current_offset = f.tell()
                    else:
                        # No new data; sleep non-blocking to prevent high CPU usage
                        try:
                            await asyncio.wait_for(self._stop_event.wait(), timeout=self.poll_interval)
                            break  # Stop requested
                        except asyncio.TimeoutError:
                            pass

        except Exception as e:
            if self._running:
                logger.error("Unexpected error in log tailing loop: %s", e, exc_info=True)
        finally:
            self._running = False
            logger.info("AsyncLogCollector stopped.")

    def stop(self) -> None:
        """
        Signals the collector to terminate gracefully.
        """
        self._running = False
        self._stop_event.set()


def cli_main():
    """
    Command-line runner for the asynchronous log collector.
    """
    import argparse
    import signal

    parser = argparse.ArgumentParser(description="Cowrie Asynchronous Log Collector & Feature Extractor")
    parser.add_argument(
        "--log-path",
        default=os.getenv("COWRIE_LOG_PATH", "./honeypot/var/log/cowrie/cowrie.json"),
        help="Path to cowrie.json file (default: ./honeypot/var/log/cowrie/cowrie.json)"
    )
    parser.add_argument(
        "--from-beginning",
        action="store_true",
        help="Process existing historical events from the beginning of the file"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    aggregator = SessionAggregator()
    collector = AsyncLogCollector(
        log_path=args.log_path,
        aggregator=aggregator,
        from_beginning=args.from_beginning
    )

    def print_event(event: NormalizedEvent, session: Any):
        print("\n" + "=" * 70)
        print("[EVENT INGESTED]")
        print(f"Event ID    : {event.event_id}")
        print(f"Session ID  : {event.session_id}")
        print(f"Source IP   : {event.source_ip or 'N/A'}")
        print(f"Event Type  : {event.event_type}")
        if event.command:
            print(f"Command     : {event.command}")
        if event.username:
            print(f"Username    : {event.username}")
        print(f"Timestamp   : {event.timestamp.isoformat()}")

        if session:
            print("-" * 70)
            print("[SESSION PROFILE UPDATE]")
            print(f"Session ID       : {session.session_id}")
            print(f"Duration (s)     : {session.duration_seconds}s")
            print(f"Total Events     : {session.total_events}")
            print(f"Commands Count   : {session.command_count} (Unique: {session.unique_command_count})")
            if session.commands:
                print(f"Recent Commands  : {', '.join(session.commands[-5:])}")
            if session.average_command_interval is not None:
                print(f"Avg Cmd Interval : {session.average_command_interval}s")
            print(f"Activity Rate    : {session.activity_rate} events/s")
            print(f"Session Closed   : {session.is_closed}")
        print("=" * 70 + "\n", flush=True)

    collector.register_callback(print_event)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def handle_sigint():
        print("\n[*] Stopping collector gracefully...")
        collector.stop()

    try:
        loop.run_until_complete(collector.start())
    except KeyboardInterrupt:
        collector.stop()
    finally:
        loop.close()


if __name__ == "__main__":
    cli_main()
