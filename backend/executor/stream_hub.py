"""Hub thread-safe para streaming SSE de execuções em andamento."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from queue import Empty, Queue
from typing import Any


@dataclass
class ExecutionStream:
    execution_id: str
    command: str
    queue: Queue = field(default_factory=Queue)
    finished: bool = False
    created_at: float = field(default_factory=time.time)


class StreamHub:
    def __init__(self) -> None:
        self._streams: dict[str, ExecutionStream] = {}
        self._lock = threading.Lock()

    def create(self, execution_id: str, command: str) -> ExecutionStream:
        stream = ExecutionStream(execution_id=execution_id, command=command)
        with self._lock:
            self._streams[execution_id] = stream
        self.push(execution_id, "start", {"execution_id": execution_id, "command": command})
        return stream

    def get(self, execution_id: str) -> ExecutionStream | None:
        with self._lock:
            return self._streams.get(execution_id)

    def push(self, execution_id: str, event_type: str, data: dict[str, Any]) -> None:
        stream = self.get(execution_id)
        if not stream:
            return
        stream.queue.put({"type": event_type, "data": data})

    def push_line(self, execution_id: str, stream_name: str, text: str) -> None:
        self.push(execution_id, "line", {"stream": stream_name, "text": text})

    def finish(
        self,
        execution_id: str,
        *,
        exit_code: int,
        success: bool,
        blocked: bool = False,
    ) -> None:
        stream = self.get(execution_id)
        if not stream:
            return
        stream.finished = True
        self.push(
            execution_id,
            "done",
            {
                "execution_id": execution_id,
                "exit_code": exit_code,
                "success": success,
                "blocked": blocked,
            },
        )

    def cleanup(self, execution_id: str, delay: float = 120.0) -> None:
        def _remove() -> None:
            time.sleep(delay)
            with self._lock:
                self._streams.pop(execution_id, None)

        threading.Thread(target=_remove, daemon=True).start()

    def subscribe_sse(self, execution_id: str) -> Iterator[str]:
        stream = self.get(execution_id)
        if not stream:
            yield f"event: error\ndata: {json.dumps({'detail': 'Execução não encontrada'})}\n\n"
            return

        while True:
            try:
                item = stream.queue.get(timeout=15)
            except Empty:
                if stream.finished:
                    break
                yield ": keepalive\n\n"
                continue

            payload = json.dumps(item["data"], ensure_ascii=False)
            yield f"event: {item['type']}\ndata: {payload}\n\n"
            if item["type"] == "done":
                break


_hub = StreamHub()


def get_stream_hub() -> StreamHub:
    return _hub
