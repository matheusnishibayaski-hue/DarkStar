"""Controle de missões Auto-Pilot e processos Docker em execução."""

from __future__ import annotations

import subprocess
import threading
from dataclasses import dataclass, field


@dataclass
class MissionControl:
    mission_id: str
    cancel_event: threading.Event = field(default_factory=threading.Event)
    processes: dict[str, subprocess.Popen] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)


class MissionRegistry:
    def __init__(self) -> None:
        self._missions: dict[str, MissionControl] = {}
        self._lock = threading.Lock()

    def register(self, mission_id: str) -> MissionControl:
        ctrl = MissionControl(mission_id=mission_id)
        with self._lock:
            self._missions[mission_id] = ctrl
        return ctrl

    def get(self, mission_id: str) -> MissionControl | None:
        with self._lock:
            return self._missions.get(mission_id)

    def is_cancelled(self, mission_id: str | None) -> bool:
        if not mission_id:
            return False
        ctrl = self.get(mission_id)
        return bool(ctrl and ctrl.cancel_event.is_set())

    def register_process(
        self,
        mission_id: str | None,
        execution_id: str,
        proc: subprocess.Popen,
    ) -> None:
        if not mission_id:
            return
        ctrl = self.get(mission_id)
        if not ctrl:
            return
        with ctrl.lock:
            ctrl.processes[execution_id] = proc

    def unregister_process(self, mission_id: str | None, execution_id: str) -> None:
        if not mission_id:
            return
        ctrl = self.get(mission_id)
        if not ctrl:
            return
        with ctrl.lock:
            ctrl.processes.pop(execution_id, None)

    def cancel(self, mission_id: str) -> bool:
        ctrl = self.get(mission_id)
        if not ctrl:
            return False
        ctrl.cancel_event.set()
        with ctrl.lock:
            procs = list(ctrl.processes.values())
        for proc in procs:
            try:
                proc.kill()
            except OSError:
                pass
        try:
            from backend.observability import incr

            incr("cancellations_total")
        except Exception:
            pass
        return True

    def cleanup(self, mission_id: str) -> None:
        with self._lock:
            self._missions.pop(mission_id, None)


_registry: MissionRegistry | None = None


def get_mission_registry() -> MissionRegistry:
    global _registry
    if _registry is None:
        _registry = MissionRegistry()
    return _registry
