import re
import subprocess
import sys

from backend.config import HOST_WIFI_TOOLS
from backend.executor.logs import save_execution_log
from backend.executor.result import ExecutionResult


def _run_netsh(args: list[str], timeout: int = 45) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["netsh", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        encoding="utf-8",
        errors="replace",
    )


def _scan_windows(command: str, reason: str, log_id: str | None = None) -> ExecutionResult:
    binary = command.strip().split()[0].split("/")[-1]
    sections: list[str] = []

    try:
        if binary == "wlan-interfaces":
            proc = _run_netsh(["wlan", "show", "interfaces"])
            sections.append("=== Adaptador Wi-Fi (Windows) ===\n" + proc.stdout)
            if proc.stderr:
                sections.append("STDERR:\n" + proc.stderr)
            ok = proc.returncode == 0
        else:
            iface = _run_netsh(["wlan", "show", "interfaces"])
            networks = _run_netsh(["wlan", "show", "networks", "mode=bssid"])
            profiles = _run_netsh(["wlan", "show", "profiles"])

            sections.append("=== Adaptador Wi-Fi ===\n" + iface.stdout)
            sections.append("=== Redes visíveis ===\n" + networks.stdout)
            sections.append("=== Perfis salvos (este PC) ===\n" + profiles.stdout)

            stderr = "\n".join(filter(None, [iface.stderr, networks.stderr, profiles.stderr]))
            if stderr:
                sections.append("STDERR:\n" + stderr)
            ok = networks.returncode == 0

        stdout = "\n\n".join(sections)
        saved_id = save_execution_log(command, reason, stdout[:50000], "", log_id=log_id)
        return ExecutionResult(
            command=command,
            reason=reason,
            stdout=stdout[:50000],
            stderr="",
            exit_code=0 if ok else 1,
            success=ok,
            log_file_id=saved_id,
            tool=binary,
        )
    except FileNotFoundError:
        return ExecutionResult(
            command=command,
            reason=reason,
            stdout="",
            stderr="netsh não disponível. Este recurso requer Windows.",
            exit_code=-1,
            success=False,
        )
    except subprocess.TimeoutExpired:
        return ExecutionResult(
            command=command,
            reason=reason,
            stdout="",
            stderr="Timeout ao escanear redes Wi-Fi.",
            exit_code=-1,
            success=False,
        )
    except Exception as e:
        return ExecutionResult(
            command=command,
            reason=reason,
            stdout="",
            stderr=str(e),
            exit_code=-1,
            success=False,
        )


def _scan_linux(command: str, reason: str, log_id: str | None = None) -> ExecutionResult:
    binary = command.strip().split()[0].split("/")[-1]
    cmds: list[list[str]] = []

    if binary == "wlan-interfaces":
        cmds = [["iw", "dev"], ["iwconfig"]]
    else:
        cmds = [["iw", "dev"], ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,SECURITY", "dev", "wifi", "list"]]

    sections: list[str] = []
    ok = False
    errors: list[str] = []

    for cmd in cmds:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=45,
                encoding="utf-8",
                errors="replace",
            )
            label = " ".join(cmd)
            sections.append(f"=== {label} ===\n{proc.stdout or '(sem saída)'}")
            if proc.stderr:
                errors.append(proc.stderr)
            ok = ok or proc.returncode == 0
        except FileNotFoundError:
            errors.append(f"{' '.join(cmd)} não encontrado.")
        except Exception as e:
            errors.append(str(e))

    stdout = "\n\n".join(sections)[:50000]
    stderr = "\n".join(errors)[:10000]
    saved_id = save_execution_log(command, reason, stdout, stderr, log_id=log_id)
    return ExecutionResult(
        command=command,
        reason=reason,
        stdout=stdout,
        stderr=stderr,
        exit_code=0 if ok else 1,
        success=ok,
        log_file_id=saved_id,
        tool=binary,
    )


def execute_host_wifi(command: str, reason: str, log_id: str | None = None) -> ExecutionResult:
    if sys.platform == "win32":
        return _scan_windows(command, reason, log_id=log_id)
    return _scan_linux(command, reason, log_id=log_id)


def windows_wifi_health() -> tuple[bool, list[str], str]:
    try:
        proc = _run_netsh(["wlan", "show", "interfaces"], timeout=15)
        if proc.returncode != 0:
            return False, [], proc.stderr.strip() or "Wi-Fi indisponível"

        interfaces = re.findall(r"^\s*Nome\s*:\s*(.+)$", proc.stdout, re.MULTILINE)
        if not interfaces:
            interfaces = re.findall(r"^\s*Name\s*:\s*(.+)$", proc.stdout, re.MULTILINE)

        net_proc = _run_netsh(["wlan", "show", "networks"], timeout=15)
        net_count = len(re.findall(r"^\s*SSID \d+", net_proc.stdout, re.MULTILINE))

        if interfaces:
            msg = f"Placa nativa: {', '.join(i.strip() for i in interfaces)} · {net_count} rede(s) visível(is)"
            return True, [i.strip() for i in interfaces], msg
        return False, [], "Nenhuma interface Wi-Fi ativa no Windows"
    except Exception as e:
        return False, [], str(e)
