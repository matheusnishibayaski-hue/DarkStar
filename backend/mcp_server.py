"""Servidor MCP via stdio — para uso com Cursor, Claude Desktop e agentes locais.

Uso:
    python -m backend.mcp_server

Protocolo: JSON-RPC 2.0 com *framing* estilo LSP (`Content-Length` + linha em
branco antes do corpo), conforme o transporte stdio do Model Context Protocol
(https://modelcontextprotocol.io). Toda a lógica de tools/resources é
compartilhada com o transporte HTTP via `backend.mcp_service`.

Exemplo de configuração no Cursor (`~/.cursor/mcp.json`):

    {
      "mcpServers": {
        "chat-ia-kali": {
          "command": "python",
          "args": ["-m", "backend.mcp_server"],
          "cwd": "/caminho/para/Chat IA Kali"
        }
      }
    }

Este processo herda o `.env` do projeto (via `backend.config`) — respeita a
mesma whitelist de ferramentas e a trava de escopo `ALLOWED_TARGETS` usadas
pelo chat e pelo Auto-Pilot.
"""

from __future__ import annotations

import json
import sys
from typing import Any, BinaryIO

from backend import mcp_service


def _read_message(stream: BinaryIO) -> dict[str, Any] | None:
    """Lê uma mensagem com framing `Content-Length: N\\r\\n\\r\\n<corpo JSON>`."""
    headers: dict[str, str] = {}
    while True:
        line = stream.readline()
        if not line:
            return None  # EOF — stdin fechado pelo cliente MCP
        if line in (b"\r\n", b"\n"):
            break
        if b":" in line:
            key, _, value = line.partition(b":")
            headers[key.strip().lower().decode("ascii", "ignore")] = value.strip().decode(
                "utf-8", "ignore"
            )

    try:
        length = int(headers.get("content-length", "0") or "0")
    except ValueError:
        return None
    if length <= 0:
        return None

    body = stream.read(length)
    if not body:
        return None
    try:
        parsed = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _write_message(stream: BinaryIO, message: dict[str, Any]) -> None:
    data = json.dumps(message, ensure_ascii=False).encode("utf-8")
    header = f"Content-Length: {len(data)}\r\n\r\n".encode("ascii")
    stream.write(header)
    stream.write(data)
    stream.flush()


def serve(stdin: BinaryIO | None = None, stdout: BinaryIO | None = None) -> None:
    """Loop principal: lê mensagens JSON-RPC do stdin e escreve respostas no stdout."""
    in_stream = stdin if stdin is not None else sys.stdin.buffer
    out_stream = stdout if stdout is not None else sys.stdout.buffer

    while True:
        message = _read_message(in_stream)
        if message is None:
            break
        response = mcp_service.handle_rpc(message)
        if response is not None:
            _write_message(out_stream, response)


if __name__ == "__main__":
    serve()
