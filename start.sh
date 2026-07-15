#!/usr/bin/env bash
# Chat IA Kali — inicialização (Linux/macOS)
set -euo pipefail
cd "$(dirname "$0")"

MODE="${1:-}"

repair_docker() {
  echo
  echo " ============================================"
  echo "  Reparar Docker"
  echo " ============================================"
  echo
  echo "  Erro de I/O ou cache corrompido = reinicie o daemon Docker."
  echo "  1. Reinicie o serviço Docker (systemd / Docker Desktop)"
  echo "  2. Verifique espaço em disco"
  echo "  3. Depois rode: ./start.sh"
  echo

  if ! command -v docker >/dev/null 2>&1; then
    echo "[ERRO] Docker não encontrado no PATH."
    exit 1
  fi

  if ! docker info >/dev/null 2>&1; then
    echo "[AVISO] Docker não responde. Inicie o daemon e rode ./start.sh repair de novo."
    exit 1
  fi

  echo "  Limpando cache (builder + system prune)..."
  docker builder prune -af || true
  docker system prune -af || true
  echo
  echo "  Pronto. Agora rode: ./start.sh"
}

if [[ "$MODE" == "repair" ]]; then
  repair_docker
  exit 0
fi

if [[ "$MODE" == "servidor" || "$MODE" == "nodocker" ]]; then
  exec "$0" --server-only
fi

echo
echo " ============================================"
echo "  Chat IA Kali - Inicialização"
echo " ============================================"
echo

# [1] Python + deps
echo "[1/4] Configuração Python..."
if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "      .env criado — edite OPENROUTER_API_KEY se necessário"
fi

if [[ ! -x venv/bin/python ]]; then
  echo "      Criando venv..."
  python3 -m venv venv
fi

# shellcheck disable=SC1091
source venv/bin/activate
python -m pip install -q --upgrade pip
pip install -q -r requirements.txt
echo "      Python OK"

run_server() {
  UVICORN_HOST="${UVICORN_HOST:-127.0.0.1}"
  UVICORN_PORT="${UVICORN_PORT:-8000}"
  if [[ -f .env ]]; then
    # shellcheck disable=SC1091
    set -a
    source <(grep -E '^(UVICORN_HOST|UVICORN_PORT)=' .env | sed 's/\r$//') || true
    set +a
  fi
  UVICORN_HOST="${UVICORN_HOST:-127.0.0.1}"
  UVICORN_PORT="${UVICORN_PORT:-8000}"

  echo
  echo " ============================================"
  echo "  Pronto: http://${UVICORN_HOST}:${UVICORN_PORT}"
  if [[ "$UVICORN_HOST" == "127.0.0.1" ]]; then
    echo "  Acesso local apenas (127.0.0.1)"
    echo "  Rede LAN: defina UVICORN_HOST=0.0.0.0 no .env"
  fi
  echo "  Ctrl+C para encerrar"
  echo " ============================================"
  echo

  exec python -m uvicorn backend.main:app --host "$UVICORN_HOST" --port "$UVICORN_PORT" --reload
}

if [[ "${1:-}" == "--server-only" ]]; then
  run_server
fi

# [2] Docker
echo "[2/4] Docker..."
if ! command -v docker >/dev/null 2>&1; then
  echo "[AVISO] Docker não encontrado. Subindo só o servidor."
  run_server
fi

if ! docker info >/dev/null 2>&1; then
  echo "[AVISO] Docker não responde. Inicie o daemon e rode ./start.sh de novo."
  echo "        Ou: ./start.sh servidor"
  read -r -p "Subir servidor sem Docker agora? [s/N] " ans
  if [[ "${ans,,}" == "s" || "${ans,,}" == "y" ]]; then
    run_server
  fi
  exit 1
fi
echo "      Docker OK"

# [3] Container Kali
echo "[3/4] Container Kali (build na 1ª vez pode demorar)..."
pushd docker >/dev/null
docker compose up -d --build
popd >/dev/null
echo "      Container OK"

# [4] Servidor
echo "[4/4] Servidor FastAPI..."
run_server
