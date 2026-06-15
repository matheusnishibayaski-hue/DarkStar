@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

if /i "%~1"=="servidor" goto server_only
if /i "%~1"=="nodocker" goto server_only
if /i "%~1"=="repair" goto repair_docker

title Chat IA Kali
echo.
echo  ============================================
echo   Chat IA Kali - Inicializacao completa
echo  ============================================
echo.

REM [1/6] Python e config (nao depende do Docker)
echo [1/6] Configuracao...
if not exist ".env" (
    copy /y ".env.example" ".env" >nul
    echo       .env criado - edite GEMINI_API_KEY se necessario
)

if not exist "venv\Scripts\python.exe" (
    echo       Criando ambiente virtual Python...
    python -m venv venv
    if errorlevel 1 (
        echo [ERRO] Python nao encontrado. Instale Python 3.10+
        pause
        exit /b 1
    )
)

call "venv\Scripts\activate.bat"
python -m pip install -q --upgrade pip >nul 2>&1
pip install -q -r requirements.txt
if errorlevel 1 (
    echo [AVISO] Algumas dependencias pip falharam - continuando...
)
echo       Python OK

REM [2/6] Docker (com timeout - nao trava se estiver carregando)
echo [2/6] Docker...
call :docker_ping 12
if !DOCKER_RC! equ 0 goto docker_ok

call :docker_desktop_running
if !DOCKER_DESKTOP! equ 0 (
    echo       Docker Desktop nao esta aberto - iniciando...
    call :start_docker_desktop
) else (
    echo       Docker Desktop aberto, aguardando engine ficar pronta...
)

set /a _dw=0
:wait_docker
set /a _dw+=1
echo       tentativa !_dw!/40 ^(max ~8 min^)...
call :docker_ping 12
if !DOCKER_RC! equ 0 goto docker_ok
if !_dw! lss 40 goto wait_docker

echo.
echo [AVISO] Docker nao respondeu. Icone da baleia ainda carregando?
echo        Abra o Docker Desktop, aguarde ficar verde/estavel e rode start.bat de novo.
echo        Ou suba so o chat agora: start.bat servidor
echo.
choice /C SN /N /M "Subir servidor sem Docker agora? (S/N): "
if errorlevel 2 (
    pause
    exit /b 1
)
goto server_only

:docker_ok
echo       Docker OK

REM [3/6] Container Kali
echo [3/6] Container Kali - build na 1a vez pode levar varios minutos...
pushd docker
docker compose up -d --build
set DOCKER_EXIT=!errorlevel!
popd
if !DOCKER_EXIT! neq 0 (
    echo [ERRO] Falha ao subir kali-tools.
    echo.
    echo  Se apareceu "input/output error" ou "blob":
    echo  - Rode: start.bat repair
    echo  - Ou no Docker Desktop: Settings ^> Troubleshoot ^> Clean/Purge data
    echo.
    echo  Para subir so o chat sem Docker: start.bat servidor
    pause
    exit /b 1
)

REM [4/6] Aguardar container
echo [4/6] Aguardando kali-tools...
set /a _kw=0
:wait_kali
call :docker_cmd 20 ps --filter name=kali-tools --filter status=running -q
if !DOCKER_RC! equ 0 (
    findstr /r "." "%TEMP%\docker-last-out.txt" >nul 2>&1
    if not errorlevel 1 goto kali_ok
)
timeout /t 2 /nobreak >nul
set /a _kw+=1
if !_kw! lss 45 goto wait_kali
echo [AVISO] Container ainda iniciando - servidor sobe mesmo assim
goto kali_done
:kali_ok
echo       kali-tools rodando
:kali_done

REM [5/6] Verificar ferramentas
echo [5/6] Verificando ferramentas...
call :docker_cmd 30 exec kali-tools which nmap
if !DOCKER_RC! neq 0 (
    echo [AVISO] Build ainda em andamento - aguarde e teste de novo
) else (
    echo       Ferramentas Kali OK
)

REM [6/6] Servidor
echo [6/6] Servidor web...
goto run_server

:server_only
echo.
echo  Servidor apenas (sem Docker/Kali)
echo  Wi-Fi scan nativo (wlan-scan) funciona assim.
echo  Ferramentas Kali precisam do container.
echo.

if not exist ".env" (
    copy /y ".env.example" ".env" >nul
)

if not exist "venv\Scripts\python.exe" (
    echo       Criando ambiente virtual Python...
    python -m venv venv
    if errorlevel 1 (
        echo [ERRO] Python nao encontrado. Instale Python 3.10+
        pause
        exit /b 1
    )
)

call "venv\Scripts\activate.bat"
pip install -q -r requirements.txt >nul 2>&1
goto run_server

:repair_docker
echo.
echo  ============================================
echo   Reparar Docker Desktop
echo  ============================================
echo.
echo  Erro "input/output error" ou blob corrompido = problema do Docker.
echo.
echo  1. Feche o Docker Desktop (Quit na bandeja)
echo  2. Abra de novo e aguarde iniciar
echo  3. Se falhar: Settings - Troubleshoot - Clean/Purge data
echo  4. Verifique espaco em disco no drive C:
echo  5. Depois rode: start.bat
echo.
echo  Reiniciando Docker agora...
echo.

taskkill /IM "Docker Desktop.exe" /F >nul 2>&1
timeout /t 5 /nobreak >nul
call :start_docker_desktop

set /a _n=0
:wait_repair
timeout /t 5 /nobreak >nul
call :docker_ping 12
if !DOCKER_RC! equ 0 goto repair_ok
set /a _n+=1
if !_n! lss 24 goto wait_repair

echo Docker ainda nao responde. Use Clean/Purge data no Docker Desktop.
pause
exit /b 1

:repair_ok
echo Docker respondeu. Limpando cache...
call :docker_cmd 120 builder prune -af
call :docker_cmd 120 system prune -af
echo.
echo Pronto. Agora rode: start.bat
pause
exit /b 0

REM --- helpers ---
:docker_ping
set "DOCKER_RC=1"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\docker-check.ps1" -TimeoutSec %~1 info >nul 2>&1
set "DOCKER_RC=!ERRORLEVEL!"
exit /b 0

:docker_cmd
set "DOCKER_RC=1"
set "_DC_TIMEOUT=%~1"
shift
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\docker-check.ps1" -TimeoutSec %_DC_TIMEOUT% -OutputPath "%TEMP%\docker-last-out.txt" %1 %2 %3 %4 %5 %6 %7 %8 %9 >nul 2>&1
set "DOCKER_RC=!ERRORLEVEL!"
exit /b 0

:docker_desktop_running
set "DOCKER_DESKTOP=0"
tasklist /FI "IMAGENAME eq Docker Desktop.exe" 2>nul | find /I "Docker Desktop.exe" >nul
if not errorlevel 1 set "DOCKER_DESKTOP=1"
exit /b 0

:start_docker_desktop
if exist "%ProgramFiles%\Docker\Docker\Docker Desktop.exe" (
    start "" "%ProgramFiles%\Docker\Docker\Docker Desktop.exe"
    exit /b 0
)
if exist "%LocalAppData%\Docker\Docker\Docker Desktop.exe" (
    start "" "%LocalAppData%\Docker\Docker\Docker Desktop.exe"
    exit /b 0
)
echo [ERRO] Docker Desktop nao encontrado.
echo        Instale: https://docker.com/products/docker-desktop
pause
exit /b 1

:run_server
echo.
echo  ============================================
echo   Pronto: http://localhost:8000
echo   Pressione Ctrl+C para encerrar
echo  ============================================
echo.

python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

echo.
echo Servidor encerrado.
pause
