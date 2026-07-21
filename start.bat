@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

if /i "%~1"=="servidor" goto server_only
if /i "%~1"=="nodocker" goto server_only
if /i "%~1"=="repair" goto repair_docker
if /i "%~1"=="menu" goto menu_only
if /i "%~1"=="quick" goto menu_only

set "COMPOSE_FILE=docker-compose.yml"
if /i "%~1"=="restricted" set "COMPOSE_FILE=docker-compose.restricted.yml"

title Chat IA Kali
set "DOCKER_HOST="
set "PIP_NO_WARN_SCRIPT_LOCATION=1"
if exist "%ProgramFiles%\Docker\Docker\resources\bin" (
    set "PATH=%ProgramFiles%\Docker\Docker\resources\bin;%PATH%"
)
echo.
echo  ============================================
echo   Chat IA Kali - Inicializacao completa
if /i "%COMPOSE_FILE%"=="docker-compose.restricted.yml" (
  echo   Perfil Docker: RESTRITO ^(sem Wi-Fi^)
) else (
  echo   Perfil Docker: Wi-Fi / completo
)
echo  ============================================
echo.

REM [1/6] Python e config (nao depende do Docker)
echo [1/6] Configuracao...
if not exist ".env" (
    copy /y ".env.example" ".env" >nul
    echo       .env criado - edite OPENROUTER_API_KEY se necessario
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
python -m pip install -q -r requirements.txt
if errorlevel 1 (
    echo [AVISO] Algumas dependencias pip falharam - continuando...
)
python -c "import reportlab" >nul 2>&1
if errorlevel 1 (
    echo       Instalando reportlab ^(relatorios PDF^)...
    python -m pip install -q reportlab==4.4.1
    if errorlevel 1 (
        echo [AVISO] reportlab nao instalado - geracao de PDF falhara
    )
)
echo       Python OK

REM [2/6] Docker (com timeout - nao trava se estiver carregando)
echo [2/6] Docker...
call :docker_ping 20
if !DOCKER_RC! equ 0 goto docker_ok

call :docker_desktop_running
if !DOCKER_DESKTOP! equ 0 (
    echo       Docker Desktop nao esta aberto - iniciando...
    call :start_docker_desktop
) else (
    echo       Docker Desktop aberto, aguardando engine ficar pronta...
)

set /a _dw=0
set /a _cli_fail=0
set /a _repair_try=0
:wait_docker
set /a _dw+=1
call :docker_backend_ping
if !DOCKER_BACKEND! equ 0 (
    echo       tentativa !_dw!/20 - aguardando backend Docker...
    timeout /t 3 /nobreak >nul
    if !_dw! lss 20 goto wait_docker
    goto docker_failed
)
call :docker_engine_ping
if !DOCKER_ENGINE! equ 0 (
    echo       tentativa !_dw!/20 - backend OK, aguardando engine...
    if !_repair_try! lss 2 if !_dw! equ 6 (
        set /a _repair_try+=1
        echo       engine nao sobe - reparo automatico !_repair_try!/2...
        call :restart_docker_engine
        set /a _dw=0
        timeout /t 15 /nobreak >nul
        goto wait_docker
    )
    timeout /t 4 /nobreak >nul
    if !_dw! lss 20 goto wait_docker
    goto docker_failed
)
if !_dw! equ 1 (
    echo       engine OK, testando CLI...
) else (
    echo       tentativa !_dw!/20 - testando CLI...
)
call :cleanup_docker_cli
call :docker_ping 12
if !DOCKER_RC! equ 0 goto docker_ok
set /a _cli_fail+=1
if !_cli_fail! geq 2 if !_repair_try! lss 2 (
    set /a _repair_try+=1
    echo       CLI travado - reparo automatico !_repair_try!/2...
    call :restart_docker_engine
    set /a _cli_fail=0
    set /a _dw=0
    timeout /t 15 /nobreak >nul
    goto wait_docker
)
if !_dw! lss 20 (
    timeout /t 4 /nobreak >nul
    goto wait_docker
)

:docker_failed
echo.
call :docker_desktop_running
if !DOCKER_DESKTOP! equ 1 (
    echo [AVISO] Docker Desktop aberto, mas a engine nao responde.
    echo        Rode: start.bat repair
    echo        Ou reinicie o PC se o problema persistir.
) else (
    echo [AVISO] Docker nao respondeu. Abra o Docker Desktop e aguarde ficar estavel.
)
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
docker compose -f "!COMPOSE_FILE!" up -d --build
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
if not defined COMPOSE_FILE set "COMPOSE_FILE=docker-compose.yml"
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
python -m pip install -q -r requirements.txt >nul 2>&1
python -c "import reportlab" >nul 2>&1
if errorlevel 1 python -m pip install -q reportlab==4.4.1 >nul 2>&1
goto run_server

:menu_only
if not defined COMPOSE_FILE set "COMPOSE_FILE=docker-compose.yml"
echo.
echo  Modo rapido — apenas menu do servidor (sem Docker/pip)
echo.
if not exist "venv\Scripts\python.exe" (
    echo [ERRO] Rode start.bat completo uma vez para criar o venv.
    pause
    exit /b 1
)
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

call :restart_docker_engine

set /a _n=0
:wait_repair
timeout /t 5 /nobreak >nul
call :cleanup_docker_cli
call :docker_ping 15
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
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\docker-check.ps1" -TimeoutSec %~1 >nul 2>&1
set "DOCKER_RC=!ERRORLEVEL!"
exit /b 0

:docker_backend_ping
set "DOCKER_BACKEND=0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\docker-check.ps1" -BackendOnly -TimeoutSec 5 >nul 2>&1
if not errorlevel 1 set "DOCKER_BACKEND=1"
exit /b 0

:docker_engine_ping
set "DOCKER_ENGINE=0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\docker-check.ps1" -EngineOnly -TimeoutSec 5 >nul 2>&1
if not errorlevel 1 set "DOCKER_ENGINE=1"
exit /b 0

:docker_pipe_ready
set "DOCKER_PIPE=0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\docker-check.ps1" -PipeOnly >nul 2>&1
if not errorlevel 1 set "DOCKER_PIPE=1"
exit /b 0

:cleanup_docker_cli
taskkill /IM docker.exe /F >nul 2>&1
exit /b 0

:restart_docker_engine
call :cleanup_docker_cli
wsl --shutdown >nul 2>&1
if exist "%ProgramFiles%\Docker\Docker\DockerCli.exe" (
    "%ProgramFiles%\Docker\Docker\DockerCli.exe" -Shutdown >nul 2>&1
)
taskkill /IM "Docker Desktop.exe" /F >nul 2>&1
timeout /t 8 /nobreak >nul
call :start_docker_desktop
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
if not defined COMPOSE_FILE set "COMPOSE_FILE=docker-compose.yml"
echo.
echo  ============================================
if exist ".env" (
  for /f "usebackq tokens=1,* delims==" %%a in (`findstr /b "UVICORN_HOST=" ".env" 2^>nul`) do set UVICORN_HOST=%%b
)
if not defined UVICORN_HOST set UVICORN_HOST=127.0.0.1
for /f "usebackq tokens=1,* delims==" %%a in (`findstr /b "UVICORN_PORT=" ".env" 2^>nul`) do set UVICORN_PORT=%%b
if not defined UVICORN_PORT set UVICORN_PORT=8000
echo   Pronto: http://!UVICORN_HOST!:!UVICORN_PORT!
if /i "!UVICORN_HOST!"=="127.0.0.1" (
  echo   Acesso local apenas ^(127.0.0.1^)
  echo   Rede LAN: defina UVICORN_HOST=0.0.0.0 no .env
)
echo   Menu: [R] reiniciar servidor  [K] reiniciar Kali  [Q] sair
echo  ============================================
echo.

set "START_PS1=%~dp0start.ps1"
if not exist "!START_PS1!" (
    echo [ERRO] Nao encontrado: !START_PS1!
    pause
    exit /b 1
)

powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File "!START_PS1!" ^
    -ProjectRoot "%CD%" ^
    -ComposeFile "!COMPOSE_FILE!"

echo.
echo Menu encerrado.
pause
exit /b 0
