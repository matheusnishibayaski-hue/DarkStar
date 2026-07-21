# start.ps1 — Menu dev Chat IA Kali (R/K/Q). Chamado por start.bat após bootstrap.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ProjectRoot,
    [string] $ComposeFile = "docker-compose.yml"
)

$ErrorActionPreference = 'Continue'
try {
    [Console]::TreatControlCAsInput = $true
} catch {
    Write-Host 'AVISO: console sem modo interativo (execute start.bat no cmd).' -ForegroundColor DarkYellow
}

function Read-DotEnv {
    param([string]$Root)
    $vars = @{}
    $envPath = Join-Path $Root '.env'
    if (-not (Test-Path $envPath)) { return $vars }
    foreach ($line in Get-Content -Path $envPath -Encoding UTF8) {
        if ($line -match '^\s*#') { continue }
        $envMatch = [regex]::Match($line, '^\s*([^=]+)=(.*)$')
        if (-not $envMatch.Success) { continue }
        $vars[$envMatch.Groups[1].Value.Trim()] = $envMatch.Groups[2].Value.Trim()
    }
    return $vars
}

function Stop-PortListener {
    param([int]$Port)
    $listenerLines = @(netstat -ano | Select-String ":$Port\s" | Select-String 'LISTENING')
    foreach ($line in $listenerLines) {
        $parts = ($line.ToString() -split '\s+') | Where-Object { $_ -ne '' }
        $procId = $parts[-1]
        if ($procId -and $procId -ne '0') {
            cmd /c "taskkill /PID $procId /F /T >nul 2>&1" | Out-Null
        }
    }
}

function Start-UvicornServer {
    param(
        [string]$Root,
        [string]$BindHost,
        [int]$Port
    )
    Stop-PortListener -Port $Port
    Start-Sleep -Milliseconds 350

    $venvAct = Join-Path $Root 'venv\Scripts\activate.bat'
    $python = Join-Path $Root 'venv\Scripts\python.exe'
    if (-not (Test-Path $python)) {
        Write-Host '[ERRO] venv nao encontrado. Rode start.bat completo uma vez.' -ForegroundColor Red
        return $null
    }

    $title = "Chat IA Kali - servidor ($BindHost`:$Port)"
    $inner = "title $title && cd /d `"$Root`" && call `"$venvAct`" && python -m uvicorn backend.main:app --host $BindHost --port $Port --reload"
    $proc = Start-Process -FilePath 'cmd.exe' `
        -ArgumentList "/k $inner" `
        -WorkingDirectory $Root `
        -PassThru `
        -WindowStyle Normal

    Write-Host ("[Servidor] iniciado http://{0}:{1} (PID {2})" -f $BindHost, $Port, $proc.Id) -ForegroundColor Green
    return $proc
}

function Stop-UvicornServer {
    param(
        [System.Diagnostics.Process]$Proc,
        [int]$Port
    )
    if ($Proc -and -not $Proc.HasExited) {
        cmd /c "taskkill /PID $($Proc.Id) /F /T >nul 2>&1" | Out-Null
    }
    Stop-PortListener -Port $Port
    Write-Host '[Servidor] encerrado' -ForegroundColor Yellow
}

function Restart-KaliContainer {
    param(
        [string]$Root,
        [string]$Compose
    )
    $dockerDir = Join-Path $Root 'docker'
    $composePath = Join-Path $dockerDir $Compose
    if (-not (Test-Path $composePath)) {
        Write-Host "[ERRO] Nao encontrado: $composePath" -ForegroundColor Red
        return
    }
    Write-Host '[Kali] docker compose restart (sem rebuild)...' -ForegroundColor Cyan
    Push-Location $dockerDir
    try {
        & docker compose -f $Compose restart 2>&1 | ForEach-Object { Write-Host $_ }
        if ($LASTEXITCODE -eq 0) {
            Write-Host '[Kali] container reiniciado.' -ForegroundColor Green
        } else {
            Write-Host "[Kali] falhou (codigo $LASTEXITCODE). Docker esta rodando?" -ForegroundColor Red
        }
    } finally {
        Pop-Location
    }
}

function Show-Menu {
    param(
        [System.Diagnostics.Process]$Server,
        [string]$BindHost,
        [int]$Port,
        [string]$Compose
    )
    $srv = if ($Server -and -not $Server.HasExited) { "PID $($Server.Id)" } else { 'PARADO' }
    Write-Host ''
    Write-Host '============================================' -ForegroundColor DarkGray
    Write-Host ' Chat IA Kali - Dev (menu)' -ForegroundColor Cyan
    Write-Host (" UI + API:  http://{0}:{1}  ({2})" -f $BindHost, $Port, $srv) -ForegroundColor White
    Write-Host (" Docker:    {0}" -f $Compose) -ForegroundColor DarkGray
    Write-Host '============================================' -ForegroundColor DarkGray
    Write-Host ' [R] Reiniciar servidor (uvicorn) — rapido, sem pip/Docker'
    Write-Host ' [K] Reiniciar container Kali (docker compose restart)'
    Write-Host ' [Q] Encerrar servidor e sair'
    Write-Host '============================================' -ForegroundColor DarkGray
    Write-Host -NoNewline ' Tecla: '
}

# --- bootstrap ----------------------------------------------------------------
$cfg = Read-DotEnv -Root $ProjectRoot
$bindHost = if ($cfg['UVICORN_HOST']) { $cfg['UVICORN_HOST'] } else { '127.0.0.1' }
$port = 8000
if ($cfg['UVICORN_PORT']) {
    [void][int]::TryParse($cfg['UVICORN_PORT'], [ref]$port)
}

$server = Start-UvicornServer -Root $ProjectRoot -BindHost $bindHost -Port $port

$running = $true
while ($running) {
    Show-Menu -Server $server -BindHost $bindHost -Port $port -Compose $ComposeFile

    try {
        while (-not [Console]::KeyAvailable) {
            Start-Sleep -Milliseconds 120
        }
        $key = [Console]::ReadKey($true)
    } catch {
        Write-Host ''
        Write-Host 'ERRO: leitura de teclas indisponivel. Use start.bat no Prompt de Comando.' -ForegroundColor Red
        $running = $false
        break
    }

    if (($key.Modifiers -band [ConsoleModifiers]::Control) -and $key.Key -eq 'C') {
        Write-Host 'Ctrl+C - encerrando.' -ForegroundColor Red
        $running = $false
        break
    }

    switch ($key.Key) {
        'R' {
            Write-Host 'R' -ForegroundColor Cyan
            Stop-UvicornServer -Proc $server -Port $port
            Start-Sleep -Milliseconds 400
            $server = Start-UvicornServer -Root $ProjectRoot -BindHost $bindHost -Port $port
        }
        'K' {
            Write-Host 'K' -ForegroundColor Magenta
            Restart-KaliContainer -Root $ProjectRoot -Compose $ComposeFile
        }
        'Q' {
            Write-Host 'Q' -ForegroundColor Red
            $running = $false
        }
        default {
            Write-Host ("(tecla {0} ignorada)" -f $key.Key) -ForegroundColor DarkGray
        }
    }
}

Write-Host ''
Write-Host 'Encerrando servidor...' -ForegroundColor Red
Stop-UvicornServer -Proc $server -Port $port
Write-Host 'Menu encerrado. Docker/Kali continuam se estavam rodando.' -ForegroundColor DarkGray
