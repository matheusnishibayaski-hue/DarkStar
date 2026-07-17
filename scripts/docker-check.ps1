param(
    [int]$TimeoutSec = 15,
    [string]$OutputPath = "",
    [switch]$PipeOnly,
    [switch]$BackendOnly,
    [switch]$EngineOnly,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$DockerArgs
)

# Exit codes:
# 0=ok, 1=docker failed, 2=docker.exe not found, 3=engine pipe missing,
# 4=backend not responding, 99=cli timeout

function Add-DockerToPath {
    $dirs = @(
        (Join-Path $env:ProgramFiles "Docker\Docker\resources\bin"),
        (Join-Path $env:ProgramFiles "Docker\Docker\resources")
    )
    foreach ($dir in $dirs) {
        if ((Test-Path $dir) -and (($env:Path -split ';') -notcontains $dir)) {
            $env:Path = "$dir;$env:Path"
        }
    }
}

function Get-DockerExe {
    Add-DockerToPath
    $cmd = Get-Command docker.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $candidate = Join-Path $env:ProgramFiles "Docker\Docker\resources\bin\docker.exe"
    if (Test-Path $candidate) { return $candidate }

    return $null
}

function Test-DockerEnginePipe {
    (Test-Path "\\.\pipe\dockerDesktopLinuxEngine") -or (Test-Path "\\.\pipe\docker_engine")
}

function Test-DockerBackend {
    param([int]$TimeoutMs = 5000)
    return (Invoke-DockerPipeRequest -PipeName "dockerBackendApiServer" -Path "/ping" -TimeoutMs $TimeoutMs)
}

function Test-DockerEngine {
    param([int]$TimeoutMs = 5000)
    $pipes = @("dockerDesktopLinuxEngine", "docker_engine")
    foreach ($name in $pipes) {
        if (Test-Path "\\.\pipe\$name") {
            if (Invoke-DockerPipeRequest -PipeName $name -Path "/_ping" -TimeoutMs $TimeoutMs) {
                return $true
            }
        }
    }
    return $false
}

function Invoke-DockerPipeRequest {
    param(
        [string]$PipeName,
        [string]$Path,
        [int]$TimeoutMs = 5000
    )
    $pipe = $null
    try {
        $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(
            ".", $PipeName,
            [System.IO.Pipes.PipeDirection]::InOut,
            [System.IO.Pipes.PipeOptions]::None)
        $pipe.Connect($TimeoutMs)
        $req = [Text.Encoding]::ASCII.GetBytes("GET $Path HTTP/1.1`r`nHost: docker`r`nConnection: close`r`n`r`n")
        $pipe.Write($req, 0, $req.Length)
        $pipe.Flush()
        $buf = New-Object byte[] 4096
        $read = $pipe.Read($buf, 0, $buf.Length)
        if ($read -le 0) { return $false }
        $text = [Text.Encoding]::UTF8.GetString($buf, 0, $read)
        return $text -match "200"
    }
    catch {
        return $false
    }
    finally {
        if ($pipe) { $pipe.Dispose() }
    }
}

function Stop-ProcessTree {
    param([int]$ProcessId)
    & taskkill.exe /PID $ProcessId /T /F 2>$null | Out-Null
}

function Clear-StaleDockerCli {
  # Only the lightweight CLI shim — not Docker Desktop / backend services.
    Get-Process -Name docker -ErrorAction SilentlyContinue | ForEach-Object {
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
}

Remove-Item Env:DOCKER_HOST -ErrorAction SilentlyContinue
Add-DockerToPath

if ($BackendOnly) {
    if (Test-DockerBackend -TimeoutMs ($TimeoutSec * 1000)) { exit 0 }
    exit 4
}

if ($EngineOnly) {
    if (Test-DockerEngine -TimeoutMs ($TimeoutSec * 1000)) { exit 0 }
    exit 5
}

if ($PipeOnly) {
    if (Test-DockerEnginePipe) { exit 0 }
    exit 3
}

$docker = Get-DockerExe
if (-not $docker) { exit 2 }

if (-not (Test-DockerEnginePipe)) { exit 3 }

if (-not (Test-DockerEngine -TimeoutMs 3000)) { exit 5 }

if ($DockerArgs.Count -eq 0) {
    $DockerArgs = @("ps", "-q", "-n", "1")
}

Clear-StaleDockerCli

try {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $docker
    $psi.Arguments = ($DockerArgs | ForEach-Object {
        if ($_ -match '\s') { '"' + $_ + '"' } else { $_ }
    }) -join ' '
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $p = [System.Diagnostics.Process]::Start($psi)
    if (-not $p) { exit 1 }

    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        Stop-ProcessTree -ProcessId $p.Id
        Clear-StaleDockerCli
        exit 99
    }

    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()

    if ($OutputPath) {
        Set-Content -Path $OutputPath -Value $stdout -NoNewline -Encoding UTF8
    }

    if ($p.ExitCode -ne 0 -and $stderr) {
        [Console]::Error.WriteLine($stderr.Trim())
    }

    exit $p.ExitCode
}
catch {
    exit 1
}
