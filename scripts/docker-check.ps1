param(
    [int]$TimeoutSec = 15,
    [string]$OutputPath = "",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$DockerArgs
)

if ($DockerArgs.Count -eq 0) {
    $DockerArgs = @("info")
}

$outFile = [System.IO.Path]::GetTempFileName()
$errFile = [System.IO.Path]::GetTempFileName()

try {
    $p = Start-Process -FilePath "docker" -ArgumentList $DockerArgs -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $outFile -RedirectStandardError $errFile

    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        exit 99
    }

    if ($OutputPath) {
        if (Test-Path $outFile) {
            Copy-Item -Path $outFile -Destination $OutputPath -Force
        } else {
            Set-Content -Path $OutputPath -Value "" -NoNewline
        }
    }

    exit $p.ExitCode
}
finally {
    Remove-Item $outFile, $errFile -Force -ErrorAction SilentlyContinue
}
