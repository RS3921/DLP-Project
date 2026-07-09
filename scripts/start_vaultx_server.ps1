$ErrorActionPreference = "Continue"

$ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$PythonExe = "C:\Users\Raveena\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"

if (-not $env:VAULTX_API_KEY) {
    $env:VAULTX_API_KEY = "vaultx-local-dev-key"
}

Set-Location $ProjectRoot
& $PythonExe vaultx.py serve --host 127.0.0.1 --port 8765
