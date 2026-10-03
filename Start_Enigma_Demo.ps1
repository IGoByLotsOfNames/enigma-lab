# Path: working/Start_Enigma_Demo.ps1
[CmdletBinding()]
param(
    [ValidateRange(0, 65535)][int]$Port = 0,
    [switch]$OpenBrowser,
    [string]$Python = ''
)

$ErrorActionPreference = 'Stop'
$demoPython = $Python
if (-not $demoPython) {
    $projectPython = Join-Path $PSScriptRoot '..\environment\.venv\Scripts\python.exe'
    if (Test-Path -LiteralPath $projectPython -PathType Leaf) {
        $demoPython = $projectPython
    } else {
        $installedPython = Get-Command python -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $installedPython) {
            throw 'Python 3.12 or newer is required. Install Python or pass -Python with its executable path.'
        }
        $demoPython = $installedPython.Source
    }
}

$demoArguments = @('-B', '-X', 'utf8', '-m', 'enigma_demo', '--port', [string]$Port)
if ($OpenBrowser) { $demoArguments += '--open-browser' }
Push-Location -LiteralPath $PSScriptRoot
try {
    & $demoPython -B -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)'
    if ($LASTEXITCODE -ne 0) { throw 'This demo requires Python 3.12 or newer.' }
    & $demoPython @demoArguments
    $demoExitCode = $LASTEXITCODE
} finally {
    Pop-Location
}
exit $demoExitCode
