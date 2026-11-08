param(
    [Parameter(Position=0)]
    [string]$Command = "help",
    [string]$TARGET = "",
    [string]$Campaign = "lab-local"
)

$Python = "python"

switch ($Command) {
    "setup" {
        & $Python toolkit/scripts/init_dirs.py
        & $Python -m pip install -q -r backend/requirements.txt
    }
    "scan" {
        if (-not $TARGET) {
            Write-Error "TARGET is required. Example: .\make.ps1 scan -TARGET 192.168.56.101"
            exit 1
        }
        & $Python toolkit/scripts/targets.py scan --target $TARGET --campaign $Campaign
    }
    "test" {
        & $Python -m pytest backend/tests -v
    }
    "dev" {
        & uvicorn backend.app.main:app --reload --port 8000
    }
    default {
        Write-Host "AI-Pentest Copilot - PowerShell Helper"
        Write-Host "  .\make.ps1 setup"
        Write-Host "  .\make.ps1 scan -TARGET <target>"
        Write-Host "  .\make.ps1 test"
        Write-Host "  .\make.ps1 dev"
    }
}
