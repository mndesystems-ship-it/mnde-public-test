$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$KeyDir = Join-Path $RepoRoot "shared\receipt_keys"
$PrivateKey = Join-Path $KeyDir "receipt_signing_private.pem"
$PublicKey = Join-Path $KeyDir "receipt_signing_public.pem"
$BackupDir = Join-Path ([System.IO.Path]::GetTempPath()) ("mnde-receipt-keys-backup-{0}" -f ([guid]::NewGuid().ToString("N")))

function Restore-Keys {
  if (Test-Path -LiteralPath $KeyDir) {
    Remove-Item -LiteralPath $KeyDir -Recurse -Force -ErrorAction SilentlyContinue
  }
  if (Test-Path -LiteralPath $BackupDir) {
    Move-Item -LiteralPath $BackupDir -Destination $KeyDir -Force
  }
}

function Assert-True([bool]$Condition, [string]$Message) {
  if (-not $Condition) { throw $Message }
}

try {
  if (Test-Path -LiteralPath $KeyDir) {
    Move-Item -LiteralPath $KeyDir -Destination $BackupDir -Force
  }

  Push-Location $RepoRoot
  try {
    & node ".\scripts\setup.mjs" "TESTER-001" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "setup failed" }
    Assert-True (Test-Path -LiteralPath $PrivateKey) "private signing key was not created"
    Assert-True (Test-Path -LiteralPath $PublicKey) "public signing key was not created"

    & node --input-type=module -e "import { signReceiptPayload } from './shared/receipt-signing.ts'; if (!signReceiptPayload('{`"ok`":true}')) process.exit(1);"
    if ($LASTEXITCODE -ne 0) { throw "generated signing keys were not usable" }

    Remove-Item -LiteralPath $KeyDir -Recurse -Force
    $out = Join-Path ([System.IO.Path]::GetTempPath()) ("mnde-missing-keys-out-{0}.log" -f ([guid]::NewGuid().ToString("N")))
    $err = Join-Path ([System.IO.Path]::GetTempPath()) ("mnde-missing-keys-err-{0}.log" -f ([guid]::NewGuid().ToString("N")))
    $process = Start-Process -FilePath "node" -ArgumentList "mnde-local-sidecar.mjs" -WorkingDirectory $RepoRoot -RedirectStandardOutput $out -RedirectStandardError $err -PassThru -WindowStyle Hidden
    if (-not $process.WaitForExit(5000)) {
      Stop-Process -Id $process.Id -Force
      throw "sidecar kept running with missing signing keys"
    }
    Assert-True ($process.ExitCode -ne 0) "sidecar should exit nonzero when signing keys are missing"
    $stderr = if (Test-Path -LiteralPath $err) { Get-Content -LiteralPath $err -Raw } else { "" }
    Assert-True ($stderr -match "ERR_RECEIPT_SIGNING_KEYS_MISSING") "missing-key error was not clear"
  } finally {
    Pop-Location
  }

  Write-Host "PASS fresh setup and missing-key handling tests"
} finally {
  Restore-Keys
}
