$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$KitRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $KitRoot
$ArtifactsRoot = Join-Path $KitRoot "artifacts"

function Fail([string]$Message) {
  Write-Host "[FAIL] $Message"
  exit 1
}

function Assert-True([bool]$Condition, [string]$Message) {
  if (-not $Condition) { Fail $Message }
}

function Read-Json([string]$Path) {
  return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Test-SidecarReachable {
  try {
    Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:8787/healthz" -TimeoutSec 1 | Out-Null
    return $true
  } catch {
    return $false
  }
}

function Test-ProcessRunning([string]$PidPath) {
  if (-not (Test-Path -LiteralPath $PidPath)) { return $false }
  $pidText = (Get-Content -LiteralPath $PidPath -Raw).Trim()
  if ([string]::IsNullOrWhiteSpace($pidText)) { return $false }
  return $null -ne (Get-Process -Id ([int]$pidText) -ErrorAction SilentlyContinue)
}

function Assert-NoGeneratedOutsideArtifacts {
  foreach ($dir in @("logs", "proofs", "receipts")) {
    $path = Join-Path $KitRoot $dir
    if (-not (Test-Path -LiteralPath $path)) { continue }
    $files = Get-ChildItem -LiteralPath $path -Recurse -File | Where-Object { $_.Name -ne ".gitkeep" }
    Assert-True (($files | Measure-Object).Count -eq 0) "$dir should not contain generated reviewer artifacts"
  }
}

Push-Location $RepoRoot
try {
  if (Test-Path -LiteralPath $ArtifactsRoot) {
    Get-ChildItem -LiteralPath $ArtifactsRoot -Force | Where-Object { $_.Name -ne ".gitkeep" } | Remove-Item -Recurse -Force
  } else {
    New-Item -ItemType Directory -Force -Path $ArtifactsRoot | Out-Null
  }
  if (-not (Test-Path -LiteralPath (Join-Path $ArtifactsRoot ".gitkeep"))) {
    Set-Content -LiteralPath (Join-Path $ArtifactsRoot ".gitkeep") -Value "" -Encoding ASCII
  }

  $output = & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $KitRoot "run-review.ps1") -Full 2>&1
  if ($LASTEXITCODE -ne 0) { Fail ($output -join "`n") }
  $text = $output -join "`n"

  Assert-True ($text -match "\[ALLOW\]\s+Receipt Stored") "ALLOW path did not pass"
  Assert-True ($text -match "\[REFUSE\]\s+Receipt Stored") "REFUSE path did not pass"
  Assert-True ($text -match "SIGNATURE: PASS\s+SCHEMA: PASS\s+REPLAY: PASS\s+HASHES: PASS") "receipt verification did not pass"
  Assert-True ($text -match "Replay Verification: PASS") "replay verification summary did not pass"
  Assert-True ($text -match "FINAL VERDICT: PASS") "final verdict did not pass"

  $expectedArtifacts = @(
    "receipts\allow-receipt.json",
    "receipts\refuse-receipt.json",
    "proofs\determinism\allow-response.json",
    "proofs\security\refuse-response.json",
    "proofs\security\environment-verification.json",
    "proofs\replay\allow-receipt-verification.json",
    "proofs\replay\refuse-receipt-verification.json",
    "logs\sidecar-receipts.jsonl",
    "logs\sidecar.pid"
  )
  foreach ($artifact in $expectedArtifacts) {
    Assert-True (Test-Path -LiteralPath (Join-Path $ArtifactsRoot $artifact)) "$artifact should be generated under reviewer-kit\artifacts"
  }

  $allowReceipt = Read-Json (Join-Path $ArtifactsRoot "receipts\allow-receipt.json")
  $refuseReceipt = Read-Json (Join-Path $ArtifactsRoot "receipts\refuse-receipt.json")
  Assert-True ($allowReceipt.decision_output.decision -eq "ALLOW") "ALLOW receipt decision mismatch"
  Assert-True ($refuseReceipt.decision_output.decision -eq "REFUSE") "REFUSE receipt decision mismatch"

  $allowReplay = Read-Json (Join-Path $ArtifactsRoot "proofs\replay\allow-receipt-verification.json")
  $refuseReplay = Read-Json (Join-Path $ArtifactsRoot "proofs\replay\refuse-receipt-verification.json")
  Assert-True ($allowReplay.verdict -eq "PASS") "ALLOW replay proof did not pass"
  Assert-True ($refuseReplay.verdict -eq "PASS") "REFUSE replay proof did not pass"
  Assert-True ($allowReplay.verify.status -eq "VALID") "ALLOW signature verification did not pass"
  Assert-True ($refuseReplay.verify.status -eq "VALID") "REFUSE signature verification did not pass"
  Assert-True ($allowReplay.replay.drift -eq $false) "ALLOW replay drift detected"
  Assert-True ($refuseReplay.replay.drift -eq $false) "REFUSE replay drift detected"

  Assert-True (-not (Test-ProcessRunning (Join-Path $ArtifactsRoot "logs\sidecar.pid"))) "sidecar process should stop after reviewer-kit run"
  Assert-True (-not (Test-SidecarReachable)) "sidecar port should close after reviewer-kit run"
  Assert-NoGeneratedOutsideArtifacts

  Write-Host "PASS reviewer-kit tests"
} finally {
  Pop-Location
}
