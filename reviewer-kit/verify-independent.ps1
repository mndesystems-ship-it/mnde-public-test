param(
  [string]$ReceiptPath = $null
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$KitRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $KitRoot
$ArtifactsRoot = Join-Path $KitRoot "artifacts"

if ([string]::IsNullOrWhiteSpace($ReceiptPath)) {
  $ReceiptPath = Join-Path $ArtifactsRoot "receipts\allow-receipt.json"
}

function Fail([string]$Message) {
  Write-Host "[FAIL] $Message"
  Write-Host "FINAL VERDICT: FAILED"
  exit 1
}

function Stop-ReviewerSidecar {
  $pidPath = Join-Path $ArtifactsRoot "logs\sidecar.pid"
  if (-not (Test-Path -LiteralPath $pidPath)) { return }
  $pidText = (Get-Content -LiteralPath $pidPath -Raw).Trim()
  if ([string]::IsNullOrWhiteSpace($pidText)) { return }
  Stop-Process -Id ([int]$pidText) -Force -ErrorAction SilentlyContinue
}

function Test-SidecarReachable {
  try {
    Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:8787/healthz" -TimeoutSec 1 | Out-Null
    return $true
  } catch {
    return $false
  }
}

Push-Location $RepoRoot
try {
  Stop-ReviewerSidecar
  $reachable = Test-SidecarReachable
  Write-Host ("Sidecar Reachable: " + ($(if ($reachable) { "YES" } else { "NO" })))
  if ($reachable) { Fail "sidecar is still reachable" }
  if (-not (Test-Path -LiteralPath $ReceiptPath)) { Fail "receipt not found: $ReceiptPath" }

  $output = & node .\tools\verify-receipt.mjs $ReceiptPath 2>&1
  $text = $output -join "`n"
  $ok = $LASTEXITCODE -eq 0
  Write-Host ("Receipt Verification: " + ($(if ($ok) { "PASS" } else { "FAIL" })))
  Write-Host ("Replay Determinism: " + ($(if ($text -match "Replay Determinism: PASS") { "PASS" } else { "FAIL" })))
  if (-not $ok) { Fail $text }
  if ($text -notmatch "Replay Determinism: PASS") { Fail "offline replay determinism failed" }
  Write-Host "FINAL VERDICT: VERIFIED"
} finally {
  Pop-Location
}
