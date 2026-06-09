$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$KitRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ArtifactsRoot = Join-Path $KitRoot "artifacts"
$SidecarUrl = "http://127.0.0.1:8787"
$ProofPath = Join-Path $ArtifactsRoot "proofs\security\environment-verification.json"
$TesterId = if ([string]::IsNullOrWhiteSpace($env:MNDE_TESTER_ID)) { "TESTER-UNASSIGNED" } else { $env:MNDE_TESTER_ID }
$InstallationId = if ([string]::IsNullOrWhiteSpace($env:MNDE_INSTALLATION_ID)) { "INSTALLATION-UNASSIGNED" } else { $env:MNDE_INSTALLATION_ID }

function Fail([string]$Message) {
  Write-Host "[FAIL] $Message"
  Write-Host ""
  Write-Host "VERDICT: FAIL"
  exit 1
}

function Reviewer-Request([string]$Id, [string]$Tool, [object]$Parameters = $null) {
  $toolCall = @{ tool = $Tool; priority = 1 }
  if ($null -ne $Parameters) { $toolCall.parameters = $Parameters }
  return @{
    execution_request = @{
      request_id = $Id
      submitted_region = "us-west-2"
      actor = @{ user_id = $TesterId }
      parameters = @{ tester_id = $TesterId; installation_id = $InstallationId }
      resources = @{ gpu_type = "a10g"; gpu_count = 1; hours = 1 }
      execution = @{ auto_scale = $false; max_scale_multiplier = 1; retry_on_fail = $false; max_retries = 0 }
      tool_calls = @($toolCall)
      orbit_intent = @{
        orbit_version = "2.0"
        action = "execute"
        boundary = "reviewer-kit"
        payload = @{ tool_calls = @($toolCall) }
        lifecycle_state = "ARMED"
        signatures = @(@{ alg = "hmac-sha256"; sig = "reviewer-kit" })
      }
      release_request = @{ execution_id = $Id; hold_state = "APPROVED"; already_consumed = $false }
      runtime_observation = @{ kill_switch_active = $false; actual_gpu_count = 1; actual_hours = 1; actual_total_cost_cents = 500 }
    }
    pricing_data = @{ gpu_hour_cents = 500 }
  }
}

function Post-Json([string]$Path, [object]$Body) {
  $json = $Body | ConvertTo-Json -Depth 40
  return Invoke-RestMethod -Method Post -Uri "$SidecarUrl$Path" -Body $json -ContentType "application/json" -TimeoutSec 10
}

function Remove-ReceiptProbes([string]$ReceiptDir) {
  if (-not (Test-Path -LiteralPath $ReceiptDir)) { return }
  Get-ChildItem -LiteralPath $ReceiptDir -Filter "write-probe-*.tmp" -File -ErrorAction SilentlyContinue | ForEach-Object {
    try {
      $_.Attributes = "Normal"
      Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop
    } catch {
      # Probe cleanup is best-effort; receipt writes below remain the authoritative storage check.
    }
  }
}

try {
  $health = Invoke-RestMethod -Method Get -Uri "$SidecarUrl/healthz" -TimeoutSec 5
  if ($health.ok -ne $true) { Fail "healthz" }
  Write-Host "[PASS] healthz"

  $ready = Invoke-RestMethod -Method Get -Uri "$SidecarUrl/readyz" -TimeoutSec 5
  if ($ready.ok -ne $true) { Fail "readyz" }
  Write-Host "[PASS] readyz"

  $signer = Post-Json "/v1/decisions" (Reviewer-Request "reviewer-kit-signer-check" "read_status")
  if ($signer.decision -ne "ALLOW" -or -not $signer.receipt.signature.value -or -not $signer.receipt.verifiable_signature.value) { Fail "signer" }
  Write-Host "[PASS] signer"

  $replay = Post-Json "/replay" @{ receipt = $signer.receipt }
  if ($replay.drift -ne $false) { Fail "replay" }
  Write-Host "[PASS] replay"

  $receiptDir = Join-Path $ArtifactsRoot "receipts"
  New-Item -ItemType Directory -Force -Path $receiptDir | Out-Null
  Remove-ReceiptProbes $receiptDir
  $probe = Join-Path $receiptDir ("write-probe-{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  Set-Content -LiteralPath $probe -Value "probe" -Encoding ASCII
  if (-not (Test-Path -LiteralPath $probe)) { Fail "receipt storage" }
  Remove-ReceiptProbes $receiptDir
  Write-Host "[PASS] receipt storage"

  $proof = @{
    checked_at = (Get-Date).ToUniversalTime().ToString("o")
    healthz = $health
    readyz = $ready
    signer_decision_hash = $signer.decision_hash
    replay = $replay
    verdict = "PASS"
  }
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ProofPath) | Out-Null
  $proof | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $ProofPath -Encoding UTF8

  Write-Host ""
  Write-Host "VERDICT: PASS"
} catch {
  Fail $_.Exception.Message
}
