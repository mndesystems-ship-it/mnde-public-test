$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$ExePath = Join-Path $RepoRoot "installer\MNDe-Execution-Control.exe"
$ArtifactsRoot = Join-Path $RepoRoot "reviewer-kit\artifacts"
$LogRoot = Join-Path $ArtifactsRoot "logs"
$SidecarUrl = "http://127.0.0.1:8787"
$SidecarOut = Join-Path $LogRoot "desktop-smoke-sidecar.stdout.log"
$SidecarErr = Join-Path $LogRoot "desktop-smoke-sidecar.stderr.log"
$ReceiptLog = Join-Path $LogRoot "desktop-smoke-receipts.jsonl"
$AuthLog = Join-Path $LogRoot "desktop-smoke-auth-audit.jsonl"
$ProofPath = Join-Path $ArtifactsRoot "proofs\security\desktop-smoke.json"
$sidecar = $null
$app = $null

function Fail([string]$Message) {
  Write-Host "[FAIL] $Message"
  Write-Host ""
  Write-Host "DESKTOP SMOKE: FAIL"
  exit 1
}

function Wait-Ready {
  $deadline = (Get-Date).AddSeconds(20)
  while ((Get-Date) -lt $deadline) {
    try {
      $ready = Invoke-RestMethod -Method Get -Uri "$SidecarUrl/readyz" -TimeoutSec 2
      if ($ready.ok -eq $true) { return }
    } catch {
      Start-Sleep -Milliseconds 250
    }
  }
  Fail "sidecar readiness timed out"
}

function Post-Json([string]$Path, [object]$Body) {
  $json = $Body | ConvertTo-Json -Depth 40
  return Invoke-RestMethod -Method Post -Uri "$SidecarUrl$Path" -Body $json -ContentType "application/json" -TimeoutSec 10
}

function ReviewerRequest([string]$Id, [string]$Tool) {
  $toolCall = @{ tool = $Tool; priority = 1 }
  $testerId = if ([string]::IsNullOrWhiteSpace($env:MNDE_TESTER_ID)) { "TESTER-UNASSIGNED" } else { $env:MNDE_TESTER_ID }
  $installationId = if ([string]::IsNullOrWhiteSpace($env:MNDE_INSTALLATION_ID)) { "INSTALLATION-UNASSIGNED" } else { $env:MNDE_INSTALLATION_ID }
  return @{
    execution_request = @{
      request_id = $Id
      submitted_region = "us-west-2"
      actor = @{ user_id = $testerId }
      parameters = @{ tester_id = $testerId; installation_id = $installationId }
      resources = @{ gpu_type = "a10g"; gpu_count = 1; hours = 1 }
      execution = @{ auto_scale = $false; max_scale_multiplier = 1; retry_on_fail = $false; max_retries = 0 }
      tool_calls = @($toolCall)
      orbit_intent = @{
        orbit_version = "2.0"
        action = "execute"
        boundary = "desktop-smoke"
        payload = @{ tool_calls = @($toolCall) }
        lifecycle_state = "ARMED"
        signatures = @(@{ alg = "hmac-sha256"; sig = "desktop-smoke" })
      }
      release_request = @{ execution_id = $Id; hold_state = "APPROVED"; already_consumed = $false }
      runtime_observation = @{ kill_switch_active = $false; actual_gpu_count = 1; actual_hours = 1; actual_total_cost_cents = 500 }
    }
    pricing_data = @{ gpu_hour_cents = 500 }
  }
}

try {
  if (-not (Test-Path -LiteralPath $ExePath)) { Fail "desktop executable missing" }
  New-Item -ItemType Directory -Force -Path $LogRoot | Out-Null
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ProofPath) | Out-Null
  Push-Location $RepoRoot
  try {
    & node ".\scripts\bootstrap_dev_receipt_keys.mjs" | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "receipt signing key bootstrap failed" }
  } finally {
    Pop-Location
  }

  $env:MNDE_RECEIPT_LOG = $ReceiptLog
  $env:MNDE_AUTH_AUDIT_LOG = $AuthLog
  $env:MNDE_RECEIPT_DURABILITY_MODE = "strict_audit"
  $env:MNDE_INLINE_REFUSAL_RECEIPTS = "1"
  $env:MNDE_WORKER_POOL_SIZE = "1"
  $env:MNDE_WORKER_QUEUE_MAX_DEPTH = "16"

  $sidecar = Start-Process -FilePath "node" -ArgumentList "mnde-local-sidecar.mjs" -WorkingDirectory $RepoRoot -RedirectStandardOutput $SidecarOut -RedirectStandardError $SidecarErr -PassThru -WindowStyle Hidden
  Wait-Ready

  $app = Start-Process -FilePath $ExePath -PassThru
  Start-Sleep -Seconds 3
  if ($app.HasExited) { Fail "desktop app exited during smoke test" }

  $health = Invoke-RestMethod -Method Get -Uri "$SidecarUrl/healthz" -TimeoutSec 5
  if ($health.ok -ne $true) { Fail "healthz failed" }
  $decision = Post-Json "/v1/decisions" (ReviewerRequest "desktop-smoke-read-status" "read_status")
  if ($decision.decision -ne "ALLOW") { Fail "sidecar decision failed" }
  $receipts = Invoke-RestMethod -Method Get -Uri "$SidecarUrl/receipts/recent?limit=10" -TimeoutSec 5
  if ($null -eq $receipts) { Fail "receipt list failed" }
  $replay = Post-Json "/replay" @{ receipt = $decision.receipt }
  if ($replay.drift -ne $false) { Fail "replay failed" }
  $policy = Invoke-RestMethod -Method Get -Uri "$SidecarUrl/policy/current" -TimeoutSec 5
  if (-not $policy.policy_hash) { Fail "policy view failed" }
  $metrics = Invoke-RestMethod -Method Get -Uri "$SidecarUrl/metrics" -TimeoutSec 5
  if (-not $metrics) { Fail "logs/metrics view failed" }

  @{
    checked_at = (Get-Date).ToUniversalTime().ToString("o")
    executable_exists = $true
    app_launches = $true
    process_responds = (-not $app.HasExited)
    sidecar_connection = "PASS"
    receipt_list_loads = "PASS"
    replay_reachable = "PASS"
    policy_view_reachable = "PASS"
    logs_view_reachable = "PASS"
    verdict = "PASS"
  } | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $ProofPath -Encoding UTF8

  Write-Host "Desktop executable: PASS"
  Write-Host "App launches: PASS"
  Write-Host "Process responds: PASS"
  Write-Host "Sidecar connection: PASS"
  Write-Host "Receipt list: PASS"
  Write-Host "Replay: PASS"
  Write-Host "Policy view: PASS"
  Write-Host "Logs view: PASS"
  Write-Host ""
  Write-Host "DESKTOP SMOKE: PASS"
} finally {
  if ($null -ne $app -and -not $app.HasExited) { Stop-Process -Id $app.Id -Force -ErrorAction SilentlyContinue }
  if ($null -ne $sidecar -and -not $sidecar.HasExited) { Stop-Process -Id $sidecar.Id -Force -ErrorAction SilentlyContinue }
}
