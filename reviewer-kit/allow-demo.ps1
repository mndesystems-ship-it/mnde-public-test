$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$KitRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ArtifactsRoot = Join-Path $KitRoot "artifacts"
$SidecarUrl = "http://127.0.0.1:8787"
$ReceiptPath = Join-Path $ArtifactsRoot "receipts\allow-receipt.json"
$ProofPath = Join-Path $ArtifactsRoot "proofs\determinism\allow-response.json"
$TesterId = if ([string]::IsNullOrWhiteSpace($env:MNDE_TESTER_ID)) { "TESTER-UNASSIGNED" } else { $env:MNDE_TESTER_ID }
$InstallationId = if ([string]::IsNullOrWhiteSpace($env:MNDE_INSTALLATION_ID)) { "INSTALLATION-UNASSIGNED" } else { $env:MNDE_INSTALLATION_ID }

function Fail([string]$Message) {
  Write-Host "[FAIL] $Message"
  exit 1
}

function Reviewer-Request {
  $toolCall = @{ tool = "read_status"; priority = 1 }
  return @{
    execution_request = @{
      request_id = "reviewer-kit-allow-read-status"
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
      release_request = @{ execution_id = "reviewer-kit-allow-read-status"; hold_state = "APPROVED"; already_consumed = $false }
      runtime_observation = @{ kill_switch_active = $false; actual_gpu_count = 1; actual_hours = 1; actual_total_cost_cents = 500 }
    }
    pricing_data = @{ gpu_hour_cents = 500 }
  }
}

try {
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ReceiptPath) | Out-Null
  $response = Invoke-RestMethod -Method Post -Uri "$SidecarUrl/v1/decisions" -Body ((Reviewer-Request) | ConvertTo-Json -Depth 40) -ContentType "application/json" -TimeoutSec 10
  if ($response.decision -ne "ALLOW") { Fail "expected ALLOW, got $($response.decision)" }
  if ($null -eq $response.receipt) { Fail "ALLOW receipt missing" }
  $response.receipt | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $ReceiptPath -Encoding UTF8
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ProofPath) | Out-Null
  $response | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $ProofPath -Encoding UTF8
  Write-Host "[ALLOW]"
  Write-Host "Receipt Stored"
} catch {
  Fail $_.Exception.Message
}
