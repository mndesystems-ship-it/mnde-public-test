param(
  [switch]$Full
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$KitRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $KitRoot
$ArtifactsRoot = Join-Path $KitRoot "artifacts"
$SidecarUrl = "http://127.0.0.1:8787"
$PidFile = Join-Path $ArtifactsRoot "logs\sidecar.pid"
$AuthPrivateKey = Join-Path $ArtifactsRoot "proofs\security\reviewer-auth-private.jwk"
$AuthPublicKey = Join-Path $ArtifactsRoot "proofs\security\reviewer-auth-public.b64url"
$ReceiptLog = Join-Path $ArtifactsRoot "logs\sidecar-receipts.jsonl"
$NonceCache = Join-Path $ArtifactsRoot "logs\auth-nonce-cache.json"
$OutLog = Join-Path $ArtifactsRoot "logs\sidecar.stdout.log"
$ErrLog = Join-Path $ArtifactsRoot "logs\sidecar.stderr.log"
$script:SidecarStarted = $false

function Repair-PathEnvironment {
  $processEnv = [System.Environment]::GetEnvironmentVariables("Process")
  $pathValue = $null
  $pathKeys = @()
  foreach ($key in $processEnv.Keys) {
    if ([string]::Equals([string]$key, "PATH", [System.StringComparison]::OrdinalIgnoreCase)) {
      $pathKeys += [string]$key
      if ([string]::IsNullOrEmpty($pathValue)) {
        $pathValue = [string]$processEnv[$key]
      }
    }
  }
  foreach ($key in $pathKeys) {
    [System.Environment]::SetEnvironmentVariable($key, $null, "Process")
  }
  if (-not [string]::IsNullOrEmpty($pathValue)) {
    [System.Environment]::SetEnvironmentVariable("Path", $pathValue, "Process")
  }
}

function Initialize-TesterIdentity {
  $identityJson = & node (Join-Path $RepoRoot "scripts\tester-id.mjs") --json
  if ($LASTEXITCODE -ne 0) { Fail "tester identity initialization failed" }
  $identity = $identityJson | ConvertFrom-Json
  $env:MNDE_TESTER_ID = $identity.tester_id
  $env:MNDE_INSTALLATION_ID = $identity.installation_id
  $identityPath = Join-Path $ArtifactsRoot "logs\tester-identity.json"
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $identityPath) | Out-Null
  $identity | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $identityPath -Encoding UTF8
}

function Fail([string]$Message) {
  Write-Host "[FAIL] $Message"
  Write-Host ""
  Write-Host "VERDICT: FAIL"
  exit 1
}

function Ensure-Dirs {
  foreach ($path in @(
    "logs",
    "receipts",
    "proofs\determinism",
    "proofs\replay",
    "proofs\parity",
    "proofs\security",
    "proofs\throughput"
  )) {
    New-Item -ItemType Directory -Force -Path (Join-Path $ArtifactsRoot $path) | Out-Null
  }
}

function Invoke-NodeJson([string]$Code) {
  $output = & node --input-type=module -e $Code
  if ($LASTEXITCODE -ne 0) { Fail "node helper failed" }
  return ($output | ConvertFrom-Json)
}

function Initialize-ReviewerAuthority {
  if ((Test-Path -LiteralPath $AuthPrivateKey) -and (Test-Path -LiteralPath $AuthPublicKey)) { return }
  $code = @"
import { generateKeyPairSync } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
const privatePath = process.argv[1];
const publicPath = process.argv[2];
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
mkdirSync(dirname(privatePath), { recursive: true });
writeFileSync(privatePath, JSON.stringify(privateKey.export({ format: 'jwk' }), null, 2) + '\n');
writeFileSync(publicPath, publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64url') + '\n');
"@
  & node --input-type=module -e $code $AuthPrivateKey $AuthPublicKey
  if ($LASTEXITCODE -ne 0) { Fail "authority key generation failed" }
}

function Initialize-ReceiptSigningKeys {
  $privateKey = Join-Path $RepoRoot "shared\receipt_keys\receipt_signing_private.pem"
  $publicKey = Join-Path $RepoRoot "shared\receipt_keys\receipt_signing_public.pem"
  if ((Test-Path -LiteralPath $privateKey) -and (Test-Path -LiteralPath $publicKey)) { return }
  Push-Location $RepoRoot
  try {
    & node ".\scripts\bootstrap_dev_receipt_keys.mjs" | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "receipt signing key bootstrap failed" }
  } finally {
    Pop-Location
  }
}

function Assert-Port-Free {
  try {
    Invoke-RestMethod -Method Get -Uri "$SidecarUrl/healthz" -TimeoutSec 1 | Out-Null
    Fail "sidecar port 8787 is already in use"
  } catch {
    return
  }
}

function Start-Sidecar {
  Assert-Port-Free
  Repair-PathEnvironment
  Set-Content -LiteralPath $OutLog -Value "" -Encoding ASCII
  Set-Content -LiteralPath $ErrLog -Value "" -Encoding ASCII
  $publicKey = (Get-Content -LiteralPath $AuthPublicKey -Raw).Trim()
  $env:MNDE_AUTH_ASSERTION_PUBLIC_KEY_B64 = $publicKey
  $env:MNDE_AUTH_NONCE_CACHE = $NonceCache
  $env:MNDE_RECEIPT_LOG = $ReceiptLog
  $env:MNDE_RECEIPT_HMAC_SECRET = "reviewer-kit-hmac-secret-000000000000000001"
  $env:MNDE_RECEIPT_HMAC_KEY_ID = "reviewer-kit-hmac-key"
  $env:MNDE_INLINE_REFUSAL_RECEIPTS = "1"
  $env:MNDE_RECEIPT_DURABILITY_MODE = "strict_audit"
  $env:MNDE_WORKER_POOL_SIZE = "1"
  $env:MNDE_WORKER_QUEUE_MAX_DEPTH = "16"
  $env:MNDE_AUTH_AUDIT_LOG = Join-Path $ArtifactsRoot "logs\auth-audit.jsonl"
  $process = Start-Process -FilePath "node" -ArgumentList "mnde-local-sidecar.mjs" -WorkingDirectory $RepoRoot -RedirectStandardOutput $OutLog -RedirectStandardError $ErrLog -PassThru -WindowStyle Hidden
  $script:SidecarStarted = $true
  Set-Content -LiteralPath $PidFile -Value ([string]$process.Id) -Encoding ASCII
}

function Stop-Sidecar {
  if (-not (Test-Path -LiteralPath $PidFile)) { return }
  $pidText = (Get-Content -LiteralPath $PidFile -Raw).Trim()
  if ([string]::IsNullOrWhiteSpace($pidText)) { return }
  $process = Get-Process -Id ([int]$pidText) -ErrorAction SilentlyContinue
  if ($null -ne $process) {
    Stop-Process -Id $process.Id -Force
  }
  Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
  $script:SidecarStarted = $false
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

function Run-FullReview {
  & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $KitRoot "verify-review.ps1")
  if ($LASTEXITCODE -ne 0) { throw "environment verification failed" }
  & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $KitRoot "allow-demo.ps1")
  if ($LASTEXITCODE -ne 0) { throw "ALLOW demo failed" }
  & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $KitRoot "refuse-demo.ps1")
  if ($LASTEXITCODE -ne 0) { throw "REFUSE demo failed" }
  & node (Join-Path $RepoRoot "scripts\hostile-input-proof.mjs")
  if ($LASTEXITCODE -ne 0) { throw "hostile input proof failed" }
  & node (Join-Path $RepoRoot "scripts\executor-blocked-demo.mjs")
  if ($LASTEXITCODE -ne 0) { throw "executor blocked demo failed" }
  & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $KitRoot "verify-receipt.ps1") (Join-Path $ArtifactsRoot "receipts\allow-receipt.json")
  if ($LASTEXITCODE -ne 0) { throw "ALLOW receipt verification failed" }
  & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $KitRoot "verify-receipt.ps1") (Join-Path $ArtifactsRoot "receipts\refuse-receipt.json")
  if ($LASTEXITCODE -ne 0) { throw "REFUSE receipt verification failed" }

  Write-Host "========================================"
  Write-Host "MNDe External Review Complete"
  Write-Host "========================================"
  Write-Host ""
  Write-Host "Environment: PASS"
  Write-Host "ALLOW: PASS"
  Write-Host "REFUSE: PASS"
  Write-Host "Receipt Verification: PASS"
  Write-Host "Replay Verification: PASS"
  Write-Host "Hostile Inputs: PASS"
  Write-Host "Executor Blocked: PASS"
  Write-Host ""
  Write-Host "FINAL VERDICT: PASS"
  Write-Host ""
  Write-Host "Artifacts:"
  Write-Host "reviewer-kit/artifacts/receipts/allow-receipt.json"
  Write-Host "reviewer-kit/artifacts/receipts/refuse-receipt.json"
  Write-Host "reviewer-kit/artifacts/proofs/security/environment-verification.json"
  Write-Host "reviewer-kit/artifacts/proofs/determinism/allow-response.json"
  Write-Host "reviewer-kit/artifacts/proofs/security/refuse-response.json"
  Write-Host "reviewer-kit/artifacts/proofs/replay/allow-receipt-verification.json"
  Write-Host "reviewer-kit/artifacts/proofs/replay/refuse-receipt-verification.json"
  Write-Host "reviewer-kit/artifacts/proofs/security/hostile-inputs.json"
  Write-Host "reviewer-kit/artifacts/proofs/security/executor-blocked-before-execution.json"
}

try {
  Ensure-Dirs
  Initialize-TesterIdentity
  Initialize-ReviewerAuthority
  Initialize-ReceiptSigningKeys
  Start-Sidecar
  Wait-Ready
  Write-Host "MNDe Reviewer Session Ready"
  if ($Full) {
    try {
      Run-FullReview
    } finally {
      Stop-Sidecar
    }
  }
} catch {
  if ($script:SidecarStarted) { Stop-Sidecar }
  Fail $_.Exception.Message
}
