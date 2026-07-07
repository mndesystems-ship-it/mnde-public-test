param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string]$ReceiptPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$KitRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ArtifactsRoot = Join-Path $KitRoot "artifacts"
$SidecarUrl = "http://127.0.0.1:8787"
$AuthPrivateKey = Join-Path $ArtifactsRoot "proofs\security\reviewer-auth-private.jwk"

function Fail([string]$Message) {
  Write-Host "[FAIL] $Message"
  Write-Host ""
  Write-Host "VERDICT: FAIL"
  exit 1
}

function New-AuthorityAssertion([string]$Capability) {
  if (-not (Test-Path -LiteralPath $AuthPrivateKey)) { Fail "reviewer authority private key missing; run run-review.ps1 first" }
  $code = @'
import { createPrivateKey, randomBytes, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
const keyPath = process.argv[1];
const capability = process.argv[2];
const privateKey = createPrivateKey({ key: JSON.parse(readFileSync(keyPath, 'utf8')), format: 'jwk' });
const now = Date.now();
const payload = {
  issuer: 'mnde-desktop',
  audience: 'mnde-sidecar',
  subject: 'external-reviewer',
  display_name: 'External Reviewer',
  roles: ['AUDITOR'],
  capabilities: [capability],
  issued_at: now,
  expires_at: now + 60000,
  nonce: `nonce_${randomBytes(24).toString('base64url')}`,
  session_id: `session_${randomBytes(24).toString('base64url')}`
};
const payloadPart = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
const signaturePart = sign(null, Buffer.from(payloadPart, 'utf8'), privateKey).toString('base64url');
process.stdout.write(`${payloadPart}.${signaturePart}`);
'@
  $assertion = & node --input-type=module -e $code $AuthPrivateKey $Capability
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($assertion)) { Fail "authority assertion generation failed" }
  return $assertion.Trim()
}

function Post-Json([string]$Path, [object]$Body, [hashtable]$Headers = @{}) {
  $json = $Body | ConvertTo-Json -Depth 60
  return Invoke-RestMethod -Method Post -Uri "$SidecarUrl$Path" -Body $json -ContentType "application/json" -Headers $Headers -TimeoutSec 10
}

function Convert-ToRepoRelativePath([string]$Path) {
  $repoRoot = Split-Path -Parent $KitRoot
  $fullPath = [System.IO.Path]::GetFullPath($Path)
  $root = [System.IO.Path]::GetFullPath($repoRoot)
  if (-not $root.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
    $root = "$root$([System.IO.Path]::DirectorySeparatorChar)"
  }
  if ($fullPath.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
    return $fullPath.Substring($root.Length).Replace("\", "/")
  }
  return [System.IO.Path]::GetFileName($fullPath)
}

function Test-ReceiptSchema([object]$Receipt) {
  $isPe = $Receipt.schema_version -eq "mnde.pe.receipt.v1"
  if (-not $isPe -and $Receipt.schema_version -ne "ecs.receipt.v2") { return $false }
  if ([string]::IsNullOrWhiteSpace($Receipt.request_hash)) { return $false }
  if ([string]::IsNullOrWhiteSpace($Receipt.canonical_request)) { return $false }
  if ($null -eq $Receipt.decision_output) { return $false }
  if ($Receipt.decision_output.decision -notin @("ALLOW", "REFUSE")) { return $false }
  if ([string]::IsNullOrWhiteSpace($Receipt.decision_output.decision_hash)) { return $false }
  if ($isPe) {
    if ([string]::IsNullOrWhiteSpace($Receipt.canonical_policy)) { return $false }
    if ($null -eq $Receipt.verifiable_signature) { return $false }
  } elseif ($null -eq $Receipt.signature -and $null -eq $Receipt.verifiable_signature) {
    return $false
  }
  return $true
}

function Get-Sha256Hex([string]$Text) {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $hashBytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))
    return -join ($hashBytes | ForEach-Object { $_.ToString("x2") })
  } finally {
    $sha.Dispose()
  }
}

function Test-PeHashes([object]$Receipt) {
  # Policy-engine hashes are prefixed with the algorithm ("sha256:<hex>").
  if (("sha256:" + (Get-Sha256Hex ([string]$Receipt.canonical_request))) -ne $Receipt.request_hash) { return $false }
  if ($Receipt.decision_output.request_hash -ne $Receipt.request_hash) { return $false }
  if ([string]::IsNullOrWhiteSpace($Receipt.decision_output.decision_hash)) { return $false }
  return $true
}

function Test-Hashes([object]$Receipt, [object]$Replay) {
  $requestHash = Get-Sha256Hex ([string]$Receipt.canonical_request)
  if ($requestHash -ne $Receipt.request_hash) { return $false }
  if ($Receipt.decision_output.request_hash -and $Receipt.decision_output.request_hash -ne $Receipt.request_hash) { return $false }
  if ($Replay.original.decision_hash -ne $Receipt.decision_output.decision_hash) { return $false }
  if ($Replay.replayed.decision_hash -ne $Receipt.decision_output.decision_hash) { return $false }
  return $true
}

try {
  $resolved = Resolve-Path -LiteralPath $ReceiptPath
  $receipt = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json

  if ($receipt.schema_version -eq "mnde.pe.receipt.v1") {
    # Policy-engine receipts verify (and deterministically replay) OFFLINE via
    # the unified verifier: it checks the signature against the local authority
    # and re-evaluates the engine over the canonical request and policy, failing
    # on any decision drift. No sidecar endpoint is involved.
    $RepoRoot = Split-Path -Parent $KitRoot
    Push-Location $RepoRoot
    try {
      & node .\tools\verify.mjs $resolved.Path | Out-Null
      $offlineOk = $LASTEXITCODE -eq 0
    } finally {
      Pop-Location
    }
    if (-not $offlineOk) { Fail "offline signature verification failed" }
    Write-Host "SIGNATURE: PASS"

    if (-not (Test-ReceiptSchema $receipt)) { Fail "receipt schema invalid" }
    Write-Host "SCHEMA: PASS"

    Write-Host "REPLAY: PASS"

    if (-not (Test-PeHashes $receipt)) { Fail "hash check failed" }
    Write-Host "HASHES: PASS"

    $verify = @{ status = "VALID"; method = "offline-unified-verifier" }
    $replay = @{ drift = $false; replayed_offline = $true; verifier = "tools/verify.mjs" }
  } else {
    $verifyHeaders = @{ "x-mnde-authority-assertion" = (New-AuthorityAssertion "verify_receipts") }
    $verify = Post-Json "/verify" @{ receipt = $receipt } $verifyHeaders
    if ($verify.status -ne "VALID") { Fail "signature verification failed: $($verify.reason)" }
    Write-Host "SIGNATURE: PASS"

    if (-not (Test-ReceiptSchema $receipt)) { Fail "receipt schema invalid" }
    Write-Host "SCHEMA: PASS"

    $replay = Post-Json "/replay" @{ receipt = $receipt }
    if ($replay.drift -ne $false) { Fail "replay drift detected" }
    Write-Host "REPLAY: PASS"

    if (-not (Test-Hashes $receipt $replay)) { Fail "hash check failed" }
    Write-Host "HASHES: PASS"
  }

  $name = [System.IO.Path]::GetFileNameWithoutExtension($resolved.Path)
  $proof = @{
    checked_at = (Get-Date).ToUniversalTime().ToString("o")
    receipt_path = (Convert-ToRepoRelativePath $resolved.Path)
    verify = $verify
    replay = $replay
    verdict = "PASS"
  }
  $proofPath = Join-Path $ArtifactsRoot "proofs\replay\$name-verification.json"
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $proofPath) | Out-Null
  $proof | ConvertTo-Json -Depth 60 | Set-Content -LiteralPath $proofPath -Encoding UTF8

  Write-Host ""
  Write-Host "VERDICT: PASS"
} catch {
  Fail $_.Exception.Message
}
