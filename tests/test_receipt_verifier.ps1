$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Verifier = Join-Path $Root "tools\verify-receipt.mjs"
$Fixtures = Join-Path $Root "tests\receipts"

function Run-Case([string]$Name, [int]$ExpectedExit) {
  & node $Verifier (Join-Path $Fixtures $Name) | Out-Null
  if ($LASTEXITCODE -ne $ExpectedExit) {
    throw "$Name expected exit $ExpectedExit but got $LASTEXITCODE"
  }
}

Run-Case "valid-receipt.json" 0
Run-Case "invalid-signature.json" 1
Run-Case "invalid-request-hash.json" 1
Run-Case "invalid-decision-hash.json" 1
Run-Case "invalid-policy-hash.json" 1
Run-Case "corrupted-json.json" 1
Run-Case "missing-field.json" 1

Write-Host "PASS receipt verifier tests"

