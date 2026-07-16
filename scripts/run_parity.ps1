#!/usr/bin/env pwsh
# Parity + smoke gate for devguard-in-browser.
#   1. JS engine dump  (node)  over fixtures/
#   2. Python tool dump (canonical wrg_devguard.secrets) over fixtures/
#   3. Compare finding sets + counts  (exit 1 on any divergence)
#   4. Headless UI-path smoke
#
# Run from web/devguard-scan/:
#   pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_parity.ps1
# The Python parity step needs the canonical detection source (wrg_devguard),
# which lives in the private WinstonRedGuard monorepo (apps/wrg_devguard) --
# not published as a standalone public repo. If you have access, pass
# -WrgDevguardSrc <monorepo-checkout>/apps/wrg_devguard/src (or set
# $env:WRG_DEVGUARD_SRC). The JS engine + UI smoke run standalone regardless;
# the Python compare is skipped with a notice if the source is not provided.
[CmdletBinding()]
param(
    [string]$WrgDevguardSrc = $env:WRG_DEVGUARD_SRC
)

$ErrorActionPreference = 'Stop'
$here = Resolve-Path "$PSScriptRoot/.."
$fixtures = Join-Path $here 'fixtures'
$jsOut = Join-Path ([System.IO.Path]::GetTempPath()) 'dgib_js.json'
$pyOut = Join-Path ([System.IO.Path]::GetTempPath()) 'dgib_py.json'

Write-Host "== [1/4] JS engine dump ==" -ForegroundColor Cyan
node (Join-Path $here 'scripts/js_reference_dump.mjs') $fixtures $jsOut

if (-not $WrgDevguardSrc -or -not (Test-Path $WrgDevguardSrc)) {
    Write-Host "== [2-3/4] Python parity SKIPPED ==" -ForegroundColor Yellow
    Write-Host "  Provide -WrgDevguardSrc <monorepo-checkout>/apps/wrg_devguard/src to run parity" -ForegroundColor Yellow
    Write-Host "  (maintainer-only: the canonical source is private, not a standalone repo)." -ForegroundColor Yellow
} else {
    Write-Host "== [2/4] Python tool dump (wrg_devguard.secrets) ==" -ForegroundColor Cyan
    $env:PYTHONPATH = $WrgDevguardSrc
    py -3 (Join-Path $here 'scripts/py_reference_dump.py') $fixtures $pyOut

    Write-Host "== [3/4] Parity compare ==" -ForegroundColor Cyan
    py -3 (Join-Path $here 'scripts/parity_compare.py') $jsOut $pyOut
    if ($LASTEXITCODE -ne 0) { Write-Host "PARITY FAIL" -ForegroundColor Red; exit 1 }
}

Write-Host "== [4/4] UI-path smoke ==" -ForegroundColor Cyan
node (Join-Path $here 'scripts/ui_smoke.mjs')
if ($LASTEXITCODE -ne 0) { Write-Host "UI SMOKE FAIL" -ForegroundColor Red; exit 1 }

Write-Host "`nALL GREEN — parity + smoke" -ForegroundColor Green
exit 0
