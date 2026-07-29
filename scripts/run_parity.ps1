#!/usr/bin/env pwsh
# Full local gate for devguard-in-browser.
#
#   pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_parity.ps1
#
# Everything except step 4 also runs in GitHub Actions
# (.github/workflows/tests.yml). Step 4 -- the finding-for-finding comparison
# against the canonical Python engine -- needs the wrg_devguard source, which
# lives in a private monorepo (maintainer-only), not a standalone public repo.
# Pass -WrgDevguardSrc <monorepo-checkout>/apps/wrg_devguard/src (or set
# $env:WRG_DEVGUARD_SRC) to include it; it is skipped with a notice otherwise.
#
# Step 4 is NOT the check that catches a drifted port. It compares what the two
# engines find in fixtures/, so it only sees a divergence the corpus exercises
# -- it printed ALL GREEN for eight days while this engine had stopped scanning
# .env.local and setup.cfg. Step 1 compares the rule and glob lists themselves,
# and needs no monorepo access at all.
[CmdletBinding()]
param(
    [string]$WrgDevguardSrc = $env:WRG_DEVGUARD_SRC
)

$ErrorActionPreference = 'Stop'
$here = Resolve-Path "$PSScriptRoot/.."
$fixtures = Join-Path $here 'fixtures'
$jsOut = Join-Path ([System.IO.Path]::GetTempPath()) 'dgib_js.json'
$pyOut = Join-Path ([System.IO.Path]::GetTempPath()) 'dgib_py.json'
$globCorpus = Join-Path ([System.IO.Path]::GetTempPath()) 'dgib_glob_corpus.json'

function Invoke-Step {
    param([string]$Title, [scriptblock]$Body)
    Write-Host "== $Title ==" -ForegroundColor Cyan
    & $Body
    if ($LASTEXITCODE -ne 0) {
        Write-Host "$Title FAILED" -ForegroundColor Red
        exit 1
    }
}

Invoke-Step '[1/8] Contract check (rule + glob lists vs canonical)' {
    node (Join-Path $here 'scripts/contract_check.mjs')
}

Invoke-Step '[2/8] Contract self-test (the checker must fail when it should)' {
    node (Join-Path $here 'scripts/contract_selftest.mjs')
}

Invoke-Step '[3/8] JS engine dump' {
    node (Join-Path $here 'scripts/js_reference_dump.mjs') $fixtures $jsOut
}

if (-not $WrgDevguardSrc -or -not (Test-Path $WrgDevguardSrc)) {
    Write-Host '== [4/8] Python parity SKIPPED ==' -ForegroundColor Yellow
    Write-Host '  Provide -WrgDevguardSrc <monorepo-checkout>/apps/wrg_devguard/src to run it' -ForegroundColor Yellow
    Write-Host '  (maintainer-only: the canonical source is private, not a standalone repo).' -ForegroundColor Yellow
    Write-Host '  Step 1 already compared the contracts and needs no such access.' -ForegroundColor Yellow
} else {
    Invoke-Step '[4/8] Python tool dump (wrg_devguard.secrets)' {
        $env:PYTHONPATH = $WrgDevguardSrc
        py -3 (Join-Path $here 'scripts/py_reference_dump.py') $fixtures $pyOut
    }
    Invoke-Step '[4/8] Parity compare' {
        py -3 (Join-Path $here 'scripts/parity_compare.py') $jsOut $pyOut
    }
}

# CPython stdlib only -- fnmatch/pathlib ARE the contract the JS matcher ports,
# so this needs no monorepo access either.
Invoke-Step '[5/8] Glob oracle corpus (CPython fnmatch)' {
    py -3 (Join-Path $here 'scripts/glob_corpus.py') $globCorpus
}

Invoke-Step '[5/8] Glob differential replay' {
    node (Join-Path $here 'scripts/glob_parity_check.mjs') $globCorpus
}

Invoke-Step '[6/8] CSP + no-network audit' {
    node (Join-Path $here 'scripts/csp_check.mjs')
}

Invoke-Step '[6/8] UI-path smoke' {
    node (Join-Path $here 'scripts/ui_smoke.mjs')
}

Invoke-Step '[7/8] CLI smoke' {
    node (Join-Path $here 'scripts/cli_smoke.mjs')
}

Invoke-Step '[8/8] CLI exit codes' {
    node (Join-Path $here 'scripts/exit_code_smoke.mjs')
}

Write-Host "`nALL GREEN - contract + parity + smoke" -ForegroundColor Green
exit 0
