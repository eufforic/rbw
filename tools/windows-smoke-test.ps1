# Drives the agent lifecycle on windows without a bitwarden account: start,
# reuse, refuse a second agent, stop. Run after `cargo build --release`.
$ErrorActionPreference = 'Stop'
$env:PATH = "$PSScriptRoot\..\target\release;$env:PATH"
$env:RBW_PROFILE = 'smoke-test'

function Expect($code, $what, [scriptblock]$run) {
    $out = & $run 2>&1 | Out-String
    if ($LASTEXITCODE -ne $code) {
        throw "${what}: exit $LASTEXITCODE, wanted $code`n$out"
    }
    Write-Host "ok: $what"
    return $out
}

Expect 0 'set email' { rbw config set email rbw-smoke-test@invalid.invalid } | Out-Null
$out = Expect 1 'unlocked before the agent runs' { rbw unlocked }
if ($out -notmatch 'agent not running') { throw "unexpected: $out" }

Expect 0 'lock starts the agent' { rbw lock } | Out-Null
$t = Measure-Command { Expect 0 'lock reuses the agent' { rbw lock } | Out-Null }
Write-Host "second call took $([math]::Round($t.TotalMilliseconds)) ms"
$out = Expect 1 'unlocked while locked' { rbw unlocked }
if ($out -notmatch 'locked') { throw "unexpected: $out" }

Expect 23 'a second agent refuses to start' { rbw-agent } | Out-Null

Expect 0 'stop-agent' { rbw stop-agent } | Out-Null
$out = Expect 1 'unlocked after stop' { rbw unlocked }
if ($out -notmatch 'agent not running') { throw "unexpected: $out" }

$out = Expect 0 'pinentry handshake' { "SETTITLE rbw`nBYE`n" | rbw-pinentry }
if ($out -notmatch '(?s)^OK Pleased.*OK\s+OK closing') { throw "unexpected: $out" }
Write-Host 'windows smoke test passed'
