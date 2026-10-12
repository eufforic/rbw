# Drives the agent lifecycle on windows without a bitwarden account: start,
# reuse, refuse a second agent, stop. Run after `cargo build --release`.
$ErrorActionPreference = 'Stop'
$bin = Resolve-Path "$PSScriptRoot\..\target\release"
$env:RBW_PROFILE = 'smoke-test'
$env:RUST_LOG = 'debug'
$out = New-Item -ItemType Directory -Force "$env:RUNNER_TEMP\rbw-smoke"

function Dump-AgentLogs {
    Get-ChildItem $env:APPDATA, $env:LOCALAPPDATA -Recurse -Filter 'agent.*' -ErrorAction SilentlyContinue |
        Where-Object FullName -match 'smoke-test' |
        ForEach-Object { Write-Host "--- $($_.FullName)"; Get-Content $_.FullName }
}

# Output goes to files, never to a pipe this script reads, so a child that
# keeps a handle open cannot hang the step; a hung command fails it instead.
function Expect($code, $what, $exe, $argv, $stdin) {
    $o = "$out\out.txt"; $e = "$out\err.txt"
    $start = @{ FilePath = "$bin\$exe"; NoNewWindow = $true; PassThru = $true
                RedirectStandardOutput = $o; RedirectStandardError = $e }
    if ($argv) { $start.ArgumentList = $argv }
    if ($stdin) { Set-Content "$out\in.txt" $stdin -NoNewline; $start.RedirectStandardInput = "$out\in.txt" }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $p = Start-Process @start
    if (-not $p.WaitForExit(30000)) {
        $p.Kill(); Dump-AgentLogs
        throw "${what}: still running after 30 s`n$(Get-Content $o -Raw)$(Get-Content $e -Raw)"
    }
    $text = "$(Get-Content $o -Raw)$(Get-Content $e -Raw)"
    if ($p.ExitCode -ne $code) {
        Dump-AgentLogs
        throw "${what}: exit $($p.ExitCode), wanted $code`n$text"
    }
    Write-Host "ok: $what ($($sw.ElapsedMilliseconds) ms)"
    return $text
}

Expect 0 'set email' rbw.exe @('config', 'set', 'email', 'rbw-smoke-test@invalid.invalid') | Out-Null
$text = Expect 1 'unlocked before the agent runs' rbw.exe @('unlocked')
if ($text -notmatch 'agent not running') { throw "unexpected: $text" }

Expect 0 'lock starts the agent' rbw.exe @('lock') | Out-Null
Expect 0 'lock reuses the agent' rbw.exe @('lock') | Out-Null
$text = Expect 1 'unlocked while locked' rbw.exe @('unlocked')
if ($text -notmatch 'locked') { throw "unexpected: $text" }

Expect 23 'a second agent refuses to start' rbw-agent.exe | Out-Null

Expect 0 'stop-agent' rbw.exe @('stop-agent') | Out-Null
$text = Expect 1 'unlocked after stop' rbw.exe @('unlocked')
if ($text -notmatch 'agent not running') { throw "unexpected: $text" }

# Callers that capture output (scripts, agent hosts) read the pipes to the
# end, so starting the agent must not leave them holding a pipe open.
$psi = [Diagnostics.ProcessStartInfo]::new("$bin\rbw.exe", 'lock')
$psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$sw = [Diagnostics.Stopwatch]::StartNew()
$p = [Diagnostics.Process]::Start($psi)
$stdout = $p.StandardOutput.ReadToEndAsync(); $stderr = $p.StandardError.ReadToEndAsync()
if (-not [Threading.Tasks.Task]::WaitAll(@($stdout, $stderr), 30000)) {
    Dump-AgentLogs
    throw 'starting the agent left the caller''s output pipes open'
}
$p.WaitForExit()
if ($p.ExitCode -ne 0) { throw "piped lock: exit $($p.ExitCode)`n$($stderr.Result)" }
Write-Host "ok: piped output closes after starting the agent ($($sw.ElapsedMilliseconds) ms)"
Expect 0 'stop-agent again' rbw.exe @('stop-agent') | Out-Null

$text = Expect 0 'pinentry handshake' rbw-pinentry.exe $null "SETTITLE rbw`nBYE`n"
if ($text -notmatch '(?s)^OK Pleased.*OK\s+OK closing') { throw "unexpected: $text" }
Write-Host 'windows smoke test passed'
