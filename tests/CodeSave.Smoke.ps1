#requires -Version 7.0
<#
    EC-008 optional fixture: CodeSave authorization, independent validation,
    safe CES-only persistence, content-addressed idempotence, store conflicts,
    source drift, WorkingTree/DeliveredTarget and Git state preservation.
    Run manually on a PowerShell 7 + Git host; never on business repositories.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$cli = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/ces.ps1'
if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) { throw 'CES CLI unavailable.' }
if (-not (Get-Command git -CommandType Application -ErrorAction SilentlyContinue)) { throw 'Git unavailable.' }
$script:checks = 0
function Check { param([bool] $Condition, [string] $Message)
    if (-not $Condition) { throw $Message }; $script:checks++
}
function Git-Fixture { param([string[]] $Argv)
    $output = @(& git @Argv 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Fixture Git failed: $($Argv -join ' ') — $output" }
    return ($output -join "`n").Trim()
}
function Run-CES { param([string] $Action, [string] $Repo, [int] $Exit, [string[]] $More = @())
    $out = @(& pwsh -NoProfile -File $cli -Action $Action -RepoPath $Repo -Json @More)
    Check ($LASTEXITCODE -eq $Exit) "$Action exit $LASTEXITCODE, expected ${Exit}: $out"
    Check ($out.Count -eq 1) 'CES emitted more than one JSON object.'
    $r = $out[0] | ConvertFrom-Json -Depth 32
    Check ($r.product_version -eq '1.0.0' -and $r.build -eq '1.0.0') 'Version not upgraded.'
    Check ($r.next_step -eq 'none') 'A nonexistent handoff was asserted.'
    Check ($r.read_only -eq ($Action -ne 'CodeSave')) 'Read-only contract does not match the action.'
    return $r
}
function Save-Observation { param([string] $Repo, [string] $File, [string[]] $Options)
    $collected = Run-CES -Action Collect -Repo $Repo -Exit 0 -More $Options
    [System.IO.File]::WriteAllText($File, ($collected | ConvertTo-Json -Depth 32 -Compress), [System.Text.UTF8Encoding]::new($false))
}
function Write-Draft { param([string] $File, [object] $Draft)
    [System.IO.File]::WriteAllText($File, ($Draft | ConvertTo-Json -Depth 24 -Compress), [System.Text.UTF8Encoding]::new($false))
}
$fixture = Join-Path ([System.IO.Path]::GetTempPath()) ('ces codesave ec008 ' + [guid]::NewGuid().ToString('N'))
$repo = Join-Path $fixture 'repository 工作区'
$snapshot = Join-Path $fixture 'observation.json'
$draftFile = Join-Path $fixture 'review.json'
try {
    [void][System.IO.Directory]::CreateDirectory($repo)
    [void](Git-Fixture -Argv @('init','-q','-b','main',$repo))
    [System.IO.File]::WriteAllText((Join-Path $repo 'worker.ps1'), "baseline`n")
    [void](Git-Fixture -Argv @('-C',$repo,'add','worker.ps1'))
    [void](Git-Fixture -Argv @('-C',$repo,'-c','user.name=CES Fixture','-c','user.email=fixture@example.invalid','commit','-qm','baseline'))
    $base = Git-Fixture -Argv @('-C',$repo,'rev-parse','HEAD')
    [System.IO.File]::AppendAllText((Join-Path $repo 'worker.ps1'), "tracked alpha marker`n")
    [void](Git-Fixture -Argv @('-C',$repo,'add','worker.ps1'))
    [System.IO.File]::WriteAllText((Join-Path $repo 'note.txt'), "unique note marker`n")
    $indexPath = Git-Fixture -Argv @('-C',$repo,'rev-parse','--git-path','index')
    if (-not [System.IO.Path]::IsPathRooted($indexPath)) { $indexPath = Join-Path $repo $indexPath }
    $indexBefore = (Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash
    Save-Observation -Repo $repo -File $snapshot -Options @('-Mode','WorkingTree','-IncludePatches','-IncludeUntrackedContent')
    $options = @('-Mode','Snapshot','-EvidencePath',$snapshot,'-InputPath',$draftFile,'-IncludePatches','-IncludeUntrackedContent')
    $prepared = Run-CES -Action CodePrepare -Repo $repo -Exit 0 -More @('-Mode','Snapshot','-EvidencePath',$snapshot,'-IncludePatches','-IncludeUntrackedContent')
    Check ($prepared.reason_code -eq 'CODE_PREPARE_READY') 'Review packet missing.'
    $draft = [ordered]@{
        schema_version = 'ces.code_insight_draft.v1'
        task_kind = 'code_analysis'
        packet_sha256 = $prepared.data.packet_sha256
        saved_collect_sha256 = $prepared.data.preparation.saved_collect_sha256
        summary = 'Two source-anchored observations; not proven defects.'
        findings = @(
            [ordered]@{
                id = 'F1'; title = 'Review staged source change'; severity = 'info'; confidence = 'medium'
                layer = 'staged'; path = 'worker.ps1'; evidence_quote = '+tracked alpha marker'
                reasoning = 'The staged change needs confirmation in its call context.'
                impact = 'Behavioral impact requires inspection and test evidence.'
                recommendation = 'Check the staged change and its tests before merging.'
            },
            [ordered]@{
                id = 'F2'; title = 'Review untracked notes file'; severity = 'low'; confidence = 'high'
                layer = 'untracked'; path = 'note.txt'; evidence_quote = 'unique note marker'
                reasoning = 'An untracked note will not be part of a normal commit.'
                impact = 'This note could be unintentionally omitted from the work.'
                recommendation = 'Confirm whether the note belongs in the repository.'
            }
        )
        limitations = @('Only literal evidence anchors were checked.')
    }
    Write-Draft -File $draftFile -Draft $draft

    $noApproval = Run-CES -Action CodeSave -Repo $repo -Exit 4 -More $options
    Check ($noApproval.reason_code -eq 'CODE_SAVE_AUTHORIZATION_REQUIRED') 'Missing save approval was ignored.'
    Check (-not (Test-Path -LiteralPath (Join-Path $repo '.codex/ces'))) 'Authorization failure unexpectedly created state.'
    $bad = $draft.packet_sha256
    $draft.packet_sha256 = 'f' * 64
    Write-Draft -File $draftFile -Draft $draft
    $unbound = Run-CES -Action CodeSave -Repo $repo -Exit 2 -More (@('-ApprovePersist') + $options)
    Check ($unbound.reason_code -eq 'CODE_SAVE_VALIDATION_FAILED' -and -not $unbound.data.persisted) 'Unbound draft was persisted.'
    Check (-not (Test-Path -LiteralPath (Join-Path $repo '.codex/ces'))) 'Invalid source caused a state write.'
    $draft.packet_sha256 = $bad
    Write-Draft -File $draftFile -Draft $draft

    $saved = Run-CES -Action CodeSave -Repo $repo -Exit 0 -More (@('-ApprovePersist') + $options)
    Check ($saved.reason_code -eq 'CODE_SAVE_OK' -and $saved.data.persisted -and $saved.data.created) 'CodeSave did not create a record.'
    Check ($saved.coverage.code_result_persisted) 'No persistence coverage was reported.'
    Check ($saved.data.record_id -match '^ci-[0-9a-f]{64}$') 'Content-addressed record ID malformed.'
    Check (Test-Path -LiteralPath $saved.data.record_path -PathType Leaf) 'Record file absent.'
    $record = Get-Content -LiteralPath $saved.data.record_path -Raw -Encoding utf8
    $parsed = $record | ConvertFrom-Json -Depth 32
    Check ($parsed.schema_version -eq 'ces.code_insight_saved.v1' -and $parsed.finding_count -eq 2) 'Wrong saved record schema/findings.'
    Check (-not $record.Contains('evidence_quote') -and -not $record.Contains('diff --git')) 'Raw source excerpt leaked into saved record.'
    Check ((Get-FileHash -LiteralPath $saved.data.record_path -Algorithm SHA256).Hash.ToLowerInvariant() -eq $saved.data.record_sha256) 'Persisted SHA-256 did not match.'
    Check ($indexBefore -eq (Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash) 'CodeSave modified the Git index.'
    Check ($base -eq (Git-Fixture -Argv @('-C',$repo,'rev-parse','HEAD'))) 'CodeSave modified HEAD.'
    $snapshotAfter = Run-CES -Action Reconcile -Repo $repo -Exit 0 -More @('-Mode','Snapshot','-EvidencePath',$snapshot)
    Check ($snapshotAfter.data.verdict -eq 'matched') 'CES-owned storage contaminated WorkingTree Reconcile.'
    $repeated = Run-CES -Action CodeSave -Repo $repo -Exit 0 -More (@('-ApprovePersist') + $options)
    Check ($repeated.reason_code -eq 'CODE_SAVE_ALREADY_PRESENT' -and -not $repeated.data.created -and $repeated.data.record_id -eq $saved.data.record_id) 'Identical save not idempotent.'
    $collectAgain = Run-CES -Action Collect -Repo $repo -Exit 0 -More @('-Mode','WorkingTree','-IncludePatches','-IncludeUntrackedContent')
    Check ($collectAgain.data.untracked.count -eq 1 -and $collectAgain.data.untracked.entries[0].path -eq 'note.txt') 'CES state must be omitted from untracked source.'

    # The user-owned store marker may not be silently replaced or fixed.
    $owner = Join-Path $repo '.codex/ces/owner.json'
    $ownerOriginal = [System.IO.File]::ReadAllText($owner)
    [System.IO.File]::WriteAllText($owner, '{"owner":"other"}')
    $unsafe = Run-CES -Action CodeSave -Repo $repo -Exit 5 -More (@('-ApprovePersist') + $options)
    Check ($unsafe.reason_code -eq 'CODE_SAVE_STORE_UNSAFE_OR_UNAVAILABLE') 'Corrupt CES ownership marker was ignored.'
    [System.IO.File]::WriteAllText($owner, $ownerOriginal)

    # A source mutation must prevent a new record even if all old hashes match.
    [System.IO.File]::AppendAllText((Join-Path $repo 'note.txt'), "drift`n")
    $drift = Run-CES -Action CodeSave -Repo $repo -Exit 2 -More (@('-ApprovePersist') + $options)
    Check ($drift.reason_code -eq 'CODE_SAVE_VALIDATION_FAILED' -and -not $drift.data.persisted) 'Stale source reached CES storage.'
    [System.IO.File]::WriteAllText((Join-Path $repo 'note.txt'), "unique note marker`n")

    # A separately pinned local DeliveredTarget packet can also be saved.
    [void](Git-Fixture -Argv @('-C',$repo,'add','worker.ps1','note.txt'))
    [void](Git-Fixture -Argv @('-C',$repo,'-c','user.name=CES Fixture','-c','user.email=fixture@example.invalid','commit','-qm','target'))
    $target = Git-Fixture -Argv @('-C',$repo,'rev-parse','HEAD')
    Save-Observation -Repo $repo -File $snapshot -Options @('-Mode','DeliveredTarget','-BaseSha',$base,'-TargetSha',$target,'-TargetRef','refs/heads/main','-IncludePatches')
    $delScope = @('-Mode','Snapshot','-EvidencePath',$snapshot,'-InputPath',$draftFile,'-IncludePatches')
    $packet = Run-CES -Action CodePrepare -Repo $repo -Exit 0 -More @('-Mode','Snapshot','-EvidencePath',$snapshot,'-IncludePatches')
    $draft.packet_sha256 = $packet.data.packet_sha256
    $draft.saved_collect_sha256 = $packet.data.preparation.saved_collect_sha256
    $draft.findings = @([ordered]@{
        id = 'DEL1'; title = 'Check pinned change'; severity = 'info'; confidence = 'low'
        layer = 'changes'; path = 'worker.ps1'; evidence_quote = '+tracked alpha marker'
        reasoning = 'The local target commit includes this observed change.'
        impact = 'No deployment or remote delivery evidence is available.'
        recommendation = 'Confirm the actual delivery channel independently.'
    })
    Write-Draft -File $draftFile -Draft $draft
    $delivered = Run-CES -Action CodeSave -Repo $repo -Exit 0 -More (@('-ApprovePersist') + $delScope)
    Check ($delivered.reason_code -eq 'CODE_SAVE_OK' -and $delivered.data.source_mode -eq 'delivered_target_diff') 'DeliveredTarget save failed.'
    Check ($delivered.data.record_id -ne $saved.data.record_id) 'Different review packets collided.'
    Check (@(Get-ChildItem -LiteralPath (Join-Path $repo '.codex/ces/code-insights') -File).Count -eq 2) 'Expected two durable CodeInsight records.'
    # Even a previously valid DeliveredTarget cannot write CES state while
    # the index contains a tracked CES path (the commit tree is still pinned).
    [void](Git-Fixture -Argv @('-C',$repo,'add','-f','.codex/ces/owner.json'))
    $trackedBoundary = Run-CES -Action CodeSave -Repo $repo -Exit 5 -More (@('-ApprovePersist') + $delScope)
    Check ($trackedBoundary.reason_code -eq 'CODE_SAVE_STORE_UNSAFE_OR_UNAVAILABLE') 'Tracked CES boundary was not rejected.'
    [void](Git-Fixture -Argv @('-C',$repo,'reset','--','.codex/ces/owner.json'))
    Write-Output "EC-008 CodeSave smoke PASS: $script:checks checks across local WorkingTree and DeliveredTarget."
} finally {
    if (Test-Path -LiteralPath $fixture) {
        Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue
    }
}
