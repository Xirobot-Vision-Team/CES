#requires -Version 7.0
<#
    EC-009 optional isolated fixture. Exercises empty store, explicit selectors,
    freshly CodeSaved records, paginated list/detail, tamper rejection,
    owner/HEAD/index safety and linked-worktree refusal. Nothing touches a
    business repository. Run manually with pwsh 7+ and Git.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$cli = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/ces.ps1'
if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) { throw 'CES CLI unavailable.' }
if (-not (Get-Command git -CommandType Application -ErrorAction SilentlyContinue)) { throw 'Git unavailable.' }
$script:checks = 0
function Check { param([bool] $Ok, [string] $Context)
    if (-not $Ok) { throw $Context }; $script:checks++
}
function Git-Fixture { param([string[]] $Argv)
    $out = @(& git @Argv 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Fixture Git failed: $($Argv -join ' ') — $out" }
    return ($out -join "`n").Trim()
}
function Run-CES { param([string] $Action, [string] $Repo, [int] $ExpectedExit, [string[]] $More = @())
    $out = @(& pwsh -NoProfile -File $cli -Action $Action -RepoPath $Repo -Json @More)
    Check ($LASTEXITCODE -eq $ExpectedExit) "Wrong $Action exit $LASTEXITCODE (expected $ExpectedExit): $out"
    Check ($out.Count -eq 1) 'Expected exactly one JSON object.'
    $result = $out[0] | ConvertFrom-Json -Depth 32
    Check ($result.product_version -eq '1.0.0' -and $result.build -eq '1.0.0') 'Version/build mismatch.'
    Check ($result.next_step -eq 'none') 'Nonexistent AI handoff advertised.'
    Check ($result.read_only -eq ($Action -ne 'CodeSave')) 'Action read-only contract incorrect.'
    return $result
}
$fixture = Join-Path ([System.IO.Path]::GetTempPath()) ('ces codeshow ec009 ' + [guid]::NewGuid().ToString('N'))
$repo = Join-Path $fixture 'repo 项目'
$observationFile = Join-Path $fixture 'saved.json'
$draftFile = Join-Path $fixture 'draft.json'
try {
    [void][System.IO.Directory]::CreateDirectory($repo)
    [void](Git-Fixture -Argv @('init','-q','-b','main',$repo))
    [System.IO.File]::WriteAllText((Join-Path $repo 'base.txt'), 'initial baseline')
    [void](Git-Fixture -Argv @('-C',$repo,'add','base.txt'))
    [void](Git-Fixture -Argv @('-C',$repo,'-c','user.name=CES Fixture','-c','user.email=fixture@example.invalid','commit','-qm','init'))
    $headBefore = Git-Fixture -Argv @('-C',$repo,'rev-parse','HEAD')
    $indexPath = Git-Fixture -Argv @('-C',$repo,'rev-parse','--git-path','index')
    if (-not [System.IO.Path]::IsPathRooted($indexPath)) { $indexPath = Join-Path $repo $indexPath }
    $indexBefore = (Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash

    $empty = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','List')
    Check ($empty.reason_code -eq 'CODE_SHOW_EMPTY' -and $empty.data.record_count -eq 0) 'Empty store was not reported correctly.'
    Check (-not (Test-Path -LiteralPath (Join-Path $repo '.codex/ces'))) 'Read-only list created CES state.'
    $badMode = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4
    Check ($badMode.reason_code -eq 'CODE_SHOW_MODE_REQUIRED') 'Show silently used a default mode.'
    $badSelector = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','List','-IncludePatches')
    Check ($badSelector.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'CodeShow accepted a source-disclosure switch.'
    $badLimit = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','List','-Limit','101')
    Check ($badLimit.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'List accepted an unbounded page size.'
    $badId = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Detail','-RecordId','../owner.json')
    Check ($badId.reason_code -eq 'CODE_SHOW_INVALID_RECORD_ID') 'Detail accepted a traversal selector.'
    $notFound = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Detail','-RecordId',('ci-' + ('a' * 64)))
    Check ($notFound.reason_code -eq 'CODE_SHOW_NOT_FOUND') 'Missing detail did not report not found.'

    # A real CodeSave fixture, not hand-written pretend CES records.
    [System.IO.File]::WriteAllText((Join-Path $repo 'new-note.txt'), "unique review anchor text`n")
    $collected = Run-CES -Action Collect -Repo $repo -ExpectedExit 0 -More @('-Mode','WorkingTree','-IncludeUntrackedContent')
    [System.IO.File]::WriteAllText($observationFile, ($collected | ConvertTo-Json -Compress -Depth 32), [System.Text.UTF8Encoding]::new($false))
    $prepared = Run-CES -Action CodePrepare -Repo $repo -ExpectedExit 0 -More @('-Mode','Snapshot','-EvidencePath',$observationFile,'-IncludeUntrackedContent')
    Check ($prepared.reason_code -eq 'CODE_PREPARE_READY') 'Could not prepare grounded test packet.'
    $draft = [ordered]@{
        schema_version = 'ces.code_insight_draft.v1'; task_kind = 'code_analysis'
        packet_sha256 = $prepared.data.packet_sha256
        saved_collect_sha256 = $prepared.data.preparation.saved_collect_sha256
        summary = 'First local review observation.'
        findings = @([ordered]@{
            id = 'NEW1'; title = 'Review pending note'; severity = 'info'; confidence = 'medium'
            layer = 'untracked'; path = 'new-note.txt'; evidence_quote = 'unique review anchor text'
            reasoning = 'Untracked note is not captured by a normal commit.'
            impact = 'The note could be lost if the worktree is discarded.'
            recommendation = 'Decide whether the note should be committed.'
        })
        limitations = @('Source is only sampled, not an immutable snapshot.')
    }
    $saveArgs = @('-Mode','Snapshot','-EvidencePath',$observationFile,'-InputPath',$draftFile,'-IncludeUntrackedContent','-ApprovePersist')
    $recordIds = [System.Collections.Generic.List[string]]::new()
    foreach ($summary in @('First local review observation.','Second local review observation.')) {
        $draft.summary = $summary
        [System.IO.File]::WriteAllText($draftFile, ($draft | ConvertTo-Json -Compress -Depth 32), [System.Text.UTF8Encoding]::new($false))
        $saved = Run-CES -Action CodeSave -Repo $repo -ExpectedExit 0 -More $saveArgs
        Check ($saved.reason_code -eq 'CODE_SAVE_OK' -and $saved.data.created) 'Could not save test record.'
        $recordIds.Add([string]$saved.data.record_id)
    }
    Check ($recordIds[0] -ne $recordIds[1]) 'Two distinct drafts created one digest.'
    $list = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','List')
    Check ($list.reason_code -eq 'CODE_SHOW_OK' -and $list.coverage.code_records_integrity_checked) 'Record-list integrity not affirmed.'
    Check ($list.data.record_count -eq 2 -and $list.data.returned_count -eq 2) 'List record counts are incorrect.'
    Check (-not $list.data.has_more -and $list.data.record_authorship_authenticated -eq $false) 'List asserted false authorship or additional records.'
    Check (($list.data.records[0].record_id -clt $list.data.records[1].record_id)) 'Record order is not stable.'
    $human = @(& pwsh -NoProfile -File $cli -Action CodeShow -Mode List -RepoPath $repo)
    Check ($LASTEXITCODE -eq 0 -and (@($human) -join ' ').Contains('CODE_SHOW_OK')) 'Non-JSON list output failed.'
    Check (-not ($list | ConvertTo-Json -Depth 32).Contains('evidence_quote')) 'List disclosed raw source quotes.'
    $pageOne = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','List','-Limit','1')
    Check ($pageOne.data.has_more -and $pageOne.data.returned_count -eq 1) 'Page-one bound incorrect.'
    $pageTwo = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','List','-Limit','1','-AfterRecordId',$pageOne.data.next_after_record_id)
    Check (-not $pageTwo.data.has_more -and $pageTwo.data.returned_count -eq 1 -and
        $pageTwo.data.records[0].record_id -eq $list.data.records[1].record_id) 'Cursor page returned the wrong record.'
    $afterEnd = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','List','-AfterRecordId',$list.data.records[1].record_id)
    Check ($afterEnd.data.returned_count -eq 0 -and $afterEnd.data.record_count -eq 2) 'Cursor-after-last was not a clean empty page.'
    $detail = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Detail','-RecordId',$recordIds[0])
    Check ($detail.reason_code -eq 'CODE_SHOW_OK' -and $detail.data.record_integrity_verified) 'Detail record integrity not verified.'
    Check ($detail.data.record.finding_count -eq 1 -and $detail.data.record.checked_findings[0].id -eq 'NEW1') 'Checked finding details missing.'
    Check ($detail.data.record.source_root -eq $repo -and -not $detail.data.record_authorship_authenticated) 'Root binding or provenance flags incorrect.'
    Check (-not ($detail | ConvertTo-Json -Depth 32).Contains('evidence_quote')) 'Detail leaked raw source quote.'

    # Detect tampered metadata even if the JSON would still parse.
    $target = Join-Path $repo ('.codex/ces/code-insights/' + $recordIds[0] + '.json')
    $original = [System.IO.File]::ReadAllBytes($target)
    [System.IO.File]::AppendAllText($target, ' ')
    $corrupt = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 2 -More @('-Mode','Detail','-RecordId',$recordIds[0])
    Check ($corrupt.reason_code -eq 'CODE_SHOW_RECORD_INVALID_OR_CHANGED' -and $null -eq $corrupt.data) 'Tampered detail was accepted.'
    $corruptList = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 2 -More @('-Mode','List')
    Check ($corruptList.reason_code -eq 'CODE_SHOW_RECORD_INVALID_OR_CHANGED' -and $null -eq $corruptList.data) 'Tampered list was accepted.'
    [System.IO.File]::WriteAllBytes($target, $original)
    $restored = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Detail','-RecordId',$recordIds[0])
    Check ($restored.reason_code -eq 'CODE_SHOW_OK') 'Restored record could not be read.'

    $ownerPath = Join-Path $repo '.codex/ces/owner.json'
    $owner = [System.IO.File]::ReadAllBytes($ownerPath)
    [System.IO.File]::WriteAllText($ownerPath, '{"owner":"unknown"}')
    $unsafe = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 5 -More @('-Mode','List')
    Check ($unsafe.reason_code -eq 'CODE_SHOW_STORE_UNSAFE_OR_UNAVAILABLE') 'Invalid ownership marker was ignored.'
    [System.IO.File]::WriteAllBytes($ownerPath, $owner)

    Check ($indexBefore -eq (Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash) 'Read-only CodeShow modified Git index before fixture boundary mutations.'

    # A tracked file occupying CES state disqualifies even a read-only Show.
    [void](Git-Fixture -Argv @('-C',$repo,'add','-f','.codex/ces/owner.json'))
    $tracked = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 5 -More @('-Mode','List')
    Check ($tracked.reason_code -eq 'CODE_SHOW_STORE_UNSAFE_OR_UNAVAILABLE') 'Tracked CES state boundary was trusted.'
    [void](Git-Fixture -Argv @('-C',$repo,'reset','--','.codex/ces/owner.json'))
    $indexAfterFixtureReset = (Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash

    $linked = Join-Path $fixture 'linked-worktree'
    [void](Git-Fixture -Argv @('-C',$repo,'worktree','add','--detach',$linked,'HEAD'))
    $linkedShow = Run-CES -Action CodeShow -Repo $linked -ExpectedExit 2 -More @('-Mode','List')
    Check ($linkedShow.reason_code -eq 'CODE_SHOW_MAIN_WORKTREE_REQUIRED') 'Linked worktree was treated as main CES storage.'
    Check ($headBefore -eq (Git-Fixture -Argv @('-C',$repo,'rev-parse','HEAD'))) 'CodeShow modified repository HEAD.'
    Check ($indexAfterFixtureReset -eq (Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash) 'CodeShow modified Git index after fixture reset.'
    Write-Output "EC-009 CodeShow smoke PASS: $script:checks checks in isolated scratch repositories."
} finally {
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue }
}
