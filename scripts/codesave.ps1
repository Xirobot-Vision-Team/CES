#requires -Version 7.0
<#
    EC-008: explicitly authorized, local-only CodeInsight persistence.
    Revalidates the complete CodeValidate source/draft gate, requires the
    verified MAIN worktree, and writes only CES-owned .codex/ces/code-insights.
    A content-addressed, no-overwrite JSON record makes identical saves
    idempotent. This is not a model call, business-source edit or remote proof.
#>

$script:CodeSaveRecordByteLimit = 512KB
$script:CodeSaveOwnerJson = '{"schema_version":"ces.local_store.v1","owner":"CES","purpose":"local_code_insights"}'

function Test-CodeSaveRegularItem {
    param([string] $Path, [bool] $Directory)

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'CES storage refuses symbolic links, junctions and other reparse points.'
    }
    if ($Directory -and $item -isnot [System.IO.DirectoryInfo]) {
        throw 'A CES storage directory is occupied by a non-directory.'
    }
    if (-not $Directory -and $item -isnot [System.IO.FileInfo]) {
        throw 'A CES storage file is occupied by a non-file.'
    }
    return $item
}

function Get-CodeSaveOptionalItem {
    param([string] $Path)

    # Get-Item -Force can expose a reparse point even where Test-Path might
    # call a dangling link "missing". Unexpected I/O/permission failures
    # are NOT converted into absence.
    try {
        return Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    } catch [System.Management.Automation.ItemNotFoundException] {
        return $null
    }
}

function Read-CodeSaveBoundedBytes {
    param([string] $Path, [int] $MaxBytes)

    $item = Test-CodeSaveRegularItem -Path $Path -Directory $false
    if ($item.Length -gt $MaxBytes) { throw 'CES storage file is larger than its permitted bound.' }
    $stream = [System.IO.FileStream]::new(
        $item.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
        ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
    )
    try {
        if ($stream.Length -gt $MaxBytes) { throw 'CES storage file grew beyond its bound.' }
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $n = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($n -le 0) { throw 'CES storage file was truncated during reading.' }
            $offset += $n
        }
        if ($stream.Length -ne $bytes.Length) { throw 'CES storage file changed size during reading.' }
        return ,$bytes
    } finally { $stream.Dispose() }
}

function Assert-CodeSaveFileMatches {
    param([string] $Path, [byte[]] $Expected)

    $observed = Read-CodeSaveBoundedBytes -Path $Path -MaxBytes $script:CodeSaveRecordByteLimit
    if ($observed.Length -ne $Expected.Length -or
        (Get-HashOfBytes -Bytes $observed) -cne (Get-HashOfBytes -Bytes $Expected)) {
        throw 'Existing CES record has a conflicting body; refusing overwrite.'
    }
}

function Write-CodeSaveAtomicNewFile {
    param([string] $Directory, [string] $LeafName, [byte[]] $Bytes)

    # Only caller-generated fixed leaf names may reach this writer.
    if ($LeafName -cnotmatch '^(?:owner\.json|ci-[0-9a-f]{64}\.json)$') {
        throw 'Unsafe CES storage leaf name.'
    }
    [void](Test-CodeSaveRegularItem -Path $Directory -Directory $true)
    [void](Assert-CesNoReparseAncestry -Path $Directory)
    $target = Join-Path $Directory $LeafName
    [void](Assert-CesNoReparseAncestry -Path $target)
    if (Test-Path -LiteralPath $target) {
        Assert-CodeSaveFileMatches -Path $target -Expected $Bytes
        return $false
    }
    $temp = Join-Path $Directory ('.ces-tmp-' + [guid]::NewGuid().ToString('N'))
    $created = $false
    try {
        $stream = [System.IO.FileStream]::new(
            $temp, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
        $created = $true
        try {
            $stream.Write($Bytes, 0, $Bytes.Length)
            $stream.Flush($true)
        } finally { $stream.Dispose() }
        # The rename is on the same filesystem and does not overwrite a
        # competing writer's file. Any existing target must match byte-for-byte
        # by length and SHA-256 before an idempotent result is returned.
        try {
            [System.IO.File]::Move($temp, $target)
            $created = $false
            return $true
        } catch [System.IO.IOException] {
            if (-not (Test-Path -LiteralPath $target)) { throw }
            Assert-CodeSaveFileMatches -Path $target -Expected $Bytes
            return $false
        }
    } finally {
        if ($created) {
            # The temp is a generated file inside the just-checked CES store;
            # do not recursively remove directories or follow link targets.
            try {
                [void](Test-CodeSaveRegularItem -Path $Directory -Directory $true)
                if (Test-Path -LiteralPath $temp) {
                    [void](Test-CodeSaveRegularItem -Path $temp -Directory $false)
                    [System.IO.File]::Delete($temp)
                }
            } catch { }
        }
    }
}

function Assert-CodeSaveGitBoundary {
    param([string] $GitExecutable, [string] $RepoRoot, [string] $AdditionalTargetSha)

    # Internal state must never collide with tracked business files, even if
    # the user staged their deletion. Check BOTH index and HEAD read-only.
    $index = Git-In -GitExecutable $GitExecutable -Directory $RepoRoot -Arguments @(
        'ls-files', '--cached', '-z', '--full-name', '--',
        ':(top,glob).codex/ces/**', ':(top,literal).codex/ces'
    ) -MaxStdoutBytes 4KB
    if (-not $index.ok) { throw 'Could not verify tracked index paths under the reserved CES state boundary.' }
    if ($index.stdout.Length -gt 0) { throw 'The CES state boundary overlaps tracked index content.' }

    # Also reject a tracked .codex *file or gitlink*: it is not safe
    # to create a child CES directory inside a repository-owned submodule.
    $indexParent = Git-In -GitExecutable $GitExecutable -Directory $RepoRoot -Arguments @(
        'ls-files', '--cached', '--stage', '-z', '--', ':(top,literal).codex'
    ) -MaxStdoutBytes 4KB
    if (-not $indexParent.ok) { throw 'Cannot inspect the CES parent in Git index.' }
    foreach ($entry in (Split-GitNulFields -Content $indexParent.stdout)) {
        if ($entry.EndsWith("`t.codex", [System.StringComparison]::Ordinal)) {
            throw 'CES parent .codex is itself a tracked file or submodule.'
        }
    }

    $head = Git-In -GitExecutable $GitExecutable -Directory $RepoRoot -Arguments @(
        'rev-parse', '--verify', 'HEAD^{commit}'
    )
    if (-not $head.ok -or $head.stdout -notmatch '^[0-9a-fA-F]{40,64}$') {
        throw 'A verified HEAD commit is required for safe CES local persistence.'
    }
    $tree = Git-In -GitExecutable $GitExecutable -Directory $RepoRoot -Arguments @(
        'ls-tree', '-r', '--name-only', '-z', 'HEAD', '--', '.codex/ces'
    ) -MaxStdoutBytes 4KB
    if (-not $tree.ok) { throw 'Could not check the committed CES state boundary.' }
    if ($tree.stdout.Length -gt 0) { throw 'The CES state boundary overlaps committed business content.' }
    # A tree-typed .codex is fine (other tracked project metadata can live
    # there); a blob or gitlink at this parent is a business path collision.
    foreach ($commit in @('HEAD', $AdditionalTargetSha)) {
        if ([string]::IsNullOrEmpty($commit)) { continue }
        $parentTree = Git-In -GitExecutable $GitExecutable -Directory $RepoRoot -Arguments @(
            'ls-tree', '-z', $commit, '--', '.codex'
        ) -MaxStdoutBytes 4KB
        if (-not $parentTree.ok) { throw 'Cannot inspect committed CES parent path type.' }
        foreach ($item in (Split-GitNulFields -Content $parentTree.stdout)) {
            if ($item.EndsWith("`t.codex", [System.StringComparison]::Ordinal) -and
                -not $item.StartsWith('040000 tree ', [System.StringComparison]::Ordinal)) {
                throw 'Committed CES parent .codex is a file or gitlink, not a safe directory.'
            }
        }
    }
    if ($IsWindows -or $IsMacOS) {
        # Git pathspec names are byte/case-sensitive while many Windows and
        # macOS volumes are not. Reject aliases such as .CODEX/CES/owner.json
        # rather than trusting only the literal .codex/ces pathspec probes.
        # This bounded fallback is intentionally fail-closed for huge indexes.
        $allScopes = @(
            [pscustomobject]@{ args = @('ls-files','--cached','-z','--full-name'); kind = 'index' },
            [pscustomobject]@{ args = @('ls-tree','-r','--name-only','-z','HEAD'); kind = 'HEAD' }
        )
        if (-not [string]::IsNullOrEmpty($AdditionalTargetSha)) {
            $allScopes += [pscustomobject]@{
                args = @('ls-tree','-r','--name-only','-z',$AdditionalTargetSha)
                kind = 'pinned_target'
            }
        }
        foreach ($scope in $allScopes) {
            $allPaths = Git-In -GitExecutable $GitExecutable -Directory $RepoRoot -Arguments $scope.args -MaxStdoutBytes 16MB
            if (-not $allPaths.ok) { throw 'Windows case-collision safety scan could not enumerate tracked paths.' }
            foreach ($candidate in (Split-GitNulFields -Content $allPaths.stdout)) {
                if ([string]::Equals($candidate, '.codex', [System.StringComparison]::OrdinalIgnoreCase) -or
                    [string]::Equals($candidate, '.codex/ces', [System.StringComparison]::OrdinalIgnoreCase) -or
                    $candidate.StartsWith('.codex/ces/', [System.StringComparison]::OrdinalIgnoreCase)) {
                    throw 'CES state boundary overlaps a tracked Git path when case is ignored.'
                }
            }
        }
    }
    if (-not [string]::IsNullOrEmpty($AdditionalTargetSha)) {
        # A separately pinned DeliveredTarget may point to a commit other
        # than current HEAD; its business tree also must not own this path.
        if ($AdditionalTargetSha -cnotmatch '^[0-9a-f]{40,64}$') {
            throw 'Invalid pinned target object identity for CES storage boundary.'
        }
        $targetTree = Git-In -GitExecutable $GitExecutable -Directory $RepoRoot -Arguments @(
            'ls-tree', '-r', '--name-only', '-z', $AdditionalTargetSha, '--', '.codex/ces'
        ) -MaxStdoutBytes 4KB
        if (-not $targetTree.ok -or $targetTree.stdout.Length -gt 0) {
            throw 'CES storage boundary could not be proven clear in the pinned target tree.'
        }
    }
}

function Initialize-CodeSaveStore {
    param([string] $RepoRoot)

    # The input root must already equal the independently verified main
    # worktree root. All storage segments are fixed literals, not user paths.
    [void](Test-CodeSaveRegularItem -Path $RepoRoot -Directory $true)
    [void](Assert-CesNoReparseAncestry -Path $RepoRoot)
    $dotCodex = Join-Path $RepoRoot '.codex'
    $store = Join-Path $dotCodex 'ces'
    if ($null -ne (Get-CodeSaveOptionalItem -Path (Join-Path $dotCodex '.git'))) {
        throw 'CES parent is a nested Git repository; refusing to write inside it.'
    }
    $records = Join-Path $store 'code-insights'
    # Fixed CES segments must stay below the verified root with no reparse hop.
    [void](Assert-CesContainedPath -Root $RepoRoot -Path $records)
    foreach ($directory in @($dotCodex, $store)) {
        if ($null -eq (Get-CodeSaveOptionalItem -Path $directory)) {
            [void][System.IO.Directory]::CreateDirectory($directory)
        }
        [void](Test-CodeSaveRegularItem -Path $directory -Directory $true)
    }
    # Validate pre-existing children BEFORE claiming ownership/creating a
    # marker. A linked code-insights child must never cause an incidental write.
    if ($null -ne (Get-CodeSaveOptionalItem -Path $records)) {
        [void](Test-CodeSaveRegularItem -Path $records -Directory $true)
    }
    $ownerPath = Join-Path $store 'owner.json'
    $ownerBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($script:CodeSaveOwnerJson)
    if ($null -eq (Get-CodeSaveOptionalItem -Path $ownerPath)) {
        # Never take over a directory already containing unknown files.
        if (@([System.IO.Directory]::EnumerateFileSystemEntries($store)).Count -ne 0) {
            throw 'Unmarked CES state directory already contains content; refusing to take ownership.'
        }
        [void](Write-CodeSaveAtomicNewFile -Directory $store -LeafName 'owner.json' -Bytes $ownerBytes)
    } else {
        Assert-CodeSaveFileMatches -Path $ownerPath -Expected $ownerBytes
    }
    if (-not (Test-Path -LiteralPath $records)) {
        [void][System.IO.Directory]::CreateDirectory($records)
    }
    [void](Test-CodeSaveRegularItem -Path $records -Directory $true)
    # Recheck all ancestors after creation, though concurrent hostile directory
    # replacement cannot be made impossible without handle-relative OS APIs.
    [void](Test-CodeSaveRegularItem -Path $dotCodex -Directory $true)
    [void](Test-CodeSaveRegularItem -Path $store -Directory $true)
    Assert-CodeSaveFileMatches -Path $ownerPath -Expected $ownerBytes
    return $records
}

function CodeSave-Snapshot {
    param(
        [System.Collections.IDictionary] $Envelope,
        [string] $RepoPath,
        [string] $EvidencePath,
        [string] $InputPath,
        [string] $GitExecutable,
        [bool] $RevealPatches,
        [bool] $RevealUntrackedContent,
        [bool] $ApprovePersist
    )

    $Envelope.read_only = $false  # This action may create CES metadata, never business code.
    if (-not $ApprovePersist) {
        $Envelope.status = 'invalid_input'
        $Envelope.reason_code = 'CODE_SAVE_AUTHORIZATION_REQUIRED'
        $Envelope.message = 'CodeSave requires the explicit -ApprovePersist switch for local CES storage.'
        return 4
    }

    # Never trust a user-written claim of validated=true; execute the FULL
    # CodeValidate, CodePrepare and Reconcile chain with the current opt-ins.
    $checked = New-Envelope -ActionName 'CodeValidate'
    $verifyCode = CodeValidate-Snapshot -Envelope $checked -InputPath $InputPath -RepoPath $RepoPath -EvidencePath $EvidencePath -GitExecutable $GitExecutable -RevealPatches $RevealPatches -RevealUntrackedContent $RevealUntrackedContent
    $Envelope.coverage = $checked.coverage
    $Envelope.evidence = $checked.evidence
    $Envelope.warnings = $checked.warnings
    if ($verifyCode -ne 0 -or $null -eq $checked.data -or
        $checked.data.validated -ne $true -or $checked.reason_code -cne 'CODE_VALIDATE_OK') {
        $Envelope.status = if ($verifyCode -eq 0) { 'partial' } else { $checked.status }
        $Envelope.reason_code = 'CODE_SAVE_VALIDATION_FAILED'
        $Envelope.message = 'No CES record was saved: the draft did not pass a fresh source-bound CodeValidate gate.'
        $Envelope.data = [ordered]@{ persisted = $false; can_persist_ces_state = $false; validation_reason_code = $checked.reason_code }
        return $(if ($verifyCode -eq 0) { 2 } else { $verifyCode })
    }
    $result = $checked.data
    if (-not $result.stable_project_root -or -not (Paths-Equal -First $result.source_root -Second $result.stable_project_root)) {
        $Envelope.status = 'partial'
        $Envelope.reason_code = 'CODE_SAVE_MAIN_WORKTREE_REQUIRED'
        $Envelope.message = 'CES storage is restricted to the independently verified main worktree; linked or unverified roots are read-only.'
        $Envelope.data = [ordered]@{ persisted = $false; can_persist_ces_state = $false }
        return 2
    }

    # Build a deterministic, bounded metadata-only checked insight. No raw
    # evidence_quote, patch or untracked file body is stored in this record.
    $body = [ordered]@{
        schema_version = 'ces.code_insight_saved.v1'
        task_kind = 'code_analysis'
        source_root = $result.source_root
        source_mode = $result.source_mode
        saved_collect_sha256 = $result.saved_collect_sha256
        packet_sha256 = $result.packet_sha256
        draft_sha256 = $result.draft_sha256
        verification_scope = $result.verification_scope
        model_origin_authenticated = $false
        source_provenance_authenticated = $false
        semantic_claims_verified = $false
        claimed_line_numbers_verified = $false
        remote_delivery_verified = $false
        ci_verified = $false
        summary = $result.summary
        limitations = @($result.limitations)
        finding_count = $result.finding_count
        checked_findings = @($result.checked_findings)
    }
    $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $bytes = $utf8.GetBytes((ConvertTo-Json -InputObject $body -Depth 32 -Compress))
    if ($bytes.Length -gt $script:CodeSaveRecordByteLimit) {
        $Envelope.status = 'invalid_input'
        $Envelope.reason_code = 'CODE_SAVE_RECORD_TOO_LARGE'
        $Envelope.message = 'Checked insight exceeds the local CES record size limit; no record was saved.'
        return 4
    }
    $recordDigest = Get-HashOfBytes -Bytes $bytes
    $recordId = 'ci-' + $recordDigest
    $root = [string]$result.stable_project_root

    # Re-sample source and draft AFTER validating, before any storage write.
    $recheck = New-Envelope -ActionName 'Reconcile'
    $recheckCode = Reconcile-Snapshot -Envelope $recheck -InputPath $RepoPath -EvidencePath $EvidencePath -GitExecutable $GitExecutable
    $draftStable = $false
    try {
        $after = Read-CodeValidateDraft -Path $InputPath
        $draftStable = ($after.sha256 -ceq $result.draft_sha256)
    } catch { $draftStable = $false }
    if ($recheckCode -ne 0 -or $null -eq $recheck.data -or
        $recheck.data.verdict -cne 'matched' -or
        $recheck.data.previous_snapshot.snapshot_file_sha256 -cne $result.saved_collect_sha256 -or
        -not $draftStable) {
        $Envelope.status = 'partial'
        $Envelope.reason_code = 'CODE_SAVE_SOURCE_CHANGED'
        $Envelope.message = 'Source, evidence or draft changed before persistence; no record was saved.'
        $Envelope.data = [ordered]@{ persisted = $false; can_persist_ces_state = $false }
        return 2
    }

    # The pinned delivered target is not necessarily the current HEAD.
    # Use ONLY the already verified, exactly saved Collect selector.
    $extraTarget = $null
    if ($result.source_mode -ceq 'delivered_target_diff') {
        try {
            $sourceFile = Read-ReconcileSnapshotFile -Path $EvidencePath
            if ($sourceFile.sha256 -cne $result.saved_collect_sha256) {
                throw 'Saved Collect changed before final storage check.'
            }
            $sourceJson = ConvertFrom-Json -InputObject $sourceFile.text -AsHashtable -Depth 32 -ErrorAction Stop
            if ($sourceJson.data.subject.source_mode -cne 'delivered_target_diff') {
                throw 'Pinned target mode changed in saved evidence.'
            }
            $extraTarget = [string]$sourceJson.data.subject.target_sha
        } catch {
            $Envelope.status = 'partial'
            $Envelope.reason_code = 'CODE_SAVE_SOURCE_CHANGED'
            $Envelope.message = 'The pinned target selector could not be rechecked; no record was saved.'
            $Envelope.data = [ordered]@{ persisted = $false; can_persist_ces_state = $false }
            return 2
        }
    }
    try {
        [void](Assert-CesVerifiedMainWorktree -GitExecutable $GitExecutable -RepoRoot $root)
        Assert-CodeSaveGitBoundary -GitExecutable $GitExecutable -RepoRoot $root -AdditionalTargetSha $extraTarget
        $records = Initialize-CodeSaveStore -RepoRoot $root
        # Reprobe Git/root and tracked state once more before no-clobber move.
        [void](Assert-CesVerifiedMainWorktree -GitExecutable $GitExecutable -RepoRoot $root)
        Assert-CodeSaveGitBoundary -GitExecutable $GitExecutable -RepoRoot $root -AdditionalTargetSha $extraTarget
        $created = Write-CodeSaveAtomicNewFile -Directory $records -LeafName ($recordId + '.json') -Bytes $bytes
        $recordFile = Join-Path $records ($recordId + '.json')
        Assert-CodeSaveFileMatches -Path $recordFile -Expected $bytes
    } catch {
        $Envelope.status = 'unavailable'
        $Envelope.reason_code = 'CODE_SAVE_STORE_UNSAFE_OR_UNAVAILABLE'
        $Envelope.message = 'The CES-owned storage path is unsafe, conflicting or not writable; no record was confirmed.'
        $Envelope.warnings = @((Limit-Text (Redact-CesKnownPaths -Message $_.Exception.Message -SensitivePaths @($root, $RepoPath, $EvidencePath, $InputPath)) 300))
        $Envelope.data = [ordered]@{ persisted = $false; can_persist_ces_state = $false }
        return 5
    }

    $Envelope.coverage.code_result_persisted = $true
    $Envelope.status = 'success'
    $Envelope.reason_code = if ($created) { 'CODE_SAVE_OK' } else { 'CODE_SAVE_ALREADY_PRESENT' }
    $Envelope.message = if ($created) { 'Validated CodeInsight saved locally in CES-owned state without source or Git mutations.' } else { 'An identical validated CodeInsight record already exists; no file was overwritten.' }
    $Envelope.data = [ordered]@{
        persisted = $true
        created = $created
        can_persist_ces_state = $true
        record_schema = 'ces.code_insight_saved.v1'
        record_id = $recordId
        record_sha256 = $recordDigest
        record_path = $recordFile
        source_mode = $result.source_mode
        finding_count = $result.finding_count
        model_origin_authenticated = $false
        semantic_claims_verified = $false
        remote_delivery_verified = $false
        ci_verified = $false
        business_source_modified = $false
    }
    return 0
}
