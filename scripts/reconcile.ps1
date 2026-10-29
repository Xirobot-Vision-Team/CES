#requires -Version 7.0
<#
    EC-005: local, read-only reconciliation of an explicitly saved CES Collect
    JSON observation with a fresh observation of the SAME repository/selector.
    A file supplied by a user is not authenticated provenance. No raw source
    diff is emitted by Reconcile, no snapshot is persisted, and equality of two
    samples does not imply that an intervening worktree/ref never changed.
#>

$script:ReconcileEvidenceByteLimit = 4MB
$script:ReconcileChangedEntryPreviewLimit = 25

function Get-ReconcileProperty {
    param([AllowNull()][object] $Object, [string] $Key)
    if ($Object -is [System.Collections.IDictionary] -and $Object.Contains($Key)) {
        return $Object[$Key]
    }
    return $null
}

function Read-ReconcileSnapshotFile {
    param([Parameter(Mandatory)][string] $Path)

    $file = Get-Item -LiteralPath $Path -ErrorAction Stop
    if (-not ($file -is [System.IO.FileInfo])) { throw 'EvidencePath must name a file.' }
    if (($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'EvidencePath cannot be a symbolic link or reparse point.'
    }
    # EC-159: verify every existing parent too; the filename alone is not enough.
    [void](Resolve-CesEvidencePath -Path $file.FullName -RelativeTo $file.FullName)
    $stream = [System.IO.FileStream]::new(
        $file.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
        ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
    )
    try {
        if ($stream.Length -gt $script:ReconcileEvidenceByteLimit) {
            throw 'Evidence file exceeds the bounded 4 MiB input limit.'
        }
        $bytes = [byte[]]::new([int]$stream.Length)
        $read = 0
        while ($read -lt $bytes.Length) {
            $n = $stream.Read($bytes, $read, $bytes.Length - $read)
            if ($n -le 0) { throw 'Evidence file changed or ended during its read.' }
            $read += $n
        }
        if ($stream.Length -ne $bytes.Length) { throw 'Evidence file size changed while reading.' }
        $text = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        if ($text.StartsWith([string][char]0xFEFF, [System.StringComparison]::Ordinal)) {
            $text = $text.Substring(1)
        }
        return [pscustomobject]@{
            full_path = $file.FullName
            bytes = $bytes.Length
            sha256 = (Get-HashOfBytes -Bytes $bytes)
            text = $text
        }
    } finally {
        $stream.Dispose()
    }
}

function Assert-ReconcilePatchRecord {
    param([System.Collections.IDictionary] $Record)

    if ($null -eq $Record -or -not $Record.Contains('state') -or -not $Record.Contains('patch_state') -or
        -not $Record.Contains('entries') -or -not $Record.Contains('count')) {
        throw 'A required source-layer record is missing.'
    }
    if ($Record.state -notin @('complete','entry_limit','unavailable','parse_error')) {
        throw 'Unrecognized layer inventory state.'
    }
    if ($Record.state -eq 'complete') {
        if ($Record.count -isnot [long] -and $Record.count -isnot [int]) { throw 'Complete inventory count is not an integer.' }
        if ($Record.count -lt 0 -or $Record.count -gt $script:CollectEntryLimit -or @($Record.entries).Count -ne $Record.count) {
            throw 'Complete inventory count and records are inconsistent.'
        }
    }
    if ($Record.patch_state -notin @('not_requested','included','included_with_exclusions','empty',
        'sensitive_paths_excluded','path_limit','byte_limit','timeout','git_error',
        'entry_limit','unavailable','discarded_unstable_snapshot','discarded_unstable_target_ref')) {
        throw 'Unrecognized patch state.'
    }
    if ($Record.patch_state -in @('included','included_with_exclusions')) {
        if ($Record.patch -isnot [string] -or $Record.patch_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            (Get-HashOfText -Content $Record.patch) -cne $Record.patch_sha256) {
            throw 'Included patch bytes do not match the supplied SHA-256.'
        }
    } elseif ($null -ne $Record.patch -or $null -ne $Record.patch_sha256) {
        throw 'Snapshot contains a patch or patch hash without included content state.'
    }
    foreach ($entry in @($Record.entries)) {
        if ($entry -isnot [System.Collections.IDictionary] -or
            (Get-ReconcileProperty $entry 'path') -isnot [string] -or [string]::IsNullOrEmpty($entry.path) -or
            (Get-ReconcileProperty $entry 'status') -isnot [string] -or -not $entry.Contains('old_path') -or
            $entry.status -cnotmatch '^(?:[ACDMRTUXB]|[RC][0-9]{1,3})$') {
            throw 'Inventory contains an invalid Git path/status entry.'
        }
    }
}

function Assert-ReconcileSnapshot {
    param([System.Collections.IDictionary] $Snapshot)

    if ($Snapshot.schema_version -cne 'ces.cli.v1' -or $Snapshot.action -cne 'Collect' -or
        $Snapshot.status -notin @('success','partial') -or $Snapshot.read_only -ne $true -or
        $Snapshot.data -isnot [System.Collections.IDictionary] -or
        $Snapshot.data.subject -isnot [System.Collections.IDictionary] -or
        $Snapshot.data.subject.kind -cne 'code' -or
        $Snapshot.data.snapshot -isnot [System.Collections.IDictionary] -or
        $Snapshot.data.snapshot.atomic -ne $false -or
        $Snapshot.coverage -isnot [System.Collections.IDictionary] -or
        $Snapshot.data.can_persist_ces_state -ne $false) {
        throw 'Evidence must be an actual-format read-only Collect envelope (ces.cli.v1).'
    }
    $mode = [string]$Snapshot.data.subject.source_mode
    if ($mode -eq 'working_tree_diff') {
        if ([string]::IsNullOrWhiteSpace([string]$Snapshot.data.source_root) -or
            $Snapshot.data.head -isnot [System.Collections.IDictionary] -or
            $Snapshot.data.head.state -notin @('attached','detached','unborn','unknown') -or
            $Snapshot.data.staged -isnot [System.Collections.IDictionary] -or
            $Snapshot.data.unstaged -isnot [System.Collections.IDictionary] -or
            $Snapshot.data.untracked -isnot [System.Collections.IDictionary]) {
            throw 'WorkingTree observation is missing required layers or root.'
        }
        Assert-ReconcilePatchRecord -Record $Snapshot.data.staged
        Assert-ReconcilePatchRecord -Record $Snapshot.data.unstaged
        $u = $Snapshot.data.untracked
        if ($u.state -notin @('complete','entry_limit','unavailable','parse_error') -or
            $null -eq $u.entries -or $u.content_requested -isnot [bool]) {
            throw 'Invalid untracked inventory record.'
        }
        if ($u.state -eq 'complete' -and (
            (($u.count -isnot [int]) -and ($u.count -isnot [long])) -or $u.count -lt 0 -or
            $u.count -gt $script:CollectEntryLimit -or @($u.entries).Count -ne $u.count)) {
            throw 'Untracked count does not match complete inventory.'
        }
        foreach ($entry in @($u.entries)) {
            if ($entry -isnot [System.Collections.IDictionary] -or
                $entry.path -isnot [string] -or [string]::IsNullOrEmpty($entry.path) -or
                $entry.content_state -notin @('not_requested','included','sensitive_path_excluded',
                    'too_large','unsafe_or_missing','changed_or_unreadable','non_utf8','binary_or_control',
                    'total_byte_limit','discarded_unstable_snapshot')) {
                throw 'Untracked content record is invalid.'
            }
            if ($entry.content_state -eq 'included') {
                if ($u.content_requested -ne $true -or $entry.content -isnot [string] -or
                    $entry.sha256 -cnotmatch '^[0-9a-f]{64}$') {
                    throw 'Included untracked content is incomplete.'
                }
                # The original collector hashes file bytes and can remove a
                # UTF-8 BOM from the rendered content; honor both encodings.
                $raw = [System.Text.Encoding]::UTF8.GetBytes($entry.content)
                $plainHash = Get-HashOfBytes -Bytes $raw
                $bomBytes = [byte[]]@(239, 187, 191) + $raw
                $bomHash = Get-HashOfBytes -Bytes $bomBytes
                $valid = (($plainHash -ceq $entry.sha256 -and $raw.Length -eq $entry.size_bytes) -or
                          ($bomHash -ceq $entry.sha256 -and $bomBytes.Length -eq $entry.size_bytes))
                if (-not $valid) { throw 'Untracked content bytes do not match the supplied SHA-256/size.' }
            } elseif ($null -ne $entry.content) {
                throw 'Untracked content appeared without an included state.'
            }
        }
        return 'WorkingTree'
    }
    if ($mode -eq 'delivered_target_diff') {
        $s = $Snapshot.data.subject
        if (-not (Test-FullCommitId ([string]$s.base_sha)) -or
            -not (Test-FullCommitId ([string]$s.target_sha)) -or
            $s.base_sha.Length -ne $s.target_sha.Length -or
            $s.target_ref -isnot [string] -or $s.target_ref.Length -gt 1024 -or
            $s.target_ref -cnotmatch '^refs/(?:heads|remotes)/[^\x00-\x20\x7F]+$' -or
            $Snapshot.data.changes -isnot [System.Collections.IDictionary]) {
            throw 'DeliveredTarget selector or change inventory is invalid.'
        }
        Assert-ReconcilePatchRecord -Record $Snapshot.data.changes
        return 'DeliveredTarget'
    }
    throw 'Only the implemented WorkingTree and DeliveredTarget collectors are comparable.'
}

function Get-ReconcileEntryKey {
    param([object] $Entry, [bool] $Untracked)
    if ($Untracked) { return [string]$Entry.path }
    $old = if ($null -ne $Entry.old_path) { [string]$Entry.old_path } else { '' }
    return ([string]$Entry.status + [char]0 + $old + [char]0 + [string]$Entry.path)
}

function Get-ReconcileEntryPreview {
    param([object] $Entry, [bool] $Untracked)
    if ($Untracked) { return [ordered]@{ path = [string]$Entry.path } }
    return [ordered]@{ status = [string]$Entry.status; path = [string]$Entry.path; old_path = $Entry.old_path }
}

function Compare-ReconcileInventory {
    param([object] $Prior, [object] $Current, [bool] $Untracked)

    $result = [ordered]@{
        previous_state = $Prior.state
        current_state = if ($null -ne $Current) { $Current.state } else { 'unavailable' }
        previous_count = $Prior.count
        current_count = if ($null -ne $Current) { $Current.count } else { $null }
        state = 'indeterminate'
        added_count = $null
        removed_count = $null
        added_preview = @()
        removed_preview = @()
        preview_limit_per_direction = $script:ReconcileChangedEntryPreviewLimit
    }
    if ($null -eq $Current -or $Prior.state -cne 'complete' -or $Current.state -cne 'complete') {
        return $result
    }
    $before = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::Ordinal)
    $after = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::Ordinal)
    foreach ($entry in @($Prior.entries)) {
        $key = Get-ReconcileEntryKey -Entry $entry -Untracked $Untracked
        if ($before.ContainsKey($key)) { return $result }
        $before[$key] = $entry
    }
    foreach ($entry in @($Current.entries)) {
        $key = Get-ReconcileEntryKey -Entry $entry -Untracked $Untracked
        if ($after.ContainsKey($key)) { return $result }
        $after[$key] = $entry
    }
    $added = [System.Collections.Generic.List[object]]::new()
    $removed = [System.Collections.Generic.List[object]]::new()
    $keysAfter = [string[]]::new($after.Count)
    $after.Keys.CopyTo($keysAfter, 0)
    [array]::Sort($keysAfter, [System.StringComparer]::Ordinal)
    $keysBefore = [string[]]::new($before.Count)
    $before.Keys.CopyTo($keysBefore, 0)
    [array]::Sort($keysBefore, [System.StringComparer]::Ordinal)
    foreach ($key in $keysAfter) {
        if (-not $before.ContainsKey($key)) { $added.Add((Get-ReconcileEntryPreview $after[$key] $Untracked)) }
    }
    foreach ($key in $keysBefore) {
        if (-not $after.ContainsKey($key)) { $removed.Add((Get-ReconcileEntryPreview $before[$key] $Untracked)) }
    }
    $result.added_count = $added.Count
    $result.removed_count = $removed.Count
    $result.added_preview = @($added.ToArray() | Select-Object -First $script:ReconcileChangedEntryPreviewLimit)
    $result.removed_preview = @($removed.ToArray() | Select-Object -First $script:ReconcileChangedEntryPreviewLimit)
    $result.state = if ($added.Count -eq 0 -and $removed.Count -eq 0) { 'matched' } else { 'changed' }
    return $result
}

function Compare-ReconcilePatch {
    param([object] $Prior, [object] $Current)
    $result = [ordered]@{
        previous_state = $Prior.patch_state
        current_state = if ($null -ne $Current) { $Current.patch_state } else { 'unavailable' }
        state = 'not_requested'
        previous_sha256 = $null
        current_sha256 = $null
    }
    if ($Prior.patch_state -ceq 'not_requested') { return $result }
    if ($null -eq $Current -or $Prior.patch_state -notin @('included','included_with_exclusions','empty') -or
        $Current.patch_state -notin @('included','included_with_exclusions','empty')) {
        $result.state = 'indeterminate'
        return $result
    }
    $result.previous_sha256 = $Prior.patch_sha256
    $result.current_sha256 = $Current.patch_sha256
    $result.state = if ($Prior.patch_state -ceq $Current.patch_state -and
        $Prior.patch_sha256 -ceq $Current.patch_sha256) { 'matched' } else { 'changed' }
    return $result
}

function Compare-ReconcileUntrackedContent {
    param([object] $Prior, [object] $Current)
    $result = [ordered]@{
        requested = [bool]$Prior.content_requested
        state = 'not_requested'
        included_previous = 0
        included_current = 0
        changed_paths_preview = @()
        changed_count = 0
        unavailable_count = 0
    }
    if (-not $Prior.content_requested) { return $result }
    if ($null -eq $Current) { $result.state = 'indeterminate'; return $result }
    $old = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::Ordinal)
    $now = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::Ordinal)
    foreach ($entry in @($Prior.entries)) { $old[[string]$entry.path] = $entry }
    foreach ($entry in @($Current.entries)) { $now[[string]$entry.path] = $entry }
    $changed = [System.Collections.Generic.List[string]]::new()
    foreach ($path in $old.Keys) {
        $before = $old[$path]
        if ($before.content_state -eq 'included') { $result.included_previous++ }
        if (-not $now.ContainsKey($path)) { $result.unavailable_count++; continue } # inventory reports path drift
        $after = $now[$path]
        if ($after.content_state -eq 'included') { $result.included_current++ }
        if ($before.content_state -eq 'included' -and $after.content_state -eq 'included') {
            if ($before.sha256 -cne $after.sha256) { $changed.Add($path) }
        } else { $result.unavailable_count++ }
    }
    $result.changed_count = $changed.Count
    $result.changed_paths_preview = @($changed.ToArray() | Select-Object -First $script:ReconcileChangedEntryPreviewLimit)
    $result.state = if ($changed.Count -gt 0) { 'changed' }
                    elseif ($result.unavailable_count -gt 0 -or $Prior.state -ne 'complete' -or $Current.state -ne 'complete') { 'indeterminate' }
                    else { 'matched' }
    return $result
}

function Reconcile-Snapshot {
    param(
        [System.Collections.IDictionary] $Envelope,
        [string] $InputPath,
        [string] $EvidencePath,
        [string] $GitExecutable
    )

    if ([string]::IsNullOrWhiteSpace($EvidencePath)) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'EVIDENCE_PATH_REQUIRED'
        $Envelope.message = 'Reconcile requires an explicitly saved local -EvidencePath from a prior Collect -Json output.'
        return 4
    }
    $file = $null
    $prior = $null
    $sourceMode = ''
    try {
        $file = Read-ReconcileSnapshotFile -Path $EvidencePath
        $prior = ConvertFrom-Json -InputObject $file.text -AsHashtable -Depth 32 -ErrorAction Stop
        if ($prior -isnot [System.Collections.IDictionary]) { throw 'Evidence root is not a JSON object.' }
        $sourceMode = Assert-ReconcileSnapshot -Snapshot $prior
    } catch {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'EVIDENCE_INVALID'
        $Envelope.message = 'EvidencePath is unreadable, oversize, malformed, or not a compatible CES Collect snapshot.'
        $Envelope.warnings = @((Limit-Text $_.Exception.Message 250))
        return 4
    }

    $guard = New-Envelope -ActionName 'Inspect'
    $guardCode = Inspect-Repository -Envelope $guard -InputPath $InputPath -GitExecutable $GitExecutable
    if ($guardCode -in @(4, 5)) {
        $Envelope.status = $guard.status; $Envelope.reason_code = $guard.reason_code
        $Envelope.message = $guard.message; $Envelope.warnings = $guard.warnings
        $Envelope.evidence = $guard.evidence
        return $guardCode
    }
    $previousRoot = if ($sourceMode -eq 'DeliveredTarget' -and $prior.data.worktree_kind -eq 'bare') {
        [string]$prior.data.object_repository_path
    } else { [string]$prior.data.source_root }
    $currentRoot = if ($guard.data.worktree_kind -eq 'bare') {
        [string]$guard.data.resolved_path
    } else { [string]$guard.data.source_root }
    if (-not (Paths-Equal -First $previousRoot -Second $currentRoot) -or
        [string]$prior.data.worktree_kind -cne [string]$guard.data.worktree_kind) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'EVIDENCE_REPO_MISMATCH'
        $Envelope.message = 'Saved Collect evidence belongs to a different Git source root or worktree kind; no cross-repository comparison was made.'
        return 4
    }
    $Envelope.coverage.repository_checked = $true
    $Envelope.coverage.snapshot_file_checked = $true
    $Envelope.coverage.source_bound = $true
    $previous = $prior.data
    $modeFlags = if ($sourceMode -eq 'WorkingTree') {
        [pscustomobject]@{
            patches = ($previous.staged.patch_state -ne 'not_requested' -or $previous.unstaged.patch_state -ne 'not_requested')
            untracked = [bool]$previous.untracked.content_requested
        }
    } else {
        [pscustomobject]@{ patches = ($previous.changes.patch_state -ne 'not_requested'); untracked = $false }
    }

    $newEnvelope = New-Envelope -ActionName 'Collect'
    $newCode = if ($sourceMode -eq 'WorkingTree') {
        Collect-WorkingTree -Envelope $newEnvelope -InputPath $InputPath -GitExecutable $GitExecutable -RequestPatches $modeFlags.patches -RequestUntrackedContent $modeFlags.untracked
    } else {
        Collect-DeliveredTarget -Envelope $newEnvelope -InputPath $InputPath -GitExecutable $GitExecutable -BaseSha $previous.subject.base_sha -TargetSha $previous.subject.target_sha -TargetRef $previous.subject.target_ref -RequestPatches $modeFlags.patches -RequestUntrackedContent $false
    }
    $fileStable = $false
    try {
        $endFile = Read-ReconcileSnapshotFile -Path $file.full_path
        $fileStable = ($endFile.sha256 -ceq $file.sha256 -and $endFile.bytes -eq $file.bytes)
    } catch { $fileStable = $false }
    $Envelope.coverage.snapshot_file_stable = $fileStable

    $refChanged = $false
    $refResult = [ordered]@{ state = 'not_applicable'; pinned_sha = $null; current_sha = $null }
    if ($sourceMode -eq 'DeliveredTarget') {
        $refResult.pinned_sha = $previous.subject.target_sha
        if ($newCode -eq 4 -and $newEnvelope.reason_code -eq 'TARGET_REF_MISMATCH') {
            $refProbe = Get-ExactTargetRef -GitExecutable $GitExecutable -Directory $currentRoot -Ref $previous.subject.target_ref
            if ($refProbe.ok -and (Test-FullCommitId $refProbe.stdout)) {
                $refResult.current_sha = $refProbe.stdout.ToLowerInvariant()
                $refChanged = ($refResult.current_sha -cne $refResult.pinned_sha)
                $refResult.state = if ($refChanged) { 'changed' } else { 'indeterminate' }
            } else { $refResult.state = 'indeterminate' }
        } elseif ($newCode -in @(0, 2)) {
            $refResult.current_sha = $newEnvelope.data.snapshot.target_ref_sha_at_end
            $refResult.state = if ($newEnvelope.coverage.target_ref_checked -and
                $newEnvelope.coverage.consistency_checked) { 'matched' } else { 'indeterminate' }
        } else { $refResult.state = 'indeterminate' }
    }

    $comparison = [ordered]@{}
    $states = [System.Collections.Generic.List[string]]::new()
    if ($refChanged) { $states.Add('changed') }
    if ($refResult.state -eq 'indeterminate') { $states.Add('indeterminate') }
    $new = if ($newCode -in @(0,2)) { $newEnvelope.data } else { $null }
    if ($sourceMode -eq 'WorkingTree') {
        $head = [ordered]@{
            previous_sha = $previous.head.sha
            current_sha = if ($null -ne $new) { $new.head.sha } else { $null }
            previous_branch = $previous.head.branch
            current_branch = if ($null -ne $new) { $new.head.branch } else { $null }
            previous_state = $previous.head.state
            current_state = if ($null -ne $new) { $new.head.state } else { $null }
            state = 'indeterminate'
        }
        if ($null -ne $new) {
            $head.state = if ($head.previous_sha -ceq $head.current_sha -and
                $head.previous_branch -ceq $head.current_branch -and
                $head.previous_state -ceq $head.current_state) { 'matched' } else { 'changed' }
        }
        $comparison.head = $head
        $states.Add($head.state)
        foreach ($layer in @('staged','unstaged')) {
            $inventory = Compare-ReconcileInventory -Prior $previous[$layer] -Current $(if ($null -ne $new) { $new[$layer] } else { $null }) -Untracked $false
            $content = Compare-ReconcilePatch -Prior $previous[$layer] -Current $(if ($null -ne $new) { $new[$layer] } else { $null })
            $comparison[$layer] = [ordered]@{ inventory = $inventory; patch = $content }
            $states.Add($inventory.state); if ($content.state -ne 'not_requested') { $states.Add($content.state) }
        }
        $currentUntracked = if ($null -ne $new) { $new.untracked } else { $null }
        $uinventory = Compare-ReconcileInventory -Prior $previous.untracked -Current $currentUntracked -Untracked $true
        $ucontent = Compare-ReconcileUntrackedContent -Prior $previous.untracked -Current $currentUntracked
        $comparison.untracked = [ordered]@{ inventory = $uinventory; content = $ucontent }
        $states.Add($uinventory.state); if ($ucontent.state -ne 'not_requested') { $states.Add($ucontent.state) }
    } else {
        $currentChanges = if ($null -ne $new) { $new.changes } else { $null }
        $inventory = Compare-ReconcileInventory -Prior $previous.changes -Current $currentChanges -Untracked $false
        $content = Compare-ReconcilePatch -Prior $previous.changes -Current $currentChanges
        $comparison.changes = [ordered]@{ inventory = $inventory; patch = $content }
        $comparison.target_ref = $refResult
        $states.Add($inventory.state); if ($content.state -ne 'not_requested') { $states.Add($content.state) }
    }

    $problems = [System.Collections.Generic.List[string]]::new()
    if (-not $fileStable) { $problems.Add('evidence_file_changed_or_unavailable') }
    if ($prior.status -ne 'success' -or $prior.coverage.consistency_checked -ne $true -or
        $prior.data.snapshot.consistency -eq 'changed_or_unverified') {
        $problems.Add('previous_snapshot_not_complete_or_stable')
    }
    if ($newCode -ne 0 -or -not $newEnvelope.coverage.consistency_checked) {
        $problems.Add('current_collect_not_complete_or_stable')
    }
    if ($states.Contains('indeterminate')) { $problems.Add('one_or_more_comparisons_unavailable') }
    if ($states.Contains('changed')) { $problems.Add('observed_git_evidence_changed') }
    # The input file is untrusted as to authorship even if internally coherent.
    # Verified equality means only two accessible, sampled observations match.
    $verdict = if (-not $fileStable) { 'indeterminate' }
               elseif ($states.Contains('changed')) { 'changed' }
               elseif ($problems.Count -gt 0) { 'indeterminate' }
               else { 'matched' }
    $inventoryStates = if ($sourceMode -eq 'WorkingTree') {
        @($comparison.head.state, $comparison.staged.inventory.state,
            $comparison.unstaged.inventory.state, $comparison.untracked.inventory.state)
    } else { @($comparison.target_ref.state, $comparison.changes.inventory.state) }
    $contentStates = if ($sourceMode -eq 'WorkingTree') {
        @($comparison.staged.patch.state, $comparison.unstaged.patch.state, $comparison.untracked.content.state)
    } else { @($comparison.changes.patch.state) }
    $Envelope.coverage.compared_inventory = ($inventoryStates -notcontains 'indeterminate')
    $Envelope.coverage.compared_content = ($modeFlags.patches -or $modeFlags.untracked) -and ($contentStates -notcontains 'indeterminate')
    $Envelope.coverage.consistency_checked = ($fileStable -and $prior.coverage.consistency_checked -eq $true -and $newEnvelope.coverage.consistency_checked -eq $true)
    $Envelope.data = [ordered]@{
        source_root = $currentRoot
        stable_project_root = $guard.data.stable_project_root
        stable_root_verified = $guard.data.stable_root_verified
        can_persist_ces_state = $false
        subject = [ordered]@{
            kind = 'code'
            source_mode = $previous.subject.source_mode
            base_sha = $previous.subject.base_sha
            target_sha = if ($sourceMode -eq 'DeliveredTarget') { $previous.subject.target_sha } else { $null }
            target_ref = if ($sourceMode -eq 'DeliveredTarget') { $previous.subject.target_ref } else { $null }
            verification_scope = 'local_repository_only'
            remote_delivery_verified = $false
            deployment_verified = $false
            pr_association_verified = $false
        }
        previous_snapshot = [ordered]@{
            product_version = $prior.product_version
            build = $prior.build
            status = $prior.status
            observed_at_utc = $previous.snapshot.observed_at_utc
            snapshot_file_sha256 = $file.sha256
            snapshot_file_bytes = $file.bytes
            snapshot_file_stable = $fileStable
            provenance_authenticated = $false
            atomic = $false
        }
        current_snapshot = [ordered]@{
            collect_status = $newEnvelope.status
            collect_reason_code = $newEnvelope.reason_code
            observed_at_utc = if ($null -ne $new) { $new.snapshot.observed_at_utc } else { $null }
            consistency = if ($null -ne $new) { $new.snapshot.consistency } else { 'not_available' }
            atomic = $false
        }
        comparison = $comparison
        verdict = $verdict
        limitations = $problems.ToArray()
        notes = 'Equality compares sampled local Git observations only. The file is user-supplied and not cryptographically authenticated; intermediate changes, remote publication, CI and deployment are not verified. No raw diff or untracked text is returned.'
    }
    $Envelope.warnings = @($problems.ToArray())
    $Envelope.evidence = @(
        [ordered]@{ check = 'snapshot_input_sha256'; sha256 = $file.sha256; stable_on_recheck = $fileStable },
        [ordered]@{ check = 'fresh_collect'; status = $newEnvelope.status; reason_code = $newEnvelope.reason_code; exit_code = $newCode }
    )
    if ($verdict -eq 'matched') {
        $Envelope.status = 'success'; $Envelope.reason_code = 'RECONCILE_MATCHED'
        $Envelope.message = 'Saved and current local Git observations match for the captured scope; no intervening atomicity or authenticity is implied.'
        return 0
    }
    $Envelope.status = 'partial'
    $Envelope.reason_code = if ($verdict -eq 'changed') { 'RECONCILE_CHANGED' } else { 'RECONCILE_INDETERMINATE' }
    $Envelope.message = if ($verdict -eq 'changed') {
        'Local Git evidence has changed since the supplied snapshot; the saved observation is historical, not the current state.'
    } else {
        'Snapshot reconciliation has incomplete or unstable evidence and cannot establish current equivalence.'
    }
    return 2
}
