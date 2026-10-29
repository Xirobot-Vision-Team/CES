#requires -Version 7.0
<#
    EC-004: read-only, locally verified target-ref commit-range collection.
    Diff comparison is between two pinned commit trees, NOT the checkout/index,
    and NOT proof of a remote merge, release, deployment or PR association.
    Loaded from the trusted CES Skill directory, never from the analyzed repo.
#>

function Test-FullCommitId {
    param([AllowNull()][string] $Value)
    return (-not [string]::IsNullOrWhiteSpace($Value) -and $Value -cmatch '^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$')
}

function Get-ExactTargetRef {
    param([string] $GitExecutable, [string] $Directory, [string] $Ref)
    # show-ref --verify does an exact ref lookup, not DWIM short-name resolution.
    return Git-In -GitExecutable $GitExecutable -Directory $Directory -Arguments @('show-ref', '--verify', '--hash', $Ref) -MaxStdoutBytes 512
}

function Test-PinnedCommitObject {
    param([string] $GitExecutable, [string] $Directory, [string] $Sha)
    # Full hexadecimal object IDs only. git cat-file does not peel annotated
    # tags or accept a branch name here; object must literally be a commit.
    $type = Git-In -GitExecutable $GitExecutable -Directory $Directory -Arguments @('cat-file', '-t', $Sha) -MaxStdoutBytes 128
    return ($type.ok -and $type.stdout -ceq 'commit')
}

function Invoke-DeliveredInventoryProbe {
    param([string] $GitExecutable, [string] $Directory, [string] $BaseSha, [string] $TargetSha)
    return Git-In -GitExecutable $GitExecutable -Directory $Directory -Arguments @(
        'diff', '--name-status', '-z', '--find-renames', '--no-ext-diff',
        '--no-textconv', '--no-color', '--ignore-submodules=none',
        $BaseSha, $TargetSha, '--'
    ) -MaxStdoutBytes $script:CollectInventoryByteLimit
}

function Get-DeliveredPatch {
    param(
        [string] $GitExecutable,
        [string] $Directory,
        [string] $BaseSha,
        [string] $TargetSha,
        [object[]] $Entries
    )
    # This is an opt-in raw patch, not content-secret-scanned. If a rename
    # touches a protected name, exclude BOTH endpoints from patch selection.
    $safePaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $excluded = 0
    foreach ($entry in $Entries) {
        if ($entry.sensitive_path) { $excluded++; continue }
        [void] $safePaths.Add([string]$entry.path)
        if ($null -ne $entry.old_path) { [void] $safePaths.Add([string]$entry.old_path) }
    }
    if ($safePaths.Count -gt $script:CollectPatchPathLimit) {
        return [pscustomobject]@{ state = 'path_limit'; text = $null; sha256 = $null; excluded_sensitive = $excluded; path_count = $safePaths.Count }
    }
    if ($safePaths.Count -eq 0) {
        $state = if ($excluded -gt 0) { 'sensitive_paths_excluded' } else { 'empty' }
        return [pscustomobject]@{ state = $state; text = $null; sha256 = $null; excluded_sensitive = $excluded; path_count = 0 }
    }
    $args = @(
        'diff', '--binary', '--full-index', '--find-renames', '--no-ext-diff',
        '--no-textconv', '--no-color', '--ignore-submodules=none',
        $BaseSha, $TargetSha, '--'
    )
    foreach ($path in ($safePaths | Sort-Object -CaseSensitive)) {
        # Literal pathspecs keep '[' '*' '?' and other Git glob tokens inert.
        $args += (':(literal)' + $path)
    }
    $probe = Git-In -GitExecutable $GitExecutable -Directory $Directory -Arguments $args -MaxStdoutBytes $script:CollectPatchByteLimit -PreserveStdout
    if (-not $probe.ok) {
        $state = if ($probe.over_limit) { 'byte_limit' } elseif ($probe.timed_out) { 'timeout' } else { 'git_error' }
        return [pscustomobject]@{ state = $state; text = $null; sha256 = $null; excluded_sensitive = $excluded; path_count = $safePaths.Count }
    }
    return [pscustomobject]@{
        state = if ($excluded -gt 0) { 'included_with_exclusions' } else { 'included' }
        text = $probe.stdout
        sha256 = (Get-HashOfText -Content $probe.stdout)
        excluded_sensitive = $excluded
        path_count = $safePaths.Count
    }
}

function Collect-DeliveredTarget {
    param(
        [System.Collections.IDictionary] $Envelope,
        [string] $InputPath,
        [string] $GitExecutable,
        [string] $BaseSha,
        [string] $TargetSha,
        [string] $TargetRef,
        [bool] $RequestPatches,
        [bool] $RequestUntrackedContent
    )

    if ($RequestUntrackedContent) {
        $Envelope.status = 'invalid_input'
        $Envelope.reason_code = 'UNTRACKED_NOT_APPLICABLE'
        $Envelope.message = 'DeliveredTarget reads committed Git objects; -IncludeUntrackedContent is only valid for WorkingTree.'
        return 4
    }
    if (-not (Test-FullCommitId $BaseSha) -or -not (Test-FullCommitId $TargetSha)) {
        $Envelope.status = 'invalid_input'
        $Envelope.reason_code = 'FULL_COMMIT_IDS_REQUIRED'
        $Envelope.message = 'DeliveredTarget requires explicit full 40- or 64-character hexadecimal -BaseSha and -TargetSha (not branch names or abbreviated IDs).'
        return 4
    }
    if ($BaseSha.Length -ne $TargetSha.Length) {
        $Envelope.status = 'invalid_input'
        $Envelope.reason_code = 'COMMIT_ID_FORMAT_MISMATCH'
        $Envelope.message = 'BaseSha and TargetSha must use the same Git object ID length.'
        return 4
    }
    if ([string]::IsNullOrWhiteSpace($TargetRef) -or
        $TargetRef.Length -gt 1024 -or
        $TargetRef -cnotmatch '^refs/(?:heads|remotes)/[^\x00-\x20\x7F]+$') {
        $Envelope.status = 'invalid_input'
        $Envelope.reason_code = 'FULL_TARGET_REF_REQUIRED'
        $Envelope.message = 'Provide a full refs/heads/... or refs/remotes/... name in -TargetRef; a short branch name or tag is not sufficient.'
        return 4
    }

    $inspectExit = Inspect-Repository -Envelope $Envelope -InputPath $InputPath -GitExecutable $GitExecutable
    if ($inspectExit -in @(4, 5)) { return $inspectExit }
    $source = $Envelope.data
    # Bare repositories can safely resolve objects; they have no persistent
    # CES project root and are always marked partial for that trust gap.
    $directory = if ($source.worktree_kind -eq 'bare') { [string]$source.resolved_path } else { [string]$source.source_root }
    $stableRootVerified = [bool]$source.stable_root_verified
    $warnings = [System.Collections.Generic.List[string]]::new()
    foreach ($item in $Envelope.warnings) { $warnings.Add([string]$item) }
    $evidence = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Envelope.evidence) { $evidence.Add($item) }
    $base = $BaseSha.ToLowerInvariant()
    $target = $TargetSha.ToLowerInvariant()

    $refSyntax = Git-In -GitExecutable $GitExecutable -Directory $directory -Arguments @('check-ref-format', $TargetRef) -MaxStdoutBytes 128
    if (-not $refSyntax.ok) {
        $Envelope.status = 'invalid_input'
        $Envelope.reason_code = 'INVALID_TARGET_REF'
        $Envelope.message = 'TargetRef is not a valid canonical Git reference name.'
        return 4
    }
    $refStart = Get-ExactTargetRef -GitExecutable $GitExecutable -Directory $directory -Ref $TargetRef
    $Envelope.coverage.target_ref_checked = $true
    $evidence.Add([ordered]@{ check = 'git_exact_target_ref_start'; exit_code = $refStart.exit_code; sha = if ($refStart.ok) { $refStart.stdout } else { $null } })
    if (-not $refStart.ok -or -not (Test-FullCommitId $refStart.stdout)) {
        $Envelope.status = if ($refStart.exit_code -eq 1) { 'invalid_input' } else { 'unavailable' }
        $Envelope.reason_code = if ($refStart.exit_code -eq 1) { 'TARGET_REF_NOT_FOUND' } else { 'TARGET_REF_UNAVAILABLE' }
        $Envelope.message = 'The specified target ref could not be resolved as an exact, existing local ref.'
        $Envelope.evidence = $evidence.ToArray()
        $Envelope.warnings = $warnings.ToArray()
        return $(if ($Envelope.status -eq 'invalid_input') { 4 } else { 5 })
    }
    # Symbolic refs such as refs/remotes/origin/HEAD are aliases, not a
    # directly pinned delivery target. Avoid interpreting them as branch truth.
    $sym = Git-In -GitExecutable $GitExecutable -Directory $directory -Arguments @('symbolic-ref', '--quiet', $TargetRef) -MaxStdoutBytes 1024
    if ($sym.exit_code -ne 1) {
        $Envelope.status = if ($sym.ok) { 'invalid_input' } else { 'unavailable' }
        $Envelope.reason_code = if ($sym.ok) { 'SYMBOLIC_TARGET_REF' } else { 'TARGET_REF_TYPE_UNVERIFIED' }
        $Envelope.message = 'TargetRef must name a direct branch/tracking ref, not a symbolic ref or an unverifiable alias.'
        $Envelope.evidence = $evidence.ToArray()
        return $(if ($sym.ok) { 4 } else { 5 })
    }
    if ($refStart.stdout.ToLowerInvariant() -cne $target) {
        $Envelope.status = 'invalid_input'
        $Envelope.reason_code = 'TARGET_REF_MISMATCH'
        $Envelope.message = 'TargetRef does not currently point to the explicitly pinned TargetSha. No other commit will be silently substituted.'
        $Envelope.evidence = $evidence.ToArray()
        return 4
    }

    $baseOk = Test-PinnedCommitObject -GitExecutable $GitExecutable -Directory $directory -Sha $base
    $targetOk = Test-PinnedCommitObject -GitExecutable $GitExecutable -Directory $directory -Sha $target
    $Envelope.coverage.base_commit_checked = $baseOk
    $Envelope.coverage.target_commit_checked = $targetOk
    $evidence.Add([ordered]@{ check = 'git_commit_object_type'; base_commit = $baseOk; target_commit = $targetOk })
    if (-not $baseOk -or -not $targetOk) {
        $Envelope.status = 'invalid_input'
        $Envelope.reason_code = 'COMMIT_OBJECT_NOT_VERIFIED'
        $Envelope.message = 'Both supplied object IDs must identify locally available Git commit objects; no fetch or substitution was attempted.'
        $Envelope.evidence = $evidence.ToArray()
        return 4
    }

    $ancestry = Git-In -GitExecutable $GitExecutable -Directory $directory -Arguments @('merge-base', '--is-ancestor', $base, $target) -MaxStdoutBytes 128
    $Envelope.coverage.ancestry_checked = ($ancestry.exit_code -in @(0, 1))
    $evidence.Add([ordered]@{ check = 'git_base_is_ancestor_of_target'; exit_code = $ancestry.exit_code })
    if ($ancestry.exit_code -ne 0) {
        $Envelope.status = if ($ancestry.exit_code -eq 1) { 'invalid_input' } else { 'unavailable' }
        $Envelope.reason_code = if ($ancestry.exit_code -eq 1) { 'BASE_NOT_ANCESTOR' } else { 'ANCESTRY_UNAVAILABLE' }
        $Envelope.message = 'The specified base must be an ancestor of target in the local Git object graph; arbitrary unrelated tree differences are not treated as delivery.'
        $Envelope.evidence = $evidence.ToArray()
        return $(if ($ancestry.exit_code -eq 1) { 4 } else { 5 })
    }

    $failed = $false
    $probe = Invoke-DeliveredInventoryProbe -GitExecutable $GitExecutable -Directory $directory -BaseSha $base -TargetSha $target
    $evidence.Add([ordered]@{
        check = 'git_delivered_diff_inventory'; exit_code = $probe.exit_code
        output_sha256 = if ($probe.ok) { Get-HashOfText -Content $probe.stdout } else { $null }
        over_limit = $probe.over_limit; timed_out = $probe.timed_out
    })
    $record = [ordered]@{
        state = 'unavailable'
        count = $null
        entries = @()
        patch_state = if ($RequestPatches) { 'unavailable' } else { 'not_requested' }
        patch = $null
        patch_sha256 = $null
        excluded_sensitive_paths = 0
    }
    if (-not $probe.ok) {
        $failed = $true
        $warnings.Add('Commit-range path inventory could not be collected; an unavailable result is not an empty diff.')
    } else {
        try {
            $entries = Convert-GitNameStatus -Content $probe.stdout
            $record.count = $entries.Length
            $record.entries = @($entries | Select-Object -First $script:CollectEntryLimit)
            $record.state = if ($entries.Length -gt $script:CollectEntryLimit) { 'entry_limit' } else { 'complete' }
            $Envelope.coverage.delivered_paths_checked = ($record.state -eq 'complete')
            if ($record.state -eq 'entry_limit') {
                $failed = $true
                $warnings.Add("Commit-range inventory has more than $($script:CollectEntryLimit) paths; results are incomplete.")
                if ($RequestPatches) { $record.patch_state = 'entry_limit' }
            } elseif ($RequestPatches) {
                $patch = Get-DeliveredPatch -GitExecutable $GitExecutable -Directory $directory -BaseSha $base -TargetSha $target -Entries $entries
                $record.patch_state = $patch.state
                $record.patch = $patch.text
                $record.patch_sha256 = $patch.sha256
                $record.excluded_sensitive_paths = $patch.excluded_sensitive
                if ($patch.state -notin @('included', 'empty')) {
                    $failed = $true
                    $warnings.Add("Commit-range patch content is incomplete ($($patch.state)); path inventory remains available.")
                }
            }
        } catch {
            $record.state = 'parse_error'
            $record.count = $null
            $record.entries = @()
            $record.patch_state = if ($RequestPatches) { 'unavailable' } else { 'not_requested' }
            $failed = $true
            $warnings.Add('Commit-range path records could not be parsed safely.')
        }
    }

    # Pinning commit IDs prevents a moved branch from altering the *selected*
    # diff. Still re-observe its target ref and inventory to avoid claiming the
    # result currently represents a branch after ref movement or object change.
    $refEnd = Get-ExactTargetRef -GitExecutable $GitExecutable -Directory $directory -Ref $TargetRef
    $refUnchanged = ($refEnd.ok -and (Test-FullCommitId $refEnd.stdout) -and ($refEnd.stdout.ToLowerInvariant() -ceq $target))
    $evidence.Add([ordered]@{
        check = 'git_exact_target_ref_end'; exit_code = $refEnd.exit_code
        sha = if ($refEnd.ok) { $refEnd.stdout } else { $null }
        matches_pinned_target = $refUnchanged
    })
    if (-not $refUnchanged) { $warnings.Add('Target ref moved or became unavailable while collecting; no present-branch equivalence is claimed.') }

    $objectsUnchanged = ((Test-PinnedCommitObject -GitExecutable $GitExecutable -Directory $directory -Sha $base) -and
                         (Test-PinnedCommitObject -GitExecutable $GitExecutable -Directory $directory -Sha $target))
    if (-not $objectsUnchanged) { $warnings.Add('At least one pinned commit object became unavailable during collection.') }

    $inventoryUnchanged = $false
    if ($probe.ok -and $record.state -ne 'parse_error') {
        $after = Invoke-DeliveredInventoryProbe -GitExecutable $GitExecutable -Directory $directory -BaseSha $base -TargetSha $target
        $inventoryUnchanged = ($after.ok -and ($after.stdout -ceq $probe.stdout))
        $evidence.Add([ordered]@{
            check = 'git_delivered_inventory_recheck'; exit_code = $after.exit_code
            output_sha256 = if ($after.ok) { Get-HashOfText -Content $after.stdout } else { $null }
            matches_start = $inventoryUnchanged
        })
        if (-not $inventoryUnchanged) { $warnings.Add('Commit-range inventory changed or could not be rechecked.') }
    }

    $contentUnchanged = $true
    if ($RequestPatches -and $record.patch_state -in @('included', 'included_with_exclusions')) {
        $again = Get-DeliveredPatch -GitExecutable $GitExecutable -Directory $directory -BaseSha $base -TargetSha $target -Entries $record.entries
        $contentUnchanged = ($again.state -ceq $record.patch_state -and $again.sha256 -ceq $record.patch_sha256)
        $evidence.Add([ordered]@{ check = 'git_delivered_patch_recheck'; matches_start = $contentUnchanged })
        if (-not $contentUnchanged) { $warnings.Add('Raw commit patch changed or could not be rechecked.') }
    }
    $consistent = ($refUnchanged -and $objectsUnchanged -and $inventoryUnchanged -and $contentUnchanged)
    $Envelope.coverage.consistency_checked = $consistent
    if (-not $consistent) {
        $failed = $true
        if ($null -ne $record.patch) {
            $record.patch = $null
            $record.patch_sha256 = $null
            $record.patch_state = 'discarded_unstable_target_ref'
        }
    }
    $Envelope.coverage.delivered_patch_checked = ($RequestPatches -and $consistent -and $record.patch_state -in @('included', 'empty'))
    if (-not $stableRootVerified) {
        $failed = $true
        $warnings.Add('No verified stable main-worktree project root; this mode does not grant CES persistence.')
    }

    $Envelope.data = [ordered]@{
        requested_path = $source.requested_path
        source_root = $source.source_root
        object_repository_path = $directory
        stable_project_root = $source.stable_project_root
        stable_root_verified = $stableRootVerified
        can_persist_ces_state = $false
        worktree_kind = $source.worktree_kind
        head = $source.head
        subject = [ordered]@{
            kind = 'code'
            source_mode = 'delivered_target_diff'
            base_sha = $base
            target_sha = $target
            target_ref = $TargetRef
            base_is_ancestor = $true
            verification_scope = 'local_ref_only'
            remote_delivery_verified = $false
            deployment_verified = $false
            pr_association_verified = $false
        }
        snapshot = [ordered]@{
            observed_at_utc = [DateTime]::UtcNow.ToString('o')
            consistency = if (-not $consistent) { 'changed_or_unverified' } elseif ($record.patch_state -in @('included', 'included_with_exclusions')) { 'ref_inventory_and_available_patch_rechecked' } else { 'ref_and_inventory_rechecked' }
            atomic = $false
            target_ref_sha_at_start = if ($refStart.ok) { $refStart.stdout.ToLowerInvariant() } else { $null }
            target_ref_sha_at_end = if ($refEnd.ok) { $refEnd.stdout.ToLowerInvariant() } else { $null }
            notes = 'Local target ref and pinned immutable commits observed and rechecked. Does not prove remote publication, CI deployment, a PR merge, or the absence of a ref move between observations.'
        }
        changes = $record
        limits = [ordered]@{
            inventory_bytes = $script:CollectInventoryByteLimit
            max_entries = $script:CollectEntryLimit
            patch_bytes = $script:CollectPatchByteLimit
            patch_paths = $script:CollectPatchPathLimit
        }
    }
    $Envelope.warnings = $warnings.ToArray()
    $Envelope.evidence = $evidence.ToArray()
    if ($failed) {
        $Envelope.status = 'partial'
        $Envelope.reason_code = if (-not $consistent) { 'COLLECT_TARGET_UNSTABLE' } else { 'COLLECT_PARTIAL' }
        $Envelope.message = 'Local target commit-range collected with coverage/trust gaps. Use only available pinned evidence; no remote delivery is asserted.'
        return 2
    }
    $Envelope.status = 'success'
    $Envelope.reason_code = 'COLLECT_DELIVERED_TARGET_OK'
    $Envelope.message = 'Pinned committed-tree diff verified against the specified local target ref; this is not proof of remote delivery or deployment.'
    return 0
}
