#requires -Version 7.0
<#
    EC-003: bounded, read-only collection of the three layers of a local
    Git working tree. Loaded only by the trusted CES CLI in this Skill.
    This module does not write to the inspected project or execute its code.
#>

$script:CollectInventoryByteLimit = 4MB
$script:CollectPatchByteLimit = 256KB
$script:CollectEntryLimit = 500
$script:CollectPatchPathLimit = 100
$script:CollectUntrackedFileByteLimit = 64KB
$script:CollectUntrackedTotalByteLimit = 256KB

function Split-GitNulFields {
    param([AllowEmptyString()][string] $Content)

    if ($Content.Length -eq 0) { return ,([string[]]@()) }
    if (-not $Content.EndsWith([string][char]0, [System.StringComparison]::Ordinal)) {
        throw 'Git path output lacked its required NUL terminator.'
    }
    $parts = $Content.Split([char]0)
    # Split() always adds an empty final element after the terminating NUL.
    $fields = [string[]]::new($parts.Length - 1)
    [array]::Copy($parts, $fields, $fields.Length)
    return ,$fields
}

function Convert-GitNameStatus {
    param([string] $Content)

    $fields = Split-GitNulFields -Content $Content
    $items = [System.Collections.Generic.List[object]]::new()
    $i = 0
    while ($i -lt $fields.Length) {
        $kind = $fields[$i]
        $i++
        if ($kind -cnotmatch '^(?:[ACDMRTUXB]|[RC][0-9]{1,3})$') {
            throw 'Git returned an unrecognized name-status record.'
        }
        $pathCount = if ($kind -cmatch '^[RC][0-9]{1,3}$') { 2 } else { 1 }
        if (($i + $pathCount) -gt $fields.Length) {
            throw 'Git returned an incomplete name-status record.'
        }
        $oldPath = $null
        if ($pathCount -eq 2) {
            $oldPath = $fields[$i]
            $i++
        }
        $path = $fields[$i]
        $i++
        if ([string]::IsNullOrEmpty($path) -or (($null -ne $oldPath) -and [string]::IsNullOrEmpty($oldPath))) {
            throw 'Git returned a name-status record with an empty path.'
        }
        $items.Add([ordered]@{
            status = $kind
            path = $path
            old_path = $oldPath
            sensitive_path = ((Test-SensitiveGitPath $path) -or (($null -ne $oldPath) -and (Test-SensitiveGitPath $oldPath)))
        })
    }
    return ,($items.ToArray())
}

function Test-SensitiveGitPath {
    param([string] $Path)

    # Conservative path filter for any optional raw content output.
    # It is not a general-purpose secret scanner. Filename inventory remains visible.
    $parts = $Path.Split('/')
    foreach ($segment in $parts) {
        if ($segment -imatch '^(?:\.git|\.env(?:\..*)?|\.npmrc|\.pypirc|\.netrc|\.dockerconfigjson|id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?|credentials?(?:\..*)?|secrets?(?:\..*)?|private[_-]?keys?(?:\..*)?)$') { return $true }
        if ($segment -imatch '\.(?:pem|p12|pfx|key|keystore|kdbx|asc)$') { return $true }
        if ($segment -imatch '^(?:\.aws|\.ssh|\.gnupg|\.kube)$') { return $true }
    }
    return $false
}

function Get-HashOfText {
    param([AllowEmptyString()][string] $Content)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
    return Get-HashOfBytes -Bytes $bytes
}

function Get-HashOfBytes {
    param([byte[]] $Bytes)
    # Avoid .NET 5+ HashData/ToHexString APIs: PowerShell 7.0 targets .NET Core 3.1.
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $algorithm.ComputeHash($Bytes)
        return [System.BitConverter]::ToString($digest).Replace('-', '').ToLowerInvariant()
    } finally {
        $algorithm.Dispose()
    }
}

function Get-ContainedUntrackedFile {
    param([string] $Root, [string] $RelativePath)

    if ([string]::IsNullOrWhiteSpace($RelativePath) -or [System.IO.Path]::IsPathRooted($RelativePath)) { return $null }
    $pieces = $RelativePath.Split('/')
    foreach ($piece in $pieces) {
        if (($piece -eq '') -or ($piece -eq '.') -or ($piece -eq '..')) { return $null }
        # Reject drive/alternate-stream separators even when running on Unix:
        # the same archive may later be used on Windows.
        if ($piece.Contains(':')) { return $null }
    }
    $candidate = $Root
    foreach ($piece in $pieces) {
        $candidate = [System.IO.Path]::Combine($candidate, $piece)
        $component = Get-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
        if ($null -eq $component) { return $null }
        if (($component.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { return $null }
    }
    $full = [System.IO.Path]::GetFullPath($candidate)
    $rootFull = [System.IO.Path]::GetFullPath($Root)
    $relative = [System.IO.Path]::GetRelativePath($rootFull, $full)
    if ($relative -eq '..' -or $relative.StartsWith(('..' + [System.IO.Path]::DirectorySeparatorChar), [System.StringComparison]::Ordinal) -or [System.IO.Path]::IsPathRooted($relative)) {
        return $null
    }
    if (-not ($component -is [System.IO.FileInfo])) { return $null }
    return $component
}

function Read-BoundedUntrackedText {
    param([string] $Root, [string] $RelativePath)

    $file = Get-ContainedUntrackedFile -Root $Root -RelativePath $RelativePath
    if ($null -eq $file) {
        return [pscustomobject]@{ state = 'unsafe_or_missing'; size = $null; sha256 = $null; text = $null }
    }
    if ($file.Length -gt $script:CollectUntrackedFileByteLimit) {
        return [pscustomobject]@{ state = 'too_large'; size = $file.Length; sha256 = $null; text = $null }
    }
    try {
        # Read exactly the observed length. Concurrent writes are detected by
        # comparing pre/post file metadata and a later content re-check.
        $beforeLength = $file.Length
        $beforeTicks = $file.LastWriteTimeUtc.Ticks
        $stream = [System.IO.FileStream]::new(
            $file.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
            ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
        )
        try {
            if ($stream.Length -ne $beforeLength) { throw 'File changed before read.' }
            $bytes = [byte[]]::new([int]$beforeLength)
            $offset = 0
            while ($offset -lt $bytes.Length) {
                $n = $stream.Read($bytes, $offset, $bytes.Length - $offset)
                if ($n -le 0) { throw 'Unexpected EOF while reading untracked file.' }
                $offset += $n
            }
            if ($stream.Length -ne $beforeLength) { throw 'File changed during read.' }
        } finally {
            $stream.Dispose()
        }
        $file.Refresh()
        if ($file.Length -ne $beforeLength -or $file.LastWriteTimeUtc.Ticks -ne $beforeTicks) {
            throw 'File changed during read.'
        }
        $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
        $text = $utf8.GetString($bytes)
        if ($text.StartsWith([string][char]0xFEFF, [System.StringComparison]::Ordinal)) { $text = $text.Substring(1) }
        if ($text -match '[\x00-\x08\x0B\x0C\x0E-\x1F]') {
            return [pscustomobject]@{ state = 'binary_or_control'; size = $beforeLength; sha256 = $null; text = $null }
        }
        return [pscustomobject]@{
            state = 'included'
            size = $beforeLength
            sha256 = (Get-HashOfBytes -Bytes $bytes)
            text = $text
        }
    } catch [System.Text.DecoderFallbackException] {
        return [pscustomobject]@{ state = 'non_utf8'; size = $file.Length; sha256 = $null; text = $null }
    } catch {
        return [pscustomobject]@{ state = 'changed_or_unreadable'; size = $file.Length; sha256 = $null; text = $null }
    }
}

function Invoke-CollectProbe {
    param([string] $GitExecutable, [string] $Directory, [string] $Layer)

    $arguments = switch ($Layer) {
        'staged' {
            @('diff', '--cached', '--name-status', '-z', '--find-renames', '--no-ext-diff', '--no-textconv', '--no-color', '--ignore-submodules=none', '--')
        }
        'unstaged' {
            @('diff', '--name-status', '-z', '--find-renames', '--no-ext-diff', '--no-textconv', '--no-color', '--ignore-submodules=none', '--')
        }
        'untracked' {
            @('ls-files', '--others', '--exclude-standard', '-z', '--full-name', '--',
                # CES-owned local state is reserved, never treated as analyzed code.
                ':(exclude,top,glob).codex/ces/**')
        }
        default { throw 'Unknown Collect probe layer.' }
    }
    return Git-In -GitExecutable $GitExecutable -Directory $Directory -Arguments $arguments -MaxStdoutBytes $script:CollectInventoryByteLimit
}

function Get-CollectPatch {
    param(
        [string] $GitExecutable,
        [string] $Directory,
        [string] $Layer,
        [object[]] $Entries
    )

    $safePaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $skipped = 0
    foreach ($entry in $Entries) {
        if ($entry.sensitive_path) { $skipped++; continue }
        [void] $safePaths.Add([string]$entry.path)
        if ($null -ne $entry.old_path) { [void] $safePaths.Add([string]$entry.old_path) }
    }
    if ($safePaths.Count -gt $script:CollectPatchPathLimit) {
        return [pscustomobject]@{ state = 'path_limit'; text = $null; sha256 = $null; skipped_sensitive = $skipped; path_count = $safePaths.Count }
    }
    if ($safePaths.Count -eq 0) {
        $state = if ($skipped -gt 0) { 'sensitive_paths_excluded' } else { 'empty' }
        return [pscustomobject]@{ state = $state; text = $null; sha256 = $null; skipped_sensitive = $skipped; path_count = 0 }
    }
    $args = @('diff')
    if ($Layer -eq 'staged') { $args += '--cached' }
    $args += @('--binary', '--full-index', '--find-renames', '--no-ext-diff', '--no-textconv', '--no-color', '--ignore-submodules=none', '--')
    # Git pathspec magic makes metacharacters in filenames literal.
    foreach ($path in ($safePaths | Sort-Object -CaseSensitive)) {
        $args += (':(literal)' + $path)
    }
    $probe = Git-In -GitExecutable $GitExecutable -Directory $Directory -Arguments $args -MaxStdoutBytes $script:CollectPatchByteLimit -PreserveStdout
    if (-not $probe.ok) {
        $state = if ($probe.over_limit) { 'byte_limit' } elseif ($probe.timed_out) { 'timeout' } else { 'git_error' }
        return [pscustomobject]@{ state = $state; text = $null; sha256 = $null; skipped_sensitive = $skipped; path_count = $safePaths.Count }
    }
    return [pscustomobject]@{
        state = if ($skipped -gt 0) { 'included_with_exclusions' } else { 'included' }
        text = $probe.stdout
        sha256 = (Get-HashOfText -Content $probe.stdout)
        skipped_sensitive = $skipped
        path_count = $safePaths.Count
    }
}

function Get-UntrackedInventory {
    param([string] $Payload, [string] $Root, [bool] $IncludeContent)

    $allPaths = Split-GitNulFields -Content $Payload
    $records = [System.Collections.Generic.List[object]]::new()
    $readBytes = 0L
    $limited = ($allPaths.Length -gt $script:CollectEntryLimit)
    $count = [math]::Min($allPaths.Length, $script:CollectEntryLimit)
    for ($i = 0; $i -lt $count; $i++) {
        $relative = $allPaths[$i]
        if ([string]::IsNullOrEmpty($relative)) { throw 'Git returned an empty untracked path.' }
        $sensitive = Test-SensitiveGitPath $relative
        $entry = [ordered]@{
            path = $relative
            sensitive_path = $sensitive
            size_bytes = $null
            content_state = 'not_requested'
            sha256 = $null
            content = $null
        }
        if ($IncludeContent) {
            if ($sensitive) {
                $entry.content_state = 'sensitive_path_excluded'
            } elseif ($readBytes -ge $script:CollectUntrackedTotalByteLimit) {
                $entry.content_state = 'total_byte_limit'
            } else {
                $fileContent = Read-BoundedUntrackedText -Root $Root -RelativePath $relative
                $entry.size_bytes = $fileContent.size
                if ($fileContent.state -eq 'included' -and ($readBytes + $fileContent.size) -gt $script:CollectUntrackedTotalByteLimit) {
                    $entry.content_state = 'total_byte_limit'
                } else {
                    $entry.content_state = $fileContent.state
                    if ($fileContent.state -eq 'included') {
                        $readBytes += $fileContent.size
                        $entry.sha256 = $fileContent.sha256
                        $entry.content = $fileContent.text
                    }
                }
            }
        }
        $records.Add($entry)
    }
    return [pscustomobject]@{
        files = $records.ToArray()
        total_paths = $allPaths.Length
        entries_truncated = $limited
        included_content_bytes = $readBytes
    }
}

function Collect-WorkingTree {
    param(
        [System.Collections.IDictionary] $Envelope,
        [string] $InputPath,
        [string] $GitExecutable,
        [bool] $RequestPatches,
        [bool] $RequestUntrackedContent
    )

    # Reuse the trusted Inspect root/head checks. Collection remains possible
    # at an unverified stable root because there is NO persistence here.
    $inspectExit = Inspect-Repository -Envelope $Envelope -InputPath $InputPath -GitExecutable $GitExecutable
    if ($inspectExit -eq 4 -or $inspectExit -eq 5) { return $inspectExit }
    if ($Envelope.data.worktree_kind -eq 'bare') {
        $Envelope.status = 'unavailable'
        $Envelope.reason_code = 'COLLECT_REQUIRES_WORKTREE'
        $Envelope.message = 'Collect WorkingTree needs a Git worktree; bare repositories have none.'
        return 5
    }
    $source = $Envelope.data
    $root = [string]$source.source_root
    $startHead = [string]$source.head.sha
    $startBranch = [string]$source.head.branch
    $warnings = [System.Collections.Generic.List[string]]::new()
    foreach ($w in $Envelope.warnings) { $warnings.Add([string]$w) }
    $evidence = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Envelope.evidence) { $evidence.Add($item) }
    $checks = [ordered]@{}
    $failed = $false
    foreach ($layer in @('staged', 'unstaged', 'untracked')) {
        $probe = Invoke-CollectProbe -GitExecutable $GitExecutable -Directory $root -Layer $layer
        $checks[$layer] = $probe
        $evidence.Add([ordered]@{
            check = "git_collect_$layer"
            exit_code = $probe.exit_code
            output_sha256 = if ($probe.ok) { Get-HashOfText $probe.stdout } else { $null }
            over_limit = $probe.over_limit
            timed_out = $probe.timed_out
        })
        if ($probe.ok) {
            $Envelope.coverage[($layer + '_paths_checked')] = $true
        } else {
            $failed = $true
            $problem = if ($probe.over_limit) { 'exceeded inventory byte limit' }
                       elseif ($probe.timed_out) { 'timed out' }
                       else { 'Git could not collect the layer' }
            $warnings.Add("$layer collection $problem; no empty inventory is inferred.")
        }
    }

    $layers = [ordered]@{}
    foreach ($layer in @('staged', 'unstaged')) {
        $probe = $checks[$layer]
        $record = [ordered]@{
            state = 'unavailable'
            count = $null
            entries = @()
            patch_state = 'not_requested'
            patch = $null
            patch_sha256 = $null
            excluded_sensitive_paths = 0
        }
        if ($probe.ok) {
            try {
                $entries = Convert-GitNameStatus -Content $probe.stdout
                $record.count = $entries.Length
                $record.entries = @($entries | Select-Object -First $script:CollectEntryLimit)
                $record.state = if ($entries.Length -gt $script:CollectEntryLimit) { 'entry_limit' } else { 'complete' }
                if ($record.state -eq 'entry_limit') {
                    $failed = $true
                    $warnings.Add("$layer has more than $($script:CollectEntryLimit) changed paths; listing is incomplete.")
                }
                if ($RequestPatches) {
                    if ($record.state -eq 'entry_limit') {
                        $record.patch_state = 'entry_limit'
                        $failed = $true
                    } else {
                        $patch = Get-CollectPatch -GitExecutable $GitExecutable -Directory $root -Layer $layer -Entries $entries
                        $record.patch_state = $patch.state
                        $record.patch = $patch.text
                        $record.patch_sha256 = $patch.sha256
                        $record.excluded_sensitive_paths = $patch.skipped_sensitive
                        if ($patch.state -notin @('included','empty')) {
                            $failed = $true
                            $warnings.Add("$layer patch content is incomplete ($($patch.state)); inventory remains available.")
                        }
                    }
                }
            } catch {
                $record.state = 'parse_error'
                $record.count = $null
                $record.entries = @()
                $record.patch_state = 'unavailable'
                $failed = $true
                $warnings.Add("$layer path records could not be parsed safely.")
            }
        } elseif ($RequestPatches) {
            $record.patch_state = 'unavailable'
        }
        $layers[$layer] = $record
    }

    $untracked = [ordered]@{
        state = 'unavailable'
        count = $null
        entries = @()
        content_requested = $RequestUntrackedContent
        included_content_bytes = 0
    }
    if ($checks.untracked.ok) {
        try {
            $inventory = Get-UntrackedInventory -Payload $checks.untracked.stdout -Root $root -IncludeContent $RequestUntrackedContent
            $untracked.entries = $inventory.files
            $untracked.count = $inventory.total_paths
            $untracked.included_content_bytes = $inventory.included_content_bytes
            $untracked.state = if ($inventory.entries_truncated) { 'entry_limit' } else { 'complete' }
            if ($inventory.entries_truncated) {
                $failed = $true
                $warnings.Add('Untracked inventory exceeded the entry limit; content was not fully enumerated.')
            }
            if ($RequestUntrackedContent) {
                $untrackedSkipped = $false
                foreach ($item in $untracked.entries) {
                    if ($item.content_state -ne 'included') {
                        $failed = $true
                        $untrackedSkipped = $true
                    }
                }
                if ($untrackedSkipped) { $warnings.Add('Some optional untracked content was unavailable or intentionally excluded; inspect each content_state.') }
            }
        } catch {
            $failed = $true
            $untracked.state = 'parse_error'
            $warnings.Add('Untracked path records could not be parsed safely.')
        }
    }

    # Best-effort second observation. A dirty worktree cannot be atomically
    # frozen by a read-only Git command; a matching path set is NOT proof that
    # bytes were unchanged, hence the carefully named consistency levels.
    $metadataRechecked = $true
    foreach ($layer in @('staged', 'unstaged', 'untracked')) {
        if (-not $checks[$layer].ok) { $metadataRechecked = $false; continue }
        $after = Invoke-CollectProbe -GitExecutable $GitExecutable -Directory $root -Layer $layer
        $evidence.Add([ordered]@{
            check = "git_recheck_$layer"
            exit_code = $after.exit_code
            output_sha256 = if ($after.ok) { Get-HashOfText $after.stdout } else { $null }
            matches_start = ($after.ok -and ($after.stdout -ceq $checks[$layer].stdout))
        })
        if (-not $after.ok) {
            $metadataRechecked = $false
            $warnings.Add("$layer could not be rechecked after collection.")
        } elseif ($after.stdout -cne $checks[$layer].stdout) {
            $metadataRechecked = $false
            $warnings.Add("$layer path inventory changed during collection.")
        }
    }
    $headNow = Git-In -GitExecutable $GitExecutable -Directory $root -Arguments @('rev-parse', '--verify', 'HEAD^{commit}')
    $branchNow = Git-In -GitExecutable $GitExecutable -Directory $root -Arguments @('symbolic-ref', '--quiet', 'HEAD')
    $endSha = if ($headNow.ok -and $headNow.stdout -match '^[0-9a-fA-F]{40,64}$') { $headNow.stdout.ToLowerInvariant() } else { '' }
    $endBranch = if ($branchNow.ok -and $branchNow.stdout.StartsWith('refs/heads/', [System.StringComparison]::Ordinal)) { $branchNow.stdout.Substring('refs/heads/'.Length) } else { '' }
    if ($endSha -cne $startHead -or $endBranch -cne $startBranch) {
        $metadataRechecked = $false
        $warnings.Add('HEAD or branch changed during collection.')
    }

    $contentRechecked = $true
    if ($RequestPatches) {
        foreach ($layer in @('staged', 'unstaged')) {
            if ($layers[$layer].patch_state -in @('included', 'included_with_exclusions')) {
                $again = Get-CollectPatch -GitExecutable $GitExecutable -Directory $root -Layer $layer -Entries $layers[$layer].entries
                if ($again.sha256 -cne $layers[$layer].patch_sha256 -or $again.state -cne $layers[$layer].patch_state) {
                    $contentRechecked = $false
                    $warnings.Add("$layer diff changed or could not be rechecked.")
                }
            }
        }
    }
    if ($RequestUntrackedContent) {
        foreach ($entry in $untracked.entries) {
            if ($entry.content_state -eq 'included') {
                $again = Read-BoundedUntrackedText -Root $root -RelativePath $entry.path
                if ($again.sha256 -cne $entry.sha256 -or $again.state -ne 'included') {
                    $contentRechecked = $false
                    $warnings.Add('At least one untracked file changed or became unreadable during collection.')
                    break
                }
            }
        }
    }

    $consistency = if (-not $metadataRechecked -or -not $contentRechecked) { 'changed_or_unverified' }
                   elseif ($RequestPatches -or $RequestUntrackedContent) { 'available_content_rechecked' }
                   else { 'path_inventory_rechecked' }
    if ($consistency -eq 'changed_or_unverified') {
        $failed = $true
        # Never return potentially stale source snippets as current evidence.
        foreach ($layer in @('staged', 'unstaged')) {
            if ($null -ne $layers[$layer].patch) {
                $layers[$layer].patch = $null
                $layers[$layer].patch_sha256 = $null
                $layers[$layer].patch_state = 'discarded_unstable_snapshot'
            }
        }
        foreach ($entry in $untracked.entries) {
            if ($entry.content_state -eq 'included') {
                $entry.content = $null
                $entry.sha256 = $null
                $entry.content_state = 'discarded_unstable_snapshot'
            }
        }
    }

    $Envelope.coverage.index_or_worktree_changes_checked = ($Envelope.coverage.staged_paths_checked -and $Envelope.coverage.unstaged_paths_checked -and $Envelope.coverage.untracked_paths_checked)
    $Envelope.coverage.consistency_checked = ($metadataRechecked -and $contentRechecked)
    $Envelope.coverage.staged_patch_checked = ($RequestPatches -and ($layers.staged.patch_state -in @('included', 'empty')))
    $Envelope.coverage.unstaged_patch_checked = ($RequestPatches -and ($layers.unstaged.patch_state -in @('included', 'empty')))
    $Envelope.coverage.untracked_content_checked = ($RequestUntrackedContent -and (-not @($untracked.entries | Where-Object { $_.content_state -ne 'included' }).Count) -and $untracked.state -eq 'complete')
    $Envelope.data = [ordered]@{
        requested_path = $source.requested_path
        source_root = $root
        stable_project_root = $source.stable_project_root
        stable_root_verified = $source.stable_root_verified
        can_persist_ces_state = $false
        worktree_kind = $source.worktree_kind
        head = $source.head
        subject = [ordered]@{ kind = 'code'; source_mode = 'working_tree_diff'; base_sha = $source.head.sha }
        snapshot = [ordered]@{
            observed_at_utc = [DateTime]::UtcNow.ToString('o')
            consistency = $consistency
            atomic = $false
            notes = 'Git worktree data is not atomically frozen; path sets were compared before/after and requested snippets were rechecked where possible.'
        }
        staged = $layers.staged
        unstaged = $layers.unstaged
        untracked = $untracked
        limits = [ordered]@{
            inventory_bytes_per_layer = $script:CollectInventoryByteLimit
            max_entries_per_layer = $script:CollectEntryLimit
            patch_bytes_per_layer = $script:CollectPatchByteLimit
            patch_paths_per_layer = $script:CollectPatchPathLimit
            untracked_file_bytes = $script:CollectUntrackedFileByteLimit
            untracked_content_total_bytes = $script:CollectUntrackedTotalByteLimit
        }
    }
    $Envelope.warnings = $warnings.ToArray()
    $Envelope.evidence = $evidence.ToArray()
    $Envelope.coverage.stable_root_verified = $source.stable_root_verified
    if (-not $source.stable_root_verified) {
        $failed = $true
        $warnings.Add('The persistent project root is not verified; no CES state may be written.')
    }
    if ($source.head.state -eq 'unknown') { $failed = $true }
    $Envelope.warnings = $warnings.ToArray()
    if ($failed) {
        $Envelope.status = 'partial'
        $Envelope.reason_code = if ($consistency -eq 'changed_or_unverified') { 'COLLECT_UNSTABLE' } else { 'COLLECT_PARTIAL' }
        $Envelope.message = 'Read-only working-tree collection has coverage gaps; use only the evidence explicitly marked available.'
        return 2
    }
    $Envelope.status = 'success'
    $Envelope.reason_code = 'COLLECT_OK'
    $Envelope.message = 'Staged, unstaged and untracked Git layers were collected without changing the project.'
    return 0
}
