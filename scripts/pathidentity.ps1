#requires -Version 7.0
<#
    EC-159: local path, main-worktree and external actor identity primitives.
    Source this module from the trusted CES package, never from RepoPath.
    These helpers NEVER grant write permission, open a provider, run git hooks,
    or authenticate a human. Git-In must be supplied by the CLI's bounded,
    read-only Git runner. Path checks are non-atomic and must be repeated at
    sensitive I/O boundaries; hostile races need OS handle-relative primitives.
#>

function Normalize-FullPath {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][string] $RelativeTo
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    if ($Path.Contains([char]0)) { throw 'A filesystem path contains NUL.' }
    $full = if ([System.IO.Path]::IsPathRooted($Path)) {
        [System.IO.Path]::GetFullPath($Path)
    } else {
        [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($RelativeTo, $Path))
    }
    $root = [System.IO.Path]::GetPathRoot($full)
    if ($full.Length -gt $root.Length) {
        $full = $full.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    }
    return $full
}

function Paths-Equal {
    param(
        [AllowNull()][string] $First,
        [AllowNull()][string] $Second
    )
    if ([string]::IsNullOrEmpty($First) -or [string]::IsNullOrEmpty($Second)) {
        return $false
    }
    # Keep the legacy comparison rule for existing Inspect/CodeShow v1 data.
    # Filesystem identity is NOT proven by this lexical equality.
    $comparison = if ($IsWindows) {
        [System.StringComparison]::OrdinalIgnoreCase
    } else {
        [System.StringComparison]::Ordinal
    }
    return [string]::Equals($First, $Second, $comparison)
}

function Assert-CesNoReparseAncestry {
    param([Parameter(Mandatory)][string] $Path)

    if (-not [System.IO.Path]::IsPathRooted($Path) -or $Path.Contains([char]0)) {
        throw 'A fully qualified filesystem path is required for an ancestry check.'
    }
    $walk = [System.IO.Path]::GetFullPath($Path)
    $first = $true
    while ($true) {
        # .NET inspects each named path component without treating a missing
        # expected output leaf as a failure. All other I/O errors fail closed.
        try {
            $attributes = [System.IO.File]::GetAttributes($walk)
            if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'A symbolic link, junction or reparse point occurs in the path ancestry.'
            }
            if (-not $first -and
                ($attributes -band [System.IO.FileAttributes]::Directory) -eq 0) {
                throw 'A path ancestor is not a directory.'
            }
        } catch [System.IO.FileNotFoundException] {
            # Missing output leaf is allowed; verified existing ancestors are not.
        } catch [System.IO.DirectoryNotFoundException] {
            # A parent may not yet exist during creation; check its ancestors.
        }
        $parent = [System.IO.Path]::GetDirectoryName($walk)
        if ([string]::IsNullOrEmpty($parent) -or $parent -ceq $walk) { break }
        $walk = $parent
        $first = $false
    }
    return $true
}

function Resolve-CesUserPath {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][string] $RelativeTo
    )
    # An explicit RepoPath is allowed to be outside the current directory.
    # Its normalization cannot authorize a store or prove a Git repository.
    $normalized = Normalize-FullPath -Path $Path -RelativeTo $RelativeTo
    if (-not $normalized) { throw 'An explicit non-empty path is required.' }
    return [pscustomobject]@{
        supplied_path = $Path
        absolute_path = $normalized
        selection = if ([System.IO.Path]::IsPathRooted($Path)) { 'explicit_absolute' } else { 'explicit_relative' }
        path_verified = $false
        write_authorized = $false
    }
}

function Assert-CesContainedPath {
    param(
        [Parameter(Mandatory)][string] $Root,
        [Parameter(Mandatory)][string] $Path,
        [switch] $AllowRoot
    )
    if (-not [System.IO.Path]::IsPathRooted($Root)) {
        throw 'The trusted containment root must be absolute.'
    }
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Contains([char]0)) {
        throw 'An empty or invalid path cannot be contained.'
    }
    # Reject lexical parent traversals even when normalization would end up
    # inside the root. The store only needs fixed, generated child names.
    $separatorPattern = if ($IsWindows) { '[\\/]' } else { '/' }
    if (@([regex]::Split($Path, $separatorPattern) | Where-Object { $_ -ceq '..' }).Count -gt 0) {
        throw 'Parent-directory traversal is not permitted for a contained path.'
    }
    $rootFull = Normalize-FullPath -Path $Root -RelativeTo $Root
    $candidate = Normalize-FullPath -Path $Path -RelativeTo $rootFull
    $comparison = if ($IsWindows -or $IsMacOS) {
        [System.StringComparison]::OrdinalIgnoreCase
    } else {
        [System.StringComparison]::Ordinal
    }
    $isRoot = [string]::Equals($candidate, $rootFull, $comparison)
    $prefix = if ($rootFull.EndsWith([string][System.IO.Path]::DirectorySeparatorChar)) {
        $rootFull
    } else { $rootFull + [System.IO.Path]::DirectorySeparatorChar }
    if ((-not $isRoot -and -not $candidate.StartsWith($prefix, $comparison)) -or
        ($isRoot -and -not $AllowRoot)) {
        throw 'The selected path falls outside the trusted root or selects the root itself.'
    }
    [void](Assert-CesNoReparseAncestry -Path $rootFull)
    [void](Assert-CesNoReparseAncestry -Path $candidate)
    return $candidate
}

function Resolve-CesEvidencePath {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][string] $RelativeTo
    )
    # Evidence may intentionally reside OUTSIDE the Git repository. It is
    # user-selected untrusted input, never a CES storage destination.
    $source = Resolve-CesUserPath -Path $Path -RelativeTo $RelativeTo
    [void](Assert-CesNoReparseAncestry -Path $source.absolute_path)
    $item = Get-Item -LiteralPath $source.absolute_path -Force -ErrorAction Stop
    if ($item -isnot [System.IO.FileInfo] -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'EvidencePath must be a regular file without a symlink ancestry.'
    }
    return [pscustomobject]@{
        supplied_path = $source.supplied_path
        absolute_path = $source.absolute_path
        file_length = $item.Length
        origin = 'caller_supplied_untrusted_bytes'
        authenticated = $false
        can_authorize_write = $false
    }
}

function Read-CommonGitDirectory {
    param([string] $GitExecutable, [string] $Directory)

    # Preserve Git 2.31+ capability detection and the legacy fallback.
    $absolute = Git-In -GitExecutable $GitExecutable -Directory $Directory -Arguments @('rev-parse', '--path-format=absolute', '--git-common-dir')
    if ($absolute.ok -and -not [string]::IsNullOrWhiteSpace($absolute.stdout)) {
        return [pscustomobject]@{
            ok = $true
            path = (Normalize-FullPath -Path $absolute.stdout -RelativeTo $Directory)
            fallback = $false
        }
    }
    $relative = Git-In -GitExecutable $GitExecutable -Directory $Directory -Arguments @('rev-parse', '--git-common-dir')
    if ($relative.ok -and -not [string]::IsNullOrWhiteSpace($relative.stdout)) {
        return [pscustomobject]@{
            ok = $true
            path = (Normalize-FullPath -Path $relative.stdout -RelativeTo $Directory)
            fallback = $true
        }
    }
    return [pscustomobject]@{ ok = $false; path = $null; fallback = $false }
}

function Find-VerifiedStableRoot {
    param([string] $GitExecutable, [string] $CommonGitDir)

    # Worktree-list ordering and same-named folders never prove main identity.
    if ([string]::IsNullOrEmpty($CommonGitDir)) { return $null }
    $name = [System.IO.Path]::GetFileName($CommonGitDir)
    if (-not [string]::Equals($name, '.git', [System.StringComparison]::OrdinalIgnoreCase)) {
        return $null
    }
    $candidate = [System.IO.Path]::GetDirectoryName($CommonGitDir)
    try {
        [void](Assert-CesNoReparseAncestry -Path $CommonGitDir)
        [void](Assert-CesNoReparseAncestry -Path $candidate)
    } catch { return $null }
    if (-not (Test-Path -LiteralPath $candidate -PathType Container)) { return $null }

    $top = Git-In -GitExecutable $GitExecutable -Directory $candidate -Arguments @('rev-parse', '--show-toplevel')
    if (-not $top.ok) { return $null }
    $topPath = Normalize-FullPath -Path $top.stdout -RelativeTo $candidate
    if (-not (Paths-Equal -First $topPath -Second $candidate)) { return $null }
    $ownGit = Git-In -GitExecutable $GitExecutable -Directory $candidate -Arguments @('rev-parse', '--absolute-git-dir')
    if (-not $ownGit.ok) { return $null }
    $ownGitPath = Normalize-FullPath -Path $ownGit.stdout -RelativeTo $candidate
    if (-not (Paths-Equal -First $ownGitPath -Second $CommonGitDir)) { return $null }
    $ownCommon = Read-CommonGitDirectory -GitExecutable $GitExecutable -Directory $candidate
    if (-not $ownCommon.ok -or -not (Paths-Equal -First $ownCommon.path -Second $CommonGitDir)) {
        return $null
    }
    return $candidate
}

function Get-CesScopedOpaqueKey {
    param([Parameter(Mandatory)][string] $Domain, [Parameter(Mandatory)][string[]] $Parts)
    # Length-prefix every UTF-8 component; no delimiter collisions, no text
    # exposed in the returned key. A digest is NOT an authentication token.
    $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $stream = [System.IO.MemoryStream]::new()
    try {
        foreach ($part in (@($Domain) + $Parts)) {
            $raw = $utf8.GetBytes($part)
            if ($raw.Length -gt 4096) { throw 'Identity component exceeds its length bound.' }
            $length = [byte[]]@(
                [byte](($raw.Length -shr 24) -band 255),
                [byte](($raw.Length -shr 16) -band 255),
                [byte](($raw.Length -shr 8) -band 255),
                [byte]($raw.Length -band 255)
            )
            $stream.Write($length, 0, $length.Length)
            $stream.Write($raw, 0, $raw.Length)
        }
        $algorithm = [System.Security.Cryptography.SHA256]::Create()
        try {
            $sha = $algorithm.ComputeHash($stream.ToArray())
            return [System.BitConverter]::ToString($sha).Replace('-', '').ToLowerInvariant()
        } finally { $algorithm.Dispose() }
    } finally { $stream.Dispose() }
}

function Assert-CesVerifiedMainWorktree {
    param([Parameter(Mandatory)][string] $GitExecutable, [Parameter(Mandatory)][string] $RepoRoot)

    # This is a read-only REPROBE, not a write permission. Caller still needs
    # CodeValidate, -ApprovePersist and CodeSave store/Git path gates.
    if (-not [System.IO.Path]::IsPathRooted($RepoRoot)) { throw 'Main worktree root must be absolute.' }
    $root = Normalize-FullPath -Path $RepoRoot -RelativeTo $RepoRoot
    [void](Assert-CesNoReparseAncestry -Path $root)
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw 'Main worktree directory is missing.' }
    $bare = Git-In -GitExecutable $GitExecutable -Directory $root -Arguments @('rev-parse', '--is-bare-repository')
    $inside = Git-In -GitExecutable $GitExecutable -Directory $root -Arguments @('rev-parse', '--is-inside-work-tree')
    if (-not $bare.ok -or $bare.stdout -cne 'false' -or -not $inside.ok -or $inside.stdout -cne 'true') {
        throw 'Repository is bare or the working tree cannot be verified.'
    }
    $top = Git-In -GitExecutable $GitExecutable -Directory $root -Arguments @('rev-parse', '--show-toplevel')
    $gitDir = Git-In -GitExecutable $GitExecutable -Directory $root -Arguments @('rev-parse', '--absolute-git-dir')
    $common = Read-CommonGitDirectory -GitExecutable $GitExecutable -Directory $root
    if (-not $top.ok -or -not $gitDir.ok -or -not $common.ok) {
        throw 'Git root and common metadata could not be independently resolved.'
    }
    $topPath = Normalize-FullPath -Path $top.stdout -RelativeTo $root
    $gitPath = Normalize-FullPath -Path $gitDir.stdout -RelativeTo $root
    $mainRoot = Find-VerifiedStableRoot -GitExecutable $GitExecutable -CommonGitDir $common.path
    if (-not $mainRoot -or -not (Paths-Equal -First $root -Second $topPath) -or
        -not (Paths-Equal -First $root -Second $mainRoot) -or
        -not (Paths-Equal -First $gitPath -Second $common.path) -or
        # For a safety boundary, reject aliases whose Git-spelled path differs
        # even by case on a case-insensitive volume; read-only Inspect may be looser.
        $root -cne $topPath -or $root -cne $mainRoot -or $gitPath -cne $common.path) {
        throw 'Root is linked, path-aliased, unstable or not the independently verified main worktree.'
    }
    [void](Assert-CesNoReparseAncestry -Path $common.path)
    return [pscustomobject]@{
        stable_root = $mainRoot
        source_root = $topPath
        git_common_dir = $common.path
        repository_scope = 'local_git_common_directory_path_only'
        local_repository_key = 'repo-local-' + (Get-CesScopedOpaqueKey -Domain 'ces.local.repo.v1' -Parts @($common.path))
        stable_root_verified = $true
        write_authorized = $false
    }
}

function Resolve-CesActorIdentity {
    param(
        [AllowNull()][string] $Provider = $null,
        [AllowNull()][string] $Tenant = $null,
        [AllowNull()][string] $ImmutableSubjectId = $null,
        [AllowNull()][string] $DisplayName = $null
    )
    # Neither Git author/email nor display name is a trustworthy external ID.
    # A COMPLETE tuple is still a caller claim, NOT verified provider evidence.
    $supplied = @($Provider, $Tenant, $ImmutableSubjectId) | Where-Object { -not [string]::IsNullOrEmpty($_) }
    if ($supplied.Count -eq 0) {
        return [pscustomobject]@{
            status = 'unknown'; reason_code = 'EXTERNAL_ACTOR_ID_MISSING'
            actor_key = $null; declared_actor_key = $null
            display_name_is_identity = $false; verified = $false; can_authorize_write = $false
        }
    }
    if ($supplied.Count -ne 3) {
        throw 'External actor identity requires provider, tenant and immutable subject ID together.'
    }
    if ($Provider -cnotmatch '^[a-z][a-z0-9._-]{0,63}$' -or
        $Tenant.Length -gt 256 -or $Tenant -notmatch '^[^\x00-\x1F\x7F]+$' -or
        $ImmutableSubjectId.Length -gt 256 -or $ImmutableSubjectId -notmatch '^[^\x00-\x1F\x7F]+$') {
        throw 'Malformed provider, tenant or immutable external subject ID.'
    }
    return [pscustomobject]@{
        status = 'declared_unverified'
        reason_code = 'EXTERNAL_ACTOR_PROVENANCE_NOT_AUTHENTICATED'
        actor_key = $null
        declared_actor_key = 'actor-claim-' + (Get-CesScopedOpaqueKey -Domain 'ces.actor.claim.v1' -Parts @($Provider, $Tenant, $ImmutableSubjectId))
        display_name_is_identity = $false
        verified = $false
        can_authorize_write = $false
    }
}

function Assert-CesVerifiedActor {
    param([Parameter(Mandatory)][object] $Actor)
    # No current CES public API can elevate a claimed identity. A future
    # provider adapter must implement its own authenticated fact verification.
    throw 'An authenticated external actor identity is required; CES EC-159 has no provider attestation adapter.'
}

function Format-CesPathForLog {
    param([AllowNull()][string] $Path, [AllowNull()][string] $VerifiedRoot = $null)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '<path-unknown>' }
    try {
        if ($VerifiedRoot) {
            $root = Normalize-FullPath -Path $VerifiedRoot -RelativeTo $VerifiedRoot
            $candidate = Normalize-FullPath -Path $Path -RelativeTo $root
            $safe = Assert-CesContainedPath -Root $root -Path $candidate -AllowRoot
            if (Paths-Equal -First $safe -Second $root) { return '<verified-repo-root>' }
            # Do not reveal child filenames: they may contain credentials.
            return '<inside-verified-repo>'
        }
    } catch { }
    return '<external-or-unverified-path>'
}

function Redact-CesKnownPaths {
    param([AllowNull()][string] $Message, [string[]] $SensitivePaths = @())
    if ([string]::IsNullOrEmpty($Message)) { return '' }
    $redacted = $Message
    $paths = @($SensitivePaths | Where-Object { -not [string]::IsNullOrEmpty($_) } | Sort-Object Length -Descending)
    foreach ($known in $paths) {
        # Do not interpret caller-controlled paths as regex or shell patterns.
        $redacted = $redacted.Replace($known, '<redacted-path>')
    }
    # Existing Limit-Text removes terminal controls and truncates diagnostics.
    return $redacted
}
