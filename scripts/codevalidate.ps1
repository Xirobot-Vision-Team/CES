#requires -Version 7.0
<#
    EC-007: read-only checking of a model-authored CodeInsight draft against
    the exact, freshly reconciled local CodePrepare review packet.

    Checks packet identity, input shape, layer/path membership and literal
    excerpt presence in the exact untracked text or pathspec-scoped Git diff. This is NOT semantic verification of a finding, proof
    of line numbers, an AI invocation, CodeSave or a persisted handoff.
#>

$script:CodeValidateDraftByteLimit = 256KB
$script:CodeValidateMaxFindings = 40
$script:CodeValidateMaxLimitations = 20

function Assert-CodeValidateUniqueKeys {
    param([System.Text.Json.JsonElement] $Node, [int] $Depth = 0)

    if ($Depth -gt 32) { throw 'Draft JSON nesting exceeds the depth limit.' }
    if ($Node.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
        # PowerShell -AsHashtable is case-insensitive in some versions. Forbid
        # both exact duplicates and alternate-cased property names before parse.
        $names = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($p in $Node.EnumerateObject()) {
            if (-not $names.Add($p.Name)) { throw 'Draft JSON has duplicate or case-colliding keys.' }
            Assert-CodeValidateUniqueKeys -Node $p.Value -Depth ($Depth + 1)
        }
    } elseif ($Node.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
        foreach ($item in $Node.EnumerateArray()) {
            Assert-CodeValidateUniqueKeys -Node $item -Depth ($Depth + 1)
        }
    }
}

function Read-CodeValidateDraft {
    param([Parameter(Mandatory)][string] $Path)

    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item -isnot [System.IO.FileInfo]) { throw 'InputPath must be a regular JSON file.' }
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'InputPath cannot name a symbolic link or reparse point.'
    }
    # EC-159: draft is untrusted evidence and any symlinked parent is unsafe.
    [void](Resolve-CesEvidencePath -Path $item.FullName -RelativeTo $item.FullName)
    $stream = [System.IO.FileStream]::new(
        $item.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
        ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
    )
    try {
        if ($stream.Length -gt $script:CodeValidateDraftByteLimit) {
            throw 'Draft exceeds the 256 KiB input bound.'
        }
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $n = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($n -le 0) { throw 'Draft changed or ended during read.' }
            $offset += $n
        }
        if ($stream.Length -ne $bytes.Length) { throw 'Draft changed size while being read.' }
        $text = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        if ($text.StartsWith([string][char]0xFEFF, [System.StringComparison]::Ordinal)) {
            $text = $text.Substring(1)
        }
        $jsonOptions = [System.Text.Json.JsonDocumentOptions]::new()
        $jsonOptions.MaxDepth = 32
        $jsonOptions.AllowTrailingCommas = $false
        $jsonOptions.CommentHandling = [System.Text.Json.JsonCommentHandling]::Disallow
        $document = [System.Text.Json.JsonDocument]::Parse($text, $jsonOptions)
        try {
            Assert-CodeValidateUniqueKeys -Node $document.RootElement
        } finally { $document.Dispose() }
        $draft = ConvertFrom-Json -InputObject $text -AsHashtable -Depth 32 -ErrorAction Stop
        if ($draft -isnot [System.Collections.IDictionary]) { throw 'Draft root must be an object.' }
        return [pscustomobject]@{
            full_path = $item.FullName
            bytes = $bytes.Length
            sha256 = (Get-HashOfBytes -Bytes $bytes)
            draft = $draft
        }
    } finally { $stream.Dispose() }
}

function Assert-CodeValidateKeys {
    param(
        [System.Collections.IDictionary] $Object,
        [string[]] $Required,
        [string[]] $Optional = @()
    )
    if ($null -eq $Object) { throw 'Expected a JSON object.' }
    foreach ($name in $Required) {
        if (-not $Object.Contains($name)) { throw "Required field '$name' is missing." }
    }
    foreach ($key in $Object.Keys) {
        if ([string]$key -cnotin ($Required + $Optional)) {
            throw "Unknown draft field '$key' is not allowed."
        }
    }
}

function Assert-CodeValidateText {
    param([object] $Value, [string] $Field, [int] $Limit, [int] $Minimum = 1)
    if ($Value -isnot [string] -or $Value.Length -lt $Minimum -or $Value.Length -gt $Limit -or
        [string]::IsNullOrWhiteSpace($Value) -or
        $Value -match '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]') {
        throw "Field '$Field' must be a bounded, nonblank, printable string."
    }
}

function Find-CodeValidatePath {
    param([System.Collections.IDictionary] $Layer, [string] $Path)

    foreach ($entry in @($Layer.entries)) {
        if ([string]::Equals([string]$entry.path, $Path, [System.StringComparison]::Ordinal)) {
            return [pscustomobject]@{ entry = $entry; endpoint = 'path' }
        }
    }
    # Deleted/renamed files can be reviewed by their old Git pathname, too.
    foreach ($entry in @($Layer.entries)) {
        if ($null -ne $entry.old_path -and
            [string]::Equals([string]$entry.old_path, $Path, [System.StringComparison]::Ordinal)) {
            return [pscustomobject]@{ entry = $entry; endpoint = 'old_path' }
        }
    }
    return $null
}

function Get-CodeValidateScopedPatch {
    param(
        [string] $GitExecutable,
        [string] $RepoRoot,
        [string] $LayerName,
        [System.Collections.IDictionary] $Scope,
        [object] $Entry
    )

    # Request a bounded, literal Git pathspec diff for exactly the matched
    # inventory entry (and its rename origin). This closes the weaker case
    # where a quote appears in some OTHER file of a large aggregate layer.
    # The final Reconcile gate still establishes only non-atomic samples.
    $argsForGit = @('diff')
    if ($LayerName -eq 'staged') { $argsForGit += '--cached' }
    $argsForGit += @(
        '--binary', '--full-index', '--find-renames', '--no-ext-diff',
        '--no-textconv', '--no-color', '--ignore-submodules=none'
    )
    if ($LayerName -eq 'changes') {
        $argsForGit += @([string]$Scope.base_sha, [string]$Scope.target_sha)
    }
    $argsForGit += '--'
    $paths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    [void] $paths.Add([string]$Entry.path)
    if ($null -ne $Entry.old_path) { [void] $paths.Add([string]$Entry.old_path) }
    foreach ($path in ($paths | Sort-Object -CaseSensitive)) {
        $argsForGit += (':(literal)' + $path)
    }
    return Git-In -GitExecutable $GitExecutable -Directory $RepoRoot -Arguments $argsForGit -MaxStdoutBytes $script:CollectPatchByteLimit -PreserveStdout
}

function Assert-CodeValidateDraftShape {
    param([System.Collections.IDictionary] $Draft)

    Assert-CodeValidateKeys -Object $Draft -Required @(
        'schema_version', 'task_kind', 'packet_sha256', 'saved_collect_sha256',
        'summary', 'findings', 'limitations'
    )
    if ($Draft.schema_version -cne 'ces.code_insight_draft.v1' -or
        $Draft.task_kind -cne 'code_analysis') {
        throw 'Draft must be a ces.code_insight_draft.v1 code_analysis object.'
    }
    foreach ($name in @('packet_sha256', 'saved_collect_sha256')) {
        if ($Draft[$name] -isnot [string] -or $Draft[$name] -cnotmatch '^[0-9a-f]{64}$') {
            throw "Field '$name' must contain lowercase SHA-256."
        }
    }
    Assert-CodeValidateText -Value $Draft.summary -Field 'summary' -Limit 4000
    if ($Draft.findings -isnot [array] -or $Draft.findings.Count -gt $script:CodeValidateMaxFindings) {
        throw 'Draft findings must be an array with no more than 40 entries.'
    }
    if ($Draft.limitations -isnot [array] -or $Draft.limitations.Count -gt $script:CodeValidateMaxLimitations) {
        throw 'Draft limitations must be an array with no more than 20 entries.'
    }
    foreach ($limitation in $Draft.limitations) {
        Assert-CodeValidateText -Value $limitation -Field 'limitations[]' -Limit 700
    }
    $ids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($f in $Draft.findings) {
        if ($f -isnot [System.Collections.IDictionary]) { throw 'Each finding must be a JSON object.' }
        Assert-CodeValidateKeys -Object $f -Required @(
            'id', 'title', 'severity', 'confidence', 'layer', 'path',
            'evidence_quote', 'reasoning', 'impact', 'recommendation'
        ) -Optional @('line_start', 'line_end')
        if ($f.id -isnot [string] -or $f.id -cnotmatch '^[A-Za-z][A-Za-z0-9_-]{0,31}$' -or
            -not $ids.Add($f.id)) { throw 'Finding IDs must be unique short ASCII identifiers.' }
        Assert-CodeValidateText -Value $f.title -Field 'title' -Limit 180 -Minimum 4
        Assert-CodeValidateText -Value $f.path -Field 'path' -Limit 4096
        Assert-CodeValidateText -Value $f.evidence_quote -Field 'evidence_quote' -Limit 900 -Minimum 8
        Assert-CodeValidateText -Value $f.reasoning -Field 'reasoning' -Limit 2400 -Minimum 8
        Assert-CodeValidateText -Value $f.impact -Field 'impact' -Limit 1200 -Minimum 8
        Assert-CodeValidateText -Value $f.recommendation -Field 'recommendation' -Limit 1200 -Minimum 8
        if ($f.severity -isnot [string] -or $f.confidence -isnot [string] -or
            $f.layer -isnot [string] -or
            $f.severity -cnotin @('critical','high','medium','low','info') -or
            $f.confidence -cnotin @('high','medium','low') -or
            $f.layer -cnotin @('staged','unstaged','untracked','changes')) {
            throw 'Finding severity, confidence or layer value is not supported.'
        }
        $hasStart = $f.Contains('line_start')
        $hasEnd = $f.Contains('line_end')
        if ($hasStart -ne $hasEnd) { throw 'Provide both line_start and line_end, or neither.' }
        if ($hasStart) {
            foreach ($key in @('line_start','line_end')) {
                if ($f[$key] -isnot [int] -and $f[$key] -isnot [long]) {
                    throw 'Claimed line references must be positive integers.'
                }
            }
            if ($f.line_start -lt 1 -or $f.line_end -lt $f.line_start -or
                $f.line_end -gt 10000000 -or ($f.line_end - $f.line_start) -gt 200) {
                throw 'Claimed line references are out of bounds.'
            }
        }
    }
}

function CodeValidate-Snapshot {
    param(
        [System.Collections.IDictionary] $Envelope,
        [string] $InputPath,
        [string] $RepoPath,
        [string] $EvidencePath,
        [string] $GitExecutable,
        [bool] $RevealPatches,
        [bool] $RevealUntrackedContent
    )

    if ([string]::IsNullOrWhiteSpace($InputPath)) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'INPUT_PATH_REQUIRED'
        $Envelope.message = 'CodeValidate requires an explicit model-authored JSON draft at -InputPath.'
        return 4
    }
    if ([string]::IsNullOrWhiteSpace($EvidencePath)) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'EVIDENCE_PATH_REQUIRED'
        $Envelope.message = 'CodeValidate requires the original user-saved Collect JSON at -EvidencePath.'
        return 4
    }

    # First validate the draft as bounded, strict, single-purpose JSON.
    # Read-only; never run commands found in its strings.
    $draftFile = $null
    try {
        $draftFile = Read-CodeValidateDraft -Path $InputPath
        Assert-CodeValidateDraftShape -Draft $draftFile.draft
    } catch {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_VALIDATE_DRAFT_INVALID'
        $Envelope.message = 'The draft is unreadable, malformed, oversize or violates the CodeInsight draft contract.'
        $Envelope.warnings = @((Limit-Text $_.Exception.Message 250))
        return 4
    }

    # The entire CodePrepare gate is reused, including Reconcile, the source
    # selector, independent disclosure consent and saved-evidence stability.
    $prepared = New-Envelope -ActionName 'CodePrepare'
    $prepareCode = CodePrepare-Snapshot -Envelope $prepared -InputPath $RepoPath -EvidencePath $EvidencePath -GitExecutable $GitExecutable -RevealPatches $RevealPatches -RevealUntrackedContent $RevealUntrackedContent
    $Envelope.coverage = $prepared.coverage
    $Envelope.evidence = $prepared.evidence
    $Envelope.warnings = $prepared.warnings
    if ($prepareCode -ne 0 -or $null -eq $prepared.data -or $prepared.data.prepared -ne $true -or
        $prepared.reason_code -cne 'CODE_PREPARE_READY' -or $null -eq $prepared.data.review_packet) {
        $Envelope.status = $prepared.status
        $Envelope.reason_code = if ($prepareCode -eq 0) { 'CODE_VALIDATE_NO_PACKET' } elseif ($prepareCode -eq 2) { 'CODE_VALIDATE_SOURCE_NOT_READY' } else { $prepared.reason_code }
        $Envelope.message = 'Draft not checked: the saved source could not produce a fresh, content-complete review packet.'
        $Envelope.data = [ordered]@{ validated = $false; can_persist_ces_state = $false; checked_findings = @(); source_status = $prepared.status; source_reason_code = $prepared.reason_code }
        return $(if ($prepareCode -eq 0) { 2 } else { $prepareCode })
    }
    $packet = $prepared.data.review_packet
    $expectedPacketSha = [string]$prepared.data.packet_sha256
    $expectedCollectSha = [string]$prepared.data.preparation.saved_collect_sha256
    if ($draftFile.draft.packet_sha256 -cne $expectedPacketSha -or
        $draftFile.draft.saved_collect_sha256 -cne $expectedCollectSha) {
        $Envelope.status = 'partial'; $Envelope.reason_code = 'CODE_VALIDATE_PACKET_MISMATCH'
        $Envelope.message = 'Draft is bound to a different or older review packet; no findings were accepted.'
        $Envelope.data = [ordered]@{ validated = $false; can_persist_ces_state = $false; checked_findings = @(); packet_bound = $false }
        return 2
    }

    $checked = [System.Collections.Generic.List[object]]::new()
    $scopedPatches = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::Ordinal)
    $anchorGitUnavailable = $false
    try {
        foreach ($finding in $draftFile.draft.findings) {
            $layerName = [string]$finding.layer
            if (-not $packet.layers.Contains($layerName)) { throw 'Finding refers to a layer absent from this source mode.' }
            $layer = $packet.layers[$layerName]
            $matched = Find-CodeValidatePath -Layer $layer -Path $finding.path
            if ($null -eq $matched) { throw 'Finding refers to a path absent from its selected layer.' }
            $quote = [string]$finding.evidence_quote
            $grade = 'diff_layer_literal_only'
            $content = $null
            if ($layerName -eq 'untracked') {
                if ($matched.entry.content_state -cne 'included' -or $matched.entry.content -isnot [string]) {
                    throw 'Untracked finding lacks complete exact-file content.'
                }
                $content = [string]$matched.entry.content
                $grade = 'exact_untracked_file_literal'
            } else {
                if ($layer.patch_state -cne 'included' -or $layer.patch -isnot [string]) {
                    throw 'Tracked finding lacks complete opt-in layer patch.'
                }
                $content = [string]$layer.patch
            }
            if ($content.IndexOf($quote, [System.StringComparison]::Ordinal) -lt 0) {
                throw 'Finding quote is absent from the disclosed layer content.'
            }
            if ($layerName -ne 'untracked') {
                $cacheKey = $layerName + [char]0 + [string]$matched.entry.path + [char]0 + [string]$matched.entry.old_path
                if (-not $scopedPatches.ContainsKey($cacheKey)) {
                    $probe = Get-CodeValidateScopedPatch -GitExecutable $GitExecutable -RepoRoot $prepared.data.source_root -LayerName $layerName -Scope $packet.scope -Entry $matched.entry
                    if (-not $probe.ok) {
                        $anchorGitUnavailable = $true
                        throw 'Scoped read-only Git patch is unavailable or exceeds the content bound.'
                    }
                    $scopedPatches.Add($cacheKey, $probe.stdout)
                }
                if ($scopedPatches[$cacheKey].IndexOf($quote, [System.StringComparison]::Ordinal) -lt 0) {
                    throw 'Finding quote is not present in the literal pathspec-scoped diff for this Git entry.'
                }
                $grade = 'pathspec_scoped_tracked_diff_literal'
            }
            $checked.Add([ordered]@{
                id = $finding.id
                title = $finding.title
                severity = $finding.severity
                confidence = $finding.confidence
                layer = $layerName
                path = $finding.path
                path_endpoint = $matched.endpoint
                line_start_claimed = if ($finding.Contains('line_start')) { $finding.line_start } else { $null }
                line_end_claimed = if ($finding.Contains('line_end')) { $finding.line_end } else { $null }
                line_numbers_verified = $false
                quote_sha256 = (Get-HashOfText -Content $quote)
                quote_presence = $grade
                reasoning = $finding.reasoning
                impact = $finding.impact
                recommendation = $finding.recommendation
            })
        }
    } catch {
        $Envelope.status = if ($anchorGitUnavailable) { 'partial' } else { 'invalid_input' }
        $Envelope.reason_code = if ($anchorGitUnavailable) { 'CODE_VALIDATE_ANCHOR_UNAVAILABLE' } else { 'CODE_VALIDATE_EVIDENCE_UNBOUND' }
        $Envelope.message = if ($anchorGitUnavailable) {
            'A read-only per-file Git anchor could not be checked; all draft findings were suppressed.'
        } else {
            'At least one finding is not anchored to an included Git layer, pathname and literal quote; the entire draft was rejected.'
        }
        $Envelope.warnings = @((Limit-Text $_.Exception.Message 250))
        $Envelope.data = [ordered]@{ validated = $false; can_persist_ces_state = $false; checked_findings = @() }
        return $(if ($anchorGitUnavailable) { 2 } else { 4 })
    }

    # A final source and both input-file recheck before returning claims.
    # Two local observations cannot guarantee continuity or authenticate the
    # model/draft; stale source always results in a findings-free response.
    $rechecked = New-Envelope -ActionName 'Reconcile'
    $recheckCode = Reconcile-Snapshot -Envelope $rechecked -InputPath $RepoPath -EvidencePath $EvidencePath -GitExecutable $GitExecutable
    $draftStable = $false
    try {
        $last = Read-CodeValidateDraft -Path $draftFile.full_path
        $draftStable = ($last.sha256 -ceq $draftFile.sha256 -and $last.bytes -eq $draftFile.bytes)
    } catch { $draftStable = $false }
    if ($recheckCode -ne 0 -or $null -eq $rechecked.data -or
        $rechecked.data.verdict -cne 'matched' -or -not $draftStable -or
        $rechecked.data.previous_snapshot.snapshot_file_sha256 -cne $expectedCollectSha) {
        $Envelope.status = 'partial'; $Envelope.reason_code = 'CODE_VALIDATE_INPUT_CHANGED'
        $Envelope.message = 'The draft or observed local Git scope could not be shown stable at return; all draft findings were suppressed.'
        $Envelope.coverage.snapshot_file_stable = $false
        $Envelope.data = [ordered]@{ validated = $false; can_persist_ces_state = $false; checked_findings = @() }
        return 2
    }

    $Envelope.coverage.code_draft_checked = $true
    $Envelope.coverage.code_findings_anchored = $true
    $Envelope.status = 'success'; $Envelope.reason_code = 'CODE_VALIDATE_OK'
    $Envelope.message = 'Draft identity and literal source anchors checked. Finding correctness, hunk/line numbers, CI, remote delivery and provenance are not verified.'
    $Envelope.data = [ordered]@{
        validated = $true
        task_kind = 'code_analysis'
        output_schema = 'ces.code_insight_checked.v1'
        can_persist_ces_state = $false
        persisted = $false
        packet_bound = $true
        source_root = $prepared.data.source_root
        stable_project_root = $prepared.data.stable_project_root
        source_mode = $packet.scope.source_mode
        verification_scope = 'two_non_atomic_local_samples_and_pathspec_scoped_literal_quote_membership'
        evidence_provenance_authenticated = $false
        model_origin_authenticated = $false
        semantic_claims_verified = $false
        claimed_line_numbers_verified = $false
        ci_verified = $false
        remote_delivery_verified = $false
        deployment_verified = $false
        draft_sha256 = $draftFile.sha256
        packet_sha256 = $expectedPacketSha
        saved_collect_sha256 = $expectedCollectSha
        summary = $draftFile.draft.summary
        limitations = @($draftFile.draft.limitations)
        finding_count = $checked.Count
        checked_findings = $checked.ToArray()
    }
    return 0
}
