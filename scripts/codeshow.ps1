#requires -Version 7.0
<#
    EC-009 to EC-021: read-only, locally bounded CodeInsight records, Findings,
    comparison, historical trace, aggregate Overview, file-level Triage and
    exact-anchor Recurrence, plus bounded cross-page Recurrence/Triage selections.
    List, Detail and Findings operate on records written by CodeSave, NEVER on arbitrary
    paths supplied by the caller. Both check a verified main-worktree boundary,
    fixed owner marker, file types and per-record content-address integrity.
    Digest equality is corruption detection, NOT authorship or source freshness.
#>

$script:CodeShowMaxPageSize = 100
$script:CodeShowMaxStoreEntries = 2000
$script:CodeShowRecordIdPattern = '^ci-[0-9a-f]{64}$'

function Assert-CodeShowRecordId {
    param([AllowNull()][string] $Id)
    if ([string]::IsNullOrEmpty($Id) -or $Id -cnotmatch $script:CodeShowRecordIdPattern) {
        throw 'RecordId must be ci- followed by exactly 64 lowercase hexadecimal characters.'
    }
}

function Assert-CodeShowJsonUniqueKeys {
    param([System.Text.Json.JsonElement] $Node, [int] $Depth = 0)

    if ($Depth -gt 32) { throw 'Saved record JSON exceeds the nesting limit.' }
    if ($Node.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
        $keys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($property in $Node.EnumerateObject()) {
            if (-not $keys.Add($property.Name)) { throw 'Saved record contains duplicate or case-colliding JSON keys.' }
            Assert-CodeShowJsonUniqueKeys -Node $property.Value -Depth ($Depth + 1)
        }
    } elseif ($Node.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
        foreach ($child in $Node.EnumerateArray()) {
            Assert-CodeShowJsonUniqueKeys -Node $child -Depth ($Depth + 1)
        }
    }
}

function Convert-CodeShowJsonValue {
    param([System.Text.Json.JsonElement] $Node, [int] $Depth = 0)

    # JsonElement preserves strings verbatim, including date-looking prose.
    # Older ConvertFrom-Json may coerce ISO strings to DateTime; a narrow v1
    # value converter avoids changing the saved free-form text on retrieval.
    if ($Depth -gt 32) { throw 'Saved record exceeds the JSON value depth limit.' }
    if ($Node.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
        $map = [ordered]@{}
        foreach ($property in $Node.EnumerateObject()) {
            $map[$property.Name] = Convert-CodeShowJsonValue -Node $property.Value -Depth ($Depth + 1)
        }
        return $map
    }
    if ($Node.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
        $values = [System.Collections.Generic.List[object]]::new()
        foreach ($element in $Node.EnumerateArray()) {
            $values.Add((Convert-CodeShowJsonValue -Node $element -Depth ($Depth + 1)))
        }
        return ,$values.ToArray()
    }
    if ($Node.ValueKind -eq [System.Text.Json.JsonValueKind]::String) { return $Node.GetString() }
    if ($Node.ValueKind -eq [System.Text.Json.JsonValueKind]::Number) {
        $integer = [long]0
        if (-not $Node.TryGetInt64([ref]$integer)) { throw 'Saved record contains an unsupported non-integer number.' }
        return $integer
    }
    if ($Node.ValueKind -eq [System.Text.Json.JsonValueKind]::True) { return $true }
    if ($Node.ValueKind -eq [System.Text.Json.JsonValueKind]::False) { return $false }
    if ($Node.ValueKind -eq [System.Text.Json.JsonValueKind]::Null) { return $null }
    throw 'Saved record contains an unsupported JSON value.'
}

function Assert-CodeShowRecordShape {
    param([System.Collections.IDictionary] $Record, [string] $VerifiedRoot)

    # Accept ONLY the current CodeSave v1 format. A self-hashed foreign JSON
    # file is not automatically a trusted CES insight.
    Assert-CodeValidateKeys -Object $Record -Required @(
        'schema_version', 'task_kind', 'source_root', 'source_mode',
        'saved_collect_sha256', 'packet_sha256', 'draft_sha256', 'verification_scope',
        'model_origin_authenticated', 'source_provenance_authenticated',
        'semantic_claims_verified', 'claimed_line_numbers_verified',
        'remote_delivery_verified', 'ci_verified', 'summary', 'limitations',
        'finding_count', 'checked_findings'
    )
    if ($Record.schema_version -cne 'ces.code_insight_saved.v1' -or $Record.task_kind -cne 'code_analysis') {
        throw 'The saved record schema or task kind is unsupported.'
    }
    if ($Record.source_root -isnot [string] -or
        -not (Paths-Equal -First $Record.source_root -Second $VerifiedRoot)) {
        throw 'Saved record was not bound to this verified main worktree.'
    }
    if ($Record.source_mode -isnot [string] -or
        $Record.source_mode -cnotin @('working_tree_diff','delivered_target_diff')) {
        throw 'Unsupported saved source mode.'
    }
    foreach ($key in @('saved_collect_sha256','packet_sha256','draft_sha256')) {
        if ($Record[$key] -isnot [string] -or $Record[$key] -cnotmatch '^[0-9a-f]{64}$') {
            throw "Saved field '$key' is not a lowercase SHA-256."
        }
    }
    if ($Record.verification_scope -cne 'two_non_atomic_local_samples_and_pathspec_scoped_literal_quote_membership') {
        throw 'Unsupported saved verification scope.'
    }
    foreach ($key in @(
        'model_origin_authenticated', 'source_provenance_authenticated',
        'semantic_claims_verified', 'claimed_line_numbers_verified',
        'remote_delivery_verified', 'ci_verified'
    )) {
        if ($Record[$key] -isnot [bool] -or $Record[$key] -ne $false) {
            throw "Saved record may not assert unverified proof '$key'."
        }
    }
    Assert-CodeValidateText -Value $Record.summary -Field 'summary' -Limit 4000
    if ($Record.limitations -isnot [array] -or $Record.limitations.Count -gt 20) {
        throw 'Saved limitations are not a bounded array.'
    }
    foreach ($limitation in $Record.limitations) {
        Assert-CodeValidateText -Value $limitation -Field 'limitations[]' -Limit 700
    }
    if (($Record.finding_count -isnot [int] -and $Record.finding_count -isnot [long]) -or
        $Record.finding_count -lt 0 -or $Record.finding_count -gt 40 -or
        $Record.checked_findings -isnot [array] -or
        $Record.checked_findings.Count -ne $Record.finding_count) {
        throw 'Saved finding count and checked-findings array disagree.'
    }
    $ids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($finding in $Record.checked_findings) {
        if ($finding -isnot [System.Collections.IDictionary]) { throw 'Saved finding is not an object.' }
        Assert-CodeValidateKeys -Object $finding -Required @(
            'id','title','severity','confidence','layer','path','path_endpoint',
            'line_start_claimed','line_end_claimed','line_numbers_verified',
            'quote_sha256','quote_presence','reasoning','impact','recommendation'
        )
        if ($finding.id -isnot [string] -or $finding.id -cnotmatch '^[A-Za-z][A-Za-z0-9_-]{0,31}$' -or
            -not $ids.Add($finding.id)) { throw 'Saved finding identifier is invalid or duplicated.' }
        Assert-CodeValidateText -Value $finding.title -Field 'title' -Limit 180 -Minimum 4
        Assert-CodeValidateText -Value $finding.path -Field 'path' -Limit 4096
        Assert-CodeValidateText -Value $finding.reasoning -Field 'reasoning' -Limit 2400 -Minimum 8
        Assert-CodeValidateText -Value $finding.impact -Field 'impact' -Limit 1200 -Minimum 8
        Assert-CodeValidateText -Value $finding.recommendation -Field 'recommendation' -Limit 1200 -Minimum 8
        if ($finding.severity -cnotin @('critical','high','medium','low','info') -or
            $finding.confidence -cnotin @('high','medium','low') -or
            $finding.layer -cnotin @('staged','unstaged','untracked','changes') -or
            $finding.path_endpoint -cnotin @('path','old_path') -or
            $finding.quote_presence -cnotin @(
                'diff_layer_literal_only','exact_untracked_file_literal','pathspec_scoped_tracked_diff_literal'
            )) { throw 'Saved finding enum is invalid.' }
        # This is a consistency check with the actual R007 validator's
        # output, not a re-check of the source or semantic finding claim.
        if ($Record.source_mode -ceq 'delivered_target_diff') {
            if ($finding.layer -cne 'changes') { throw 'Delivered-target finding has an impossible source layer.' }
        } elseif ($finding.layer -cnotin @('staged','unstaged','untracked')) {
            throw 'Working-tree finding has an impossible source layer.'
        }
        if ($finding.layer -ceq 'untracked') {
            if ($finding.path_endpoint -cne 'path' -or
                $finding.quote_presence -cne 'exact_untracked_file_literal') {
                throw 'Untracked finding has an impossible proof marker.'
            }
        } elseif ($finding.quote_presence -cne 'pathspec_scoped_tracked_diff_literal') {
            throw 'Tracked finding has an impossible proof marker.'
        }
        if ($finding.line_numbers_verified -isnot [bool] -or $finding.line_numbers_verified) {
            throw 'Saved finding incorrectly asserts verified line numbers.'
        }
        if ($finding.quote_sha256 -isnot [string] -or $finding.quote_sha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw 'Saved finding quote digest is invalid.'
        }
        $start = $finding.line_start_claimed
        $end = $finding.line_end_claimed
        if (($null -eq $start) -ne ($null -eq $end)) {
            throw 'Saved claimed line interval is incomplete.'
        }
        if ($null -ne $start) {
            if (($start -isnot [int] -and $start -isnot [long]) -or
                ($end -isnot [int] -and $end -isnot [long]) -or
                $start -lt 1 -or $end -lt $start -or $end -gt 10000000 -or
                ($end - $start) -gt 200) {
                throw 'Saved claimed line interval is invalid.'
            }
        }
    }
}

function Read-CodeShowRecord {
    param([string] $Directory, [string] $Id, [string] $VerifiedRoot)

    Assert-CodeShowRecordId -Id $Id
    $path = Join-Path $Directory ($Id + '.json')
    $first = Read-CodeSaveBoundedBytes -Path $path -MaxBytes $script:CodeSaveRecordByteLimit
    $digest = Get-HashOfBytes -Bytes $first
    if ($digest -cne $Id.Substring(3)) { throw 'Saved record bytes do not match the SHA-256 in its filename.' }
    $text = [System.Text.UTF8Encoding]::new($false, $true).GetString($first)
    if ($text.StartsWith([string][char]0xFEFF, [System.StringComparison]::Ordinal)) {
        throw 'Saved CodeInsight record must not contain a UTF-8 BOM.'
    }
    $settings = [System.Text.Json.JsonDocumentOptions]::new()
    $settings.MaxDepth = 32
    $settings.AllowTrailingCommas = $false
    $settings.CommentHandling = [System.Text.Json.JsonCommentHandling]::Disallow
    $document = [System.Text.Json.JsonDocument]::Parse($text, $settings)
    try {
        Assert-CodeShowJsonUniqueKeys -Node $document.RootElement
        $record = Convert-CodeShowJsonValue -Node $document.RootElement
    } finally { $document.Dispose() }
    if ($record -isnot [System.Collections.IDictionary]) { throw 'Saved record must contain a JSON object.' }
    Assert-CodeShowRecordShape -Record $record -VerifiedRoot $VerifiedRoot
    # A second exact-length/content read detects ordinary concurrent edits.
    # It does NOT create an atomic filesystem snapshot or resist malicious races.
    $second = Read-CodeSaveBoundedBytes -Path $path -MaxBytes $script:CodeSaveRecordByteLimit
    if ($second.Length -ne $first.Length -or (Get-HashOfBytes -Bytes $second) -cne $digest) {
        throw 'Saved record changed during this read.'
    }
    return [pscustomobject]@{
        id = $Id
        path = $path
        sha256 = $digest
        record = $record
    }
}

function Get-CodeShowRecordIds {
    param([string] $Directory)

    $items = [System.Collections.Generic.List[string]]::new()
    foreach ($path in [System.IO.Directory]::EnumerateFileSystemEntries($Directory)) {
        if ($items.Count -ge $script:CodeShowMaxStoreEntries) {
            throw 'CODE_SHOW_SCAN_LIMIT: the CES local store exceeded the bounded enumeration limit.'
        }
        $leaf = [System.IO.Path]::GetFileName($path)
        if ($leaf -cnotmatch '^ci-[0-9a-f]{64}\.json$') {
            throw 'Unknown or incomplete entry exists inside CES code-insights; no partial inventory asserted.'
        }
        [void](Test-CodeSaveRegularItem -Path $path -Directory $false)
        $items.Add($leaf.Substring(0, $leaf.Length - '.json'.Length))
    }
    # SHA names are ASCII lowercase; ordinal ordering supplies reproducible
    # cursor semantics on PowerShell hosts with different locales.
    $items.Sort([System.StringComparer]::Ordinal)
    return $items.ToArray()
}

function Get-CodeShowOptionalItem {
    param([string] $Path)
    try {
        return Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    } catch [System.Management.Automation.ItemNotFoundException] {
        return $null
    }
}

function Assert-CodeShowOwnerMarker {
    param([string] $Path)
    $expected = [System.Text.UTF8Encoding]::new($false).GetBytes($script:CodeSaveOwnerJson)
    $actual = Read-CodeSaveBoundedBytes -Path $Path -MaxBytes 512
    if ($actual.Length -ne $expected.Length) { throw 'Invalid CES local store owner marker.' }
    for ($i = 0; $i -lt $actual.Length; $i++) {
        if ($actual[$i] -ne $expected[$i]) { throw 'Invalid CES local store owner marker.' }
    }
}

function Get-CodeShowStore {
    param([string] $RepoRoot, [string] $GitExecutable)

    [void](Test-CodeSaveRegularItem -Path $RepoRoot -Directory $true)
    [void](Assert-CesVerifiedMainWorktree -GitExecutable $GitExecutable -RepoRoot $RepoRoot)
    Assert-CodeSaveGitBoundary -GitExecutable $GitExecutable -RepoRoot $RepoRoot -AdditionalTargetSha $null
    $dotCodex = Join-Path $RepoRoot '.codex'
    $ownerDir = Join-Path $dotCodex 'ces'
    $owner = Join-Path $ownerDir 'owner.json'
    $records = Join-Path $ownerDir 'code-insights'
    [void](Assert-CesContainedPath -Root $RepoRoot -Path $records)

    # Probe leaf objects as well as Test-Path: a dangling symlink is unsafe,
    # not proof that the local CES store is simply missing.
    $codexItem = Get-CodeShowOptionalItem -Path $dotCodex
    if ($null -eq $codexItem) { return [pscustomobject]@{ exists = $false; directory = $null; owner = $null } }
    [void](Test-CodeSaveRegularItem -Path $dotCodex -Directory $true)
    if ($null -ne (Get-CodeShowOptionalItem -Path (Join-Path $dotCodex '.git'))) {
        throw 'The .codex parent is a nested Git repository.'
    }
    $stateItem = Get-CodeShowOptionalItem -Path $ownerDir
    if ($null -eq $stateItem) { return [pscustomobject]@{ exists = $false; directory = $null; owner = $null } }
    [void](Test-CodeSaveRegularItem -Path $ownerDir -Directory $true)
    Assert-CodeShowOwnerMarker -Path $owner
    [void](Test-CodeSaveRegularItem -Path $records -Directory $true)
    return [pscustomobject]@{ exists = $true; directory = $records; owner = $owner }
}

function CodeShow-Local {
    param(
        [System.Collections.IDictionary] $Envelope,
        [string] $RepoPath,
        [string] $GitExecutable,
        [string] $Mode,
        [string] $RecordId,
        [string] $AfterRecordId,
        [int] $Limit,
        [string] $AfterFindingCursor,
        [string] $FindingSeverity,
        [string] $FindingLayer,
        [string] $FindingPath,
        [string] $FindingSourceMode,
        [string] $FindingsRecordIds,
        [bool] $FindingsRecordIdsExplicit = $false,
        [bool] $AfterFindingCursorExplicit = $false,
        [string] $LeftRecordId,
        [string] $RightRecordId,
        [string] $FindingId,
        [string] $AfterTraceCursor,
        [string] $TraceRecordIds,
        [bool] $TraceRecordIdsExplicit = $false,
        [string] $AfterOverviewCursor,
        [string] $OverviewSourceMode,
        [string] $OverviewRecordIds,
        [bool] $OverviewRecordIdsExplicit = $false,
        [string] $AfterTriageCursor,
        [string] $TriageSourceMode,
        [int] $TriageTop = 15,
        [string] $TriageRecordIds,
        [bool] $TriageRecordIdsExplicit = $false,
        [bool] $LimitExplicit = $false,
        [string] $AfterRecurrenceCursor,
        [string] $RecurrenceSourceMode,
        [string] $RecurrencePath,
        [int] $RecurrenceMinRecords = 2,
        [int] $RecurrenceTop = 15,
        [string] $RecurrenceRecordIds,
        [string] $SequenceRecordIds,
        [int] $SequenceTop = 10,
        [AllowNull()][string] $SequencePath = $null,
        [bool] $SequencePathExplicit = $false,
        [AllowNull()][string] $SequenceFindingRecordId = $null,
        [AllowNull()][string] $SequenceFindingId = $null,
        [bool] $SequenceFindingRecordIdExplicit = $false,
        [bool] $SequenceFindingIdExplicit = $false,
        [AllowNull()][string] $SequenceAnchorIndex = $null,
        [bool] $SequenceAnchorIndexExplicit = $false,
        [AllowNull()][string] $SequencePairIndex = $null,
        [bool] $SequencePairIndexExplicit = $false,
        [AllowNull()][string] $SequencePairOverviewIndex = $null,
        [bool] $SequencePairOverviewIndexExplicit = $false,
        [AllowNull()][string] $SequencePairPathIndex = $null,
        [bool] $SequencePairPathIndexExplicit = $false,
        [AllowNull()][string] $SequencePairPathAnchorIndex = $null,
        [bool] $SequencePairPathAnchorIndexExplicit = $false,
        [AllowNull()][string] $SequencePairPathAnchorFindingSide = $null,
        [bool] $SequencePairPathAnchorFindingSideExplicit = $false,
        [AllowNull()][string] $SequencePairPathAnchorFindingIndex = $null,
        [bool] $SequencePairPathAnchorFindingIndexExplicit = $false,
        [AllowNull()][string] $SequencePairPathAnchorFindingCounterpartIndex = $null,
        [bool] $SequencePairPathAnchorFindingCounterpartIndexExplicit = $false
    )

    # CLI validates field applicability; repeat the dangerous boundaries at
    # the action for direct-module callers who bypass the dispatcher.
    if (-not [string]::IsNullOrEmpty($TriageRecordIds)) { $TriageRecordIdsExplicit = $true }
    if (-not [string]::IsNullOrEmpty($OverviewRecordIds)) { $OverviewRecordIdsExplicit = $true }
    if (-not [string]::IsNullOrEmpty($TraceRecordIds)) { $TraceRecordIdsExplicit = $true }
    if (-not [string]::IsNullOrEmpty($FindingsRecordIds)) { $FindingsRecordIdsExplicit = $true }
    if (-not [string]::IsNullOrEmpty($AfterFindingCursor)) { $AfterFindingCursorExplicit = $true }
    if (-not [string]::IsNullOrEmpty($SequencePath)) { $SequencePathExplicit = $true }
    if (-not [string]::IsNullOrEmpty($SequenceFindingRecordId)) { $SequenceFindingRecordIdExplicit = $true }
    if (-not [string]::IsNullOrEmpty($SequenceFindingId)) { $SequenceFindingIdExplicit = $true }
    if (-not [string]::IsNullOrEmpty($SequenceAnchorIndex)) { $SequenceAnchorIndexExplicit = $true }
    if (-not [string]::IsNullOrEmpty($SequencePairIndex)) { $SequencePairIndexExplicit = $true }
    if (-not [string]::IsNullOrEmpty($SequencePairOverviewIndex)) { $SequencePairOverviewIndexExplicit = $true }
    if (-not [string]::IsNullOrEmpty($SequencePairPathIndex)) { $SequencePairPathIndexExplicit = $true }
    if (-not [string]::IsNullOrEmpty($SequencePairPathAnchorIndex)) { $SequencePairPathAnchorIndexExplicit = $true }
    if (-not [string]::IsNullOrEmpty($SequencePairPathAnchorFindingSide)) { $SequencePairPathAnchorFindingSideExplicit = $true }
    if (-not [string]::IsNullOrEmpty($SequencePairPathAnchorFindingIndex)) { $SequencePairPathAnchorFindingIndexExplicit = $true }
    if (-not [string]::IsNullOrEmpty($SequencePairPathAnchorFindingCounterpartIndex)) { $SequencePairPathAnchorFindingCounterpartIndexExplicit = $true }
    if ($Mode -notin @('List','Detail','Findings','Compare','Trace','Overview','Triage','Recurrence','Sequence')) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_MODE_REQUIRED'
        $Envelope.message = 'CodeShow requires -Mode List, Detail, Findings, Compare, Trace, Overview, Triage, Recurrence or Sequence.'
        return 4
    }
    if ($Mode -ieq 'List' -and ($Limit -lt 1 -or $Limit -gt $script:CodeShowMaxPageSize -or
        -not [string]::IsNullOrEmpty($RecordId))) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SELECTORS_NOT_APPLICABLE'
        $Envelope.message = 'List supports -Limit 1..100 and an optional -AfterRecordId only.'
        return 4
    }
    if ($Mode -ieq 'Detail' -and ([string]::IsNullOrEmpty($RecordId) -or
        -not [string]::IsNullOrEmpty($AfterRecordId) -or
        -not [string]::IsNullOrEmpty($AfterFindingCursor))) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SELECTORS_NOT_APPLICABLE'
        $Envelope.message = 'Detail requires -RecordId and does not accept a list cursor.'
        return 4
    }
    if ($Mode -ieq 'Findings' -and ($Limit -lt 1 -or $Limit -gt $script:CodeShowMaxPageSize -or
        -not [string]::IsNullOrEmpty($RecordId) -or -not [string]::IsNullOrEmpty($AfterRecordId))) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SELECTORS_NOT_APPLICABLE'
        $Envelope.message = 'Findings accepts -Limit 1..100, optional filters, and either a scan cursor or explicit saved record IDs.'
        return 4
    }
    if ($Mode -ieq 'Findings' -and $FindingsRecordIdsExplicit -and $AfterFindingCursorExplicit) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_FINDINGS_SELECTION_CONFLICT'
        $Envelope.message = 'Explicit Findings selection cannot be combined with any -AfterFindingCursor (even empty).'
        return 4
    }
    if ($Mode -ieq 'Sequence' -and ([string]::IsNullOrEmpty($SequenceRecordIds) -or
        -not [string]::IsNullOrEmpty($RecordId) -or
        -not [string]::IsNullOrEmpty($AfterRecordId) -or $LimitExplicit -or $Limit -ne 50)) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SEQUENCE_RECORD_IDS_INVALID'
        $Envelope.message = 'Sequence requires caller-ordered selected IDs; RecordId, List cursors and Limit are not supported.'
        return 4
    }
    if ($Mode -ieq 'Sequence' -and ($SequenceTop -lt 1 -or
        $SequenceTop -gt $script:CodeShowSequenceMaxTop)) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SEQUENCE_TOP_INVALID'
        $Envelope.message = 'SequenceTop must be an integer from 1 through 20.'
        return 4
    }
    if ($Mode -ieq 'Sequence' -and $SequencePathExplicit -and
        ([string]::IsNullOrEmpty($SequencePath) -or $SequencePath.Length -gt 4096 -or
            $SequencePath.Contains([char]0))) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SEQUENCE_PATH_INVALID'
        $Envelope.message = 'SequencePath must be a nonempty literal saved Git path of at most 4096 characters without NUL.'
        return 4
    }
    # EC-049: fifth-level opposite-endpoint original Finding requires the
    # FULL four-level selection. An explicit empty index is invalid, not absent.
    # Validate before any record body is accessed (also for direct callers).
    if ($Mode -ieq 'Sequence' -and $SequencePairPathAnchorFindingCounterpartIndexExplicit -and
        (-not $SequencePairOverviewIndexExplicit -or
            -not $SequencePairPathIndexExplicit -or
            -not $SequencePairPathAnchorIndexExplicit -or
            -not $SequencePairPathAnchorFindingSideExplicit -or
            -not $SequencePairPathAnchorFindingIndexExplicit -or
            $SequencePathExplicit -or $SequencePairIndexExplicit -or
            $SequenceAnchorIndexExplicit -or $SequenceFindingRecordIdExplicit -or
            $SequenceFindingIdExplicit -or
            $SequencePairPathAnchorFindingSide -cnotin @('left','right') -or
            $SequencePairPathAnchorFindingIndex -cnotmatch '^[1-9][0-9]?$' -or
            [int]$SequencePairPathAnchorFindingIndex -gt 40 -or
            $SequencePairPathAnchorFindingCounterpartIndex -cnotmatch '^[1-9][0-9]?$' -or
            [int]$SequencePairPathAnchorFindingCounterpartIndex -gt 40)) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SEQUENCE_PAIR_PATH_ANCHOR_FINDING_COUNTERPART_SELECTOR_INVALID'
        $Envelope.message = 'CounterpartIndex 1..40 requires the complete pair/path/anchor/side/original Finding selection and no competing focus.'
        return 4
    }
    # EC-048: strict two-coordinate endpoint original-Finding selection.
    # An explicit empty side/index is invalid, not silently absent.
    if ($Mode -ieq 'Sequence' -and
        ($SequencePairPathAnchorFindingSideExplicit -or $SequencePairPathAnchorFindingIndexExplicit) -and
        (-not $SequencePairPathAnchorFindingSideExplicit -or
            -not $SequencePairPathAnchorFindingIndexExplicit -or
            -not $SequencePairOverviewIndexExplicit -or
            -not $SequencePairPathIndexExplicit -or
            -not $SequencePairPathAnchorIndexExplicit -or
            $SequencePathExplicit -or $SequencePairIndexExplicit -or
            $SequenceAnchorIndexExplicit -or $SequenceFindingRecordIdExplicit -or
            $SequenceFindingIdExplicit -or
            $SequencePairPathAnchorFindingSide -cnotin @('left','right') -or
            $SequencePairPathAnchorFindingIndex -cnotmatch '^[1-9][0-9]?$' -or
            [int]$SequencePairPathAnchorFindingIndex -gt 40)) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SEQUENCE_PAIR_PATH_ANCHOR_FINDING_SELECTOR_INVALID'
        $Envelope.message = 'FindingSide left/right and canonical FindingIndex 1..40 require all three pair/path/anchor parents; no competing focus.'
        return 4
    }
    # EC-047: a third ordinal is meaningful only for the full indexed
    # pair/path; absent parents, malformed numbers and competing focuses fail.
    if ($Mode -ieq 'Sequence' -and $SequencePairPathAnchorIndexExplicit -and
        (-not $SequencePairOverviewIndexExplicit -or -not $SequencePairPathIndexExplicit -or
            $SequencePathExplicit -or $SequencePairIndexExplicit -or
            $SequenceAnchorIndexExplicit -or $SequenceFindingRecordIdExplicit -or
            $SequenceFindingIdExplicit -or
            $SequencePairPathAnchorIndex -cnotmatch '^[1-9][0-9]{0,2}$' -or
            [int]$SequencePairPathAnchorIndex -gt 480)) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SEQUENCE_PAIR_PATH_ANCHOR_SELECTOR_INVALID'
        $Envelope.message = 'SequencePairPathAnchorIndex requires a complete pair/path ordinal and a canonical 1..480 anchor index.'
        return 4
    }
    if ($Mode -ieq 'Sequence' -and $SequencePairPathIndexExplicit -and
        (-not $SequencePairOverviewIndexExplicit -or $SequencePathExplicit -or
            $SequencePairIndexExplicit -or $SequenceAnchorIndexExplicit -or
            $SequenceFindingRecordIdExplicit -or $SequenceFindingIdExplicit -or
            $SequencePairPathIndex -cnotmatch '^[1-9][0-9]{0,2}$' -or
            [int]$SequencePairPathIndex -gt 480)) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SEQUENCE_PAIR_PATH_SELECTOR_INVALID'
        $Envelope.message = 'SequencePairPathIndex needs a pair overview, a canonical 1..480 path index and no other focus selector.'
        return 4
    }
    if ($Mode -ieq 'Sequence' -and ($SequenceFindingRecordIdExplicit -or
        $SequenceFindingIdExplicit) -and
        (-not $SequenceFindingRecordIdExplicit -or -not $SequenceFindingIdExplicit -or
        -not $SequencePathExplicit -or
        $SequenceFindingRecordId -cnotmatch '^ci-[0-9a-f]{64}$' -or
        $SequenceFindingId -cnotmatch '^[A-Za-z][A-Za-z0-9_-]{0,31}$')) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SEQUENCE_FINDING_SELECTOR_INVALID'
        $Envelope.message = 'Sequence Finding focus requires a selected original record ID, exact original Finding ID and explicit saved path.'
        return 4
    }
    if ($Mode -ieq 'Sequence' -and $SequenceAnchorIndexExplicit -and
        (-not $SequencePathExplicit -or $SequenceFindingRecordIdExplicit -or
            $SequenceFindingIdExplicit -or
            $SequenceAnchorIndex -cnotmatch '^[1-9][0-9]{0,2}$' -or
            [int]$SequenceAnchorIndex -gt 480)) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SEQUENCE_ANCHOR_SELECTOR_INVALID'
        $Envelope.message = 'SequenceAnchorIndex requires an explicit literal path and a 1..480 index, and cannot be combined with original Finding selectors.'
        return 4
    }
    if ($Mode -ieq 'Sequence' -and $SequencePairIndexExplicit -and
        (-not $SequencePathExplicit -or $SequenceAnchorIndexExplicit -or
            $SequenceFindingRecordIdExplicit -or $SequenceFindingIdExplicit -or
            $SequencePairIndex -cnotmatch '^[1-9][0-9]?$' -or
            [int]$SequencePairIndex -gt 66)) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SEQUENCE_PAIR_SELECTOR_INVALID'
        $Envelope.message = 'SequencePairIndex requires an explicit literal path and one exclusive canonical 1..66 report pair index.'
        return 4
    }
    if ($Mode -ieq 'Sequence' -and $SequencePairOverviewIndexExplicit -and
        ($SequencePathExplicit -or $SequencePairIndexExplicit -or
            $SequenceAnchorIndexExplicit -or $SequenceFindingRecordIdExplicit -or
            $SequenceFindingIdExplicit -or
            $SequencePairOverviewIndex -cnotmatch '^[1-9][0-9]?$' -or
            [int]$SequencePairOverviewIndex -gt 66)) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SEQUENCE_PAIR_OVERVIEW_SELECTOR_INVALID'
        $Envelope.message = 'SequencePairOverviewIndex requires an exclusive canonical report-pair index 1..66 with no literal path or other focused selector.'
        return 4
    }
    if ($Mode -ine 'Sequence' -and (-not [string]::IsNullOrEmpty($SequenceRecordIds) -or
        $SequenceTop -ne $script:CodeShowSequenceDefaultTop -or $SequencePathExplicit -or
        $SequenceFindingRecordIdExplicit -or $SequenceFindingIdExplicit -or
        $SequenceAnchorIndexExplicit -or $SequencePairIndexExplicit -or
        $SequencePairOverviewIndexExplicit -or $SequencePairPathIndexExplicit -or
        $SequencePairPathAnchorIndexExplicit -or
        $SequencePairPathAnchorFindingSideExplicit -or
        $SequencePairPathAnchorFindingIndexExplicit -or
        $SequencePairPathAnchorFindingCounterpartIndexExplicit)) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SELECTORS_NOT_APPLICABLE'
        $Envelope.message = 'Sequence selectors belong only to Sequence mode.'
        return 4
    }
    if ($Mode -ieq 'Compare' -and ([string]::IsNullOrEmpty($LeftRecordId) -or
        [string]::IsNullOrEmpty($RightRecordId))) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_COMPARE_IDS_REQUIRED'
        $Envelope.message = 'Compare requires both -LeftRecordId and -RightRecordId, each a saved CES record ID.'
        return 4
    }
    if ($Mode -ieq 'Compare' -and (-not [string]::IsNullOrEmpty($RecordId) -or
        -not [string]::IsNullOrEmpty($AfterRecordId) -or $Limit -ne 50)) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SELECTORS_NOT_APPLICABLE'
        $Envelope.message = 'Compare accepts only two record IDs; no list or Finding selectors.'
        return 4
    }
    if ($Mode -ieq 'Trace' -and ([string]::IsNullOrEmpty($RecordId) -or
        [string]::IsNullOrEmpty($FindingId) -or
        -not [string]::IsNullOrEmpty($AfterRecordId) -or
        $Limit -lt 1 -or $Limit -gt $script:CodeShowMaxPageSize)) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_TRACE_SELECTORS_REQUIRED'
        $Envelope.message = 'Trace requires -RecordId and -FindingId plus either paging or 2..24 explicitly selected saved record IDs.'
        return 4
    }
    if ($Mode -ieq 'Trace' -and $TraceRecordIdsExplicit -and
        ($LimitExplicit -or -not [string]::IsNullOrEmpty($AfterTraceCursor))) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_TRACE_SELECTION_CONFLICT'
        $Envelope.message = 'Selected Trace records cannot use an explicit -Limit or -AfterTraceCursor.'
        return 4
    }
    if ($Mode -ieq 'Overview' -and ($Limit -lt 1 -or $Limit -gt $script:CodeShowMaxPageSize -or
        -not [string]::IsNullOrEmpty($RecordId) -or -not [string]::IsNullOrEmpty($AfterRecordId))) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SELECTORS_NOT_APPLICABLE'
        $Envelope.message = 'Overview supports a bounded page OR 2..24 explicitly selected saved records plus an optional exact saved-mode filter.'
        return 4
    }
    if ($Mode -ieq 'Overview' -and $OverviewRecordIdsExplicit -and
        ($LimitExplicit -or -not [string]::IsNullOrEmpty($AfterOverviewCursor))) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_OVERVIEW_SELECTION_CONFLICT'
        $Envelope.message = 'An explicit Overview selection cannot use a cursor or Limit.'
        return 4
    }
    if ($Mode -ieq 'Triage' -and ($Limit -lt 1 -or $Limit -gt $script:CodeShowMaxPageSize -or
        -not [string]::IsNullOrEmpty($RecordId) -or -not [string]::IsNullOrEmpty($AfterRecordId))) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SELECTORS_NOT_APPLICABLE'
        $Envelope.message = 'Triage supports a paginated scan OR 2..24 comma-separated explicit record IDs, plus Top and saved-mode filtering.'
        return 4
    }
    if ($Mode -ieq 'Recurrence' -and ($Limit -lt 1 -or $Limit -gt $script:CodeShowMaxPageSize -or
        -not [string]::IsNullOrEmpty($RecordId) -or -not [string]::IsNullOrEmpty($AfterRecordId))) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SELECTORS_NOT_APPLICABLE'
        $Envelope.message = 'Recurrence supports a paginated scan OR 2..24 comma-separated explicit record IDs, with -RecurrenceTop 1..30, -RecurrenceMinRecords 2..24 and exact saved-mode/path filters.'
        return 4
    }
    if ($Mode -ieq 'Recurrence' -and -not [string]::IsNullOrEmpty($RecurrenceRecordIds) -and
        (-not [string]::IsNullOrEmpty($AfterRecurrenceCursor) -or $Limit -ne 50)) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_RECURRENCE_SELECTION_CONFLICT'
        $Envelope.message = 'Explicit record selection scans its entire bounded set; it cannot use a cursor or a separate Limit.'
        return 4
    }
    if ($Mode -ieq 'Recurrence' -and ($RecurrenceTop -lt 1 -or $RecurrenceTop -gt $script:CodeShowRecurrenceMaxTop)) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_RECURRENCE_TOP_INVALID'
        $Envelope.message = 'RecurrenceTop must be an integer from 1 through 30.'
        return 4
    }
    if ($Mode -ieq 'Recurrence' -and ($RecurrenceMinRecords -lt 2 -or
        $RecurrenceMinRecords -gt $script:CodeShowRecurrenceMaxMinRecords)) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_RECURRENCE_MIN_INVALID'
        $Envelope.message = 'RecurrenceMinRecords must be an integer from 2 through 24.'
        return 4
    }
    if ($Mode -ine 'Recurrence' -and (-not [string]::IsNullOrEmpty($AfterRecurrenceCursor) -or
        -not [string]::IsNullOrEmpty($RecurrenceSourceMode) -or -not [string]::IsNullOrEmpty($RecurrencePath) -or
        $RecurrenceTop -ne $script:CodeShowRecurrenceDefaultTop -or
        $RecurrenceMinRecords -ne $script:CodeShowRecurrenceDefaultMinRecords -or
        -not [string]::IsNullOrEmpty($RecurrenceRecordIds))) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SELECTORS_NOT_APPLICABLE'
        $Envelope.message = 'Recurrence selectors belong only to Recurrence mode.'
        return 4
    }
    if ($Mode -ieq 'Recurrence' -and (
        (-not [string]::IsNullOrEmpty($RecurrenceSourceMode) -and
            $RecurrenceSourceMode -cnotin @('working_tree_diff','delivered_target_diff')) -or
        ([string]$RecurrencePath).Length -gt 4096 -or ([string]$RecurrencePath).Contains([char]0))) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_RECURRENCE_FILTER_INVALID'
        $Envelope.message = 'Recurrence filter requires an exact saved mode and a bounded, literal case-sensitive Git path.'
        return 4
    }
    if ($Mode -ieq 'Triage' -and $TriageRecordIdsExplicit -and
        ($LimitExplicit -or -not [string]::IsNullOrEmpty($AfterTriageCursor))) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_TRIAGE_SELECTION_CONFLICT'
        $Envelope.message = 'An explicit Triage record set cannot use -Limit or -AfterTriageCursor.'
        return 4
    }
    if ($Mode -ieq 'Triage' -and ($TriageTop -lt 1 -or $TriageTop -gt $script:CodeShowTriageMaxTop)) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_TRIAGE_TOP_INVALID'
        $Envelope.message = 'TriageTop must be an integer from 1 through 30.'
        return 4
    }
    if ($Mode -ine 'Triage' -and (-not [string]::IsNullOrEmpty($AfterTriageCursor) -or
        -not [string]::IsNullOrEmpty($TriageSourceMode) -or $TriageTop -ne $script:CodeShowTriageDefaultTop -or
        $TriageRecordIdsExplicit -or -not [string]::IsNullOrEmpty($TriageRecordIds))) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SELECTORS_NOT_APPLICABLE'
        $Envelope.message = 'Triage filter, Top, cursor and selected record IDs belong only to Triage mode.'
        return 4
    }
    if ($Mode -ieq 'Triage' -and -not [string]::IsNullOrEmpty($TriageSourceMode) -and
        $TriageSourceMode -cnotin @('working_tree_diff','delivered_target_diff')) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_TRIAGE_FILTER_INVALID'
        $Envelope.message = 'TriageSourceMode must be an exact lowercase saved source-mode enum.'
        return 4
    }
    if ($Mode -ine 'Overview' -and (-not [string]::IsNullOrEmpty($AfterOverviewCursor) -or
        -not [string]::IsNullOrEmpty($OverviewSourceMode) -or $OverviewRecordIdsExplicit -or
        -not [string]::IsNullOrEmpty($OverviewRecordIds))) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SELECTORS_NOT_APPLICABLE'
        $Envelope.message = 'Overview filters, cursor and selected IDs cannot be used outside Overview mode.'
        return 4
    }
    if ($Mode -ieq 'Overview' -and -not [string]::IsNullOrEmpty($OverviewSourceMode) -and
        $OverviewSourceMode -cnotin @('working_tree_diff','delivered_target_diff')) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_OVERVIEW_FILTER_INVALID'
        $Envelope.message = 'OverviewSourceMode must be an exact lowercase saved source-mode enum.'
        return 4
    }
    if ($Mode -ine 'Trace' -and (-not [string]::IsNullOrEmpty($FindingId) -or
        -not [string]::IsNullOrEmpty($AfterTraceCursor) -or $TraceRecordIdsExplicit -or
        -not [string]::IsNullOrEmpty($TraceRecordIds))) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SELECTORS_NOT_APPLICABLE'
        $Envelope.message = 'FindingId, AfterTraceCursor and TraceRecordIds belong only to Trace.'
        return 4
    }
    if ($Mode -ine 'Compare' -and (-not [string]::IsNullOrEmpty($LeftRecordId) -or
        -not [string]::IsNullOrEmpty($RightRecordId))) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SELECTORS_NOT_APPLICABLE'
        $Envelope.message = 'LeftRecordId and RightRecordId are exclusively for Compare mode.'
        return 4
    }
    if ($Mode -ine 'Findings' -and (-not [string]::IsNullOrEmpty($AfterFindingCursor) -or
        -not [string]::IsNullOrEmpty($FindingSeverity) -or -not [string]::IsNullOrEmpty($FindingLayer) -or
        -not [string]::IsNullOrEmpty($FindingPath) -or -not [string]::IsNullOrEmpty($FindingSourceMode) -or
        $FindingsRecordIdsExplicit -or -not [string]::IsNullOrEmpty($FindingsRecordIds))) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SELECTORS_NOT_APPLICABLE'
        $Envelope.message = 'Finding filters/cursor/selected IDs cannot be used outside Findings mode.'
        return 4
    }
    if ($Mode -ieq 'Findings' -and (
        (-not [string]::IsNullOrEmpty($FindingSeverity) -and $FindingSeverity -cnotin @('critical','high','medium','low','info')) -or
        (-not [string]::IsNullOrEmpty($FindingLayer) -and $FindingLayer -cnotin @('staged','unstaged','untracked','changes')) -or
        (-not [string]::IsNullOrEmpty($FindingSourceMode) -and $FindingSourceMode -cnotin @('working_tree_diff','delivered_target_diff')) -or
        ([string]$FindingPath).Length -gt 4096 -or ([string]$FindingPath).Contains([char]0))) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_FINDING_FILTER_INVALID'
        $Envelope.message = 'Finding filters must be exact lowercase enum values and a bounded literal path.'
        return 4
    }
    if ($Mode -ieq 'Trace' -and $FindingId -cnotmatch '^[A-Za-z][A-Za-z0-9_-]{0,31}$') {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_TRACE_FINDING_ID_INVALID'
        $Envelope.message = 'Trace FindingId must match the exact saved, case-sensitive Finding ID grammar.'
        return 4
    }
    $findingCursor = $null
    $findingsSelected = @()
    $traceCursor = $null
    $traceSelected = @()
    $overviewCursor = $null
    $overviewSelected = @()
    $triageCursor = $null
    $triageSelected = @()
    $recurrenceCursor = $null
    $recurrenceSelected = @()
    $sequenceSelected = @()
    try {
        if ($Mode -ieq 'Detail' -or $Mode -ieq 'Trace') { Assert-CodeShowRecordId -Id $RecordId }
        if ($Mode -ieq 'Compare') {
            Assert-CodeShowRecordId -Id $LeftRecordId
            Assert-CodeShowRecordId -Id $RightRecordId
        }
        if (-not [string]::IsNullOrEmpty($AfterRecordId)) { Assert-CodeShowRecordId -Id $AfterRecordId }
        if ($Mode -ieq 'Findings' -and -not $FindingsRecordIdsExplicit) {
            $findingCursor = Parse-CodeShowFindingCursor -Value $AfterFindingCursor
        }
    } catch {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = if ($Mode -ieq 'Findings') { 'CODE_SHOW_INVALID_FINDING_CURSOR' } else { 'CODE_SHOW_INVALID_RECORD_ID' }
        $Envelope.message = (Limit-Text $_.Exception.Message 240)
        return 4
    }

    if ($Mode -ieq 'Sequence') {
        try { $sequenceSelected = @(Parse-CodeShowSequenceRecordIds -Value $SequenceRecordIds) }
        catch {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SEQUENCE_RECORD_IDS_INVALID'
            $Envelope.message = (Limit-Text $_.Exception.Message 240)
            return 4
        }
    }
    if ($Mode -ieq 'Sequence' -and $SequenceFindingRecordIdExplicit -and
        -not ($sequenceSelected -ccontains $SequenceFindingRecordId)) {
        $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SEQUENCE_FINDING_RECORD_NOT_SELECTED'
        $Envelope.message = 'SequenceFindingRecordId must match exactly one already selected full saved record ID.'
        return 4
    }
    if ($Mode -ieq 'Findings' -and $FindingsRecordIdsExplicit) {
        try { $findingsSelected = @(Parse-CodeShowFindingsRecordIds -Value $FindingsRecordIds) }
        catch {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_FINDINGS_RECORD_IDS_INVALID'
            $Envelope.message = (Limit-Text $_.Exception.Message 240)
            return 4
        }
    }
    if ($Mode -ieq 'Overview' -and -not [string]::IsNullOrEmpty($AfterOverviewCursor)) {
        try { $overviewCursor = Parse-CodeShowOverviewCursor -Value $AfterOverviewCursor }
        catch {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_INVALID_OVERVIEW_CURSOR'
            $Envelope.message = (Limit-Text $_.Exception.Message 240)
            return 4
        }
    }
    if ($Mode -ieq 'Overview' -and $OverviewRecordIdsExplicit) {
        try { $overviewSelected = @(Parse-CodeShowOverviewRecordIds -Value $OverviewRecordIds) }
        catch {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_OVERVIEW_RECORD_IDS_INVALID'
            $Envelope.message = (Limit-Text $_.Exception.Message 240)
            return 4
        }
    }
    if ($Mode -ieq 'Triage' -and -not [string]::IsNullOrEmpty($AfterTriageCursor)) {
        try { $triageCursor = Parse-CodeShowTriageCursor -Value $AfterTriageCursor }
        catch {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_INVALID_TRIAGE_CURSOR'
            $Envelope.message = (Limit-Text $_.Exception.Message 240)
            return 4
        }
    }
    if ($Mode -ieq 'Triage' -and $TriageRecordIdsExplicit) {
        try { $triageSelected = @(Parse-CodeShowTriageRecordIds -Value $TriageRecordIds) }
        catch {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_TRIAGE_RECORD_IDS_INVALID'
            $Envelope.message = (Limit-Text $_.Exception.Message 240)
            return 4
        }
    }
    if ($Mode -ieq 'Recurrence' -and -not [string]::IsNullOrEmpty($AfterRecurrenceCursor)) {
        try { $recurrenceCursor = Parse-CodeShowRecurrenceCursor -Value $AfterRecurrenceCursor }
        catch {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_INVALID_RECURRENCE_CURSOR'
            $Envelope.message = (Limit-Text $_.Exception.Message 240)
            return 4
        }
    }
    if ($Mode -ieq 'Recurrence' -and -not [string]::IsNullOrEmpty($RecurrenceRecordIds)) {
        try { $recurrenceSelected = @(Parse-CodeShowRecurrenceRecordIds -Value $RecurrenceRecordIds) }
        catch {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_RECURRENCE_RECORD_IDS_INVALID'
            $Envelope.message = (Limit-Text $_.Exception.Message 240)
            return 4
        }
    }
    if ($Mode -ieq 'Trace') {
        try { $traceCursor = Parse-CodeShowTraceCursor -Value $AfterTraceCursor }
        catch {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_INVALID_TRACE_CURSOR'
            $Envelope.message = (Limit-Text $_.Exception.Message 240)
            return 4
        }
        if ($TraceRecordIdsExplicit) {
            try { $traceSelected = @(Parse-CodeShowTraceRecordIds -Value $TraceRecordIds) }
            catch {
                $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_TRACE_RECORD_IDS_INVALID'
                $Envelope.message = (Limit-Text $_.Exception.Message 240)
                return 4
            }
            if (-not ($traceSelected -ccontains $RecordId)) {
                $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_TRACE_SELECTION_SEED_REQUIRED'
                $Envelope.message = 'TraceRecordIds must include the exact seed RecordId so only selected bodies are opened.'
                return 4
            }
        }
    }

    $inspected = New-Envelope -ActionName 'Inspect'
    $inspectionExit = Inspect-Repository -Envelope $inspected -InputPath $RepoPath -GitExecutable $GitExecutable
    $Envelope.coverage = $inspected.coverage
    $Envelope.evidence = $inspected.evidence
    $Envelope.warnings = $inspected.warnings
    if ($inspectionExit -ne 0 -or $null -eq $inspected.data -or
        $inspected.data.stable_root_verified -ne $true -or
        $inspected.data.worktree_kind -cne 'main' -or
        $inspected.data.head.sha -notmatch '^[0-9a-f]{40,64}$') {
        $Envelope.status = 'partial'; $Envelope.reason_code = 'CODE_SHOW_MAIN_WORKTREE_REQUIRED'
        $Envelope.message = 'Records may be inspected only from a verified main Git worktree with a real HEAD commit.'
        $Envelope.data = [ordered]@{ read_only = $true; source_root = if ($inspected.data) { $inspected.data.source_root } else { $null } }
        return 2
    }
    $root = [string]$inspected.data.stable_project_root
    $filterHash = $null
    $overviewQueryHash = $null
    $triageQueryHash = $null
    $recurrenceQueryHash = $null
    if ($Mode -ieq 'Recurrence' -and $recurrenceSelected.Count -eq 0) {
        $recurrenceQueryHash = Get-CodeShowRecurrenceQueryHash -VerifiedRoot $root `
            -SourceMode $RecurrenceSourceMode -Path $RecurrencePath `
            -MinRecords $RecurrenceMinRecords -Top $RecurrenceTop
        if ($null -ne $recurrenceCursor -and $recurrenceCursor.query_sha256 -cne $recurrenceQueryHash) {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_RECURRENCE_CURSOR_MISMATCH'
            $Envelope.message = 'Recurrence cursor belongs to another main root, filter, MinRecords or Top setting.'
            return 4
        }
    }
    if ($Mode -ieq 'Triage' -and $triageSelected.Count -eq 0) {
        $triageQueryHash = Get-CodeShowTriageQueryHash -VerifiedRoot $root -SourceMode $TriageSourceMode -Top $TriageTop
        if ($null -ne $triageCursor -and $triageCursor.query_sha256 -cne $triageQueryHash) {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_TRIAGE_CURSOR_MISMATCH'
            $Envelope.message = 'Triage cursor belongs to another main root, filter or Top setting.'
            return 4
        }
    }
    if ($Mode -ieq 'Overview' -and $overviewSelected.Count -eq 0) {
        $overviewQueryHash = Get-CodeShowOverviewQueryHash -VerifiedRoot $root -SourceMode $OverviewSourceMode
        if ($null -ne $overviewCursor -and $overviewCursor.query_sha256 -cne $overviewQueryHash) {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_OVERVIEW_CURSOR_MISMATCH'
            $Envelope.message = 'Overview cursor belongs to another main root or source-mode filter.'
            return 4
        }
    }
    if ($Mode -ieq 'Findings') {
        $filterHash = Get-CodeShowFindingFilterHash -VerifiedRoot $root -Severity $FindingSeverity -Layer $FindingLayer -Path $FindingPath -SourceMode $FindingSourceMode
        if ($null -ne $findingCursor -and $findingCursor.filter_sha256 -cne $filterHash) {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_FINDING_CURSOR_MISMATCH'
            $Envelope.message = 'Finding cursor belongs to a different repository root or filter tuple; start a new query.'
            return 4
        }
    }
    try {
        $store = Get-CodeShowStore -RepoRoot $root -GitExecutable $GitExecutable
        $Envelope.coverage.code_store_checked = $true
        if (-not $store.exists) {
            if ($Mode -ieq 'Detail' -or $Mode -ieq 'Compare' -or $Mode -ieq 'Trace' -or $Mode -ieq 'Sequence') {
                $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_NOT_FOUND'
                $Envelope.message = 'No CES-owned local records exist at this verified root.'
                return 4
            }
            $Envelope.status = 'success'; $Envelope.reason_code = 'CODE_SHOW_EMPTY'
            $Envelope.message = 'No CES-owned local store exists. CodeShow did not create one.'
            if ($Mode -ieq 'Recurrence') {
                if ($recurrenceSelected.Count -gt 0) {
                    $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_NOT_FOUND'
                    $Envelope.message = 'Selected saved record IDs do not exist; the CES store is absent.'
                    return 4
                }
                if ($null -ne $recurrenceCursor) {
                    $Envelope.status = 'partial'; $Envelope.reason_code = 'CODE_SHOW_CURSOR_STALE'
                    $Envelope.message = 'The CES store vanished since the earlier Recurrence page.'
                    return 2
                }
                $Envelope.data = New-CodeShowRecurrenceResult -VerifiedRoot $root -Limit $Limit `
                    -Top $RecurrenceTop -MinRecords $RecurrenceMinRecords `
                    -SourceMode $RecurrenceSourceMode -Path $RecurrencePath `
                    -RecordCount 0 -ScannedCount 0 -IncludedCount 0 -RecordsWithFindings 0 `
                    -FindingCount 0 -DistinctAnchors 0 -EligibleAnchors 0 -Anchors @() `
                    -Cursor $null -NextCursor $null -WindowExhausted $false -HasMoreCandidates $false
            } elseif ($Mode -ieq 'Triage') {
                if ($triageSelected.Count -gt 0) {
                    $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_NOT_FOUND'
                    $Envelope.message = 'Selected Triage record IDs cannot exist because the CES store is absent.'
                    return 4
                }
                if ($null -ne $triageCursor) {
                    $Envelope.status = 'partial'; $Envelope.reason_code = 'CODE_SHOW_CURSOR_STALE'
                    $Envelope.message = 'The CES store vanished since the earlier Triage page.'
                    return 2
                }
                $Envelope.data = New-CodeShowTriageResult -VerifiedRoot $root -Limit $Limit -Top $TriageTop `
                    -SourceMode $TriageSourceMode -RecordCount 0 -ScannedCount 0 `
                    -IncludedCount 0 -RecordsWithFindings 0 -FindingCount 0 -TotalGroups 0 `
                    -PathGroups @() -Cursor $null -NextCursor $null -WindowExhausted $false -HasMoreCandidates $false
            } elseif ($Mode -ieq 'Overview') {
                if ($overviewSelected.Count -gt 0) {
                    $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_NOT_FOUND'
                    $Envelope.message = 'Selected Overview records cannot exist because the CES store is absent.'
                    return 4
                }
                if ($null -ne $overviewCursor) {
                    $Envelope.status = 'partial'; $Envelope.reason_code = 'CODE_SHOW_CURSOR_STALE'
                    $Envelope.message = 'The CES store vanished since the earlier Overview page.'
                    return 2
                }
                $Envelope.data = New-CodeShowOverviewResult -VerifiedRoot $root -Limit $Limit `
                    -SourceMode $OverviewSourceMode -RecordCount 0 -ScannedCount 0 `
                    -IncludedCount 0 -RecordsWithFindings 0 -FindingCount 0 `
                    -Counts (New-CodeShowOverviewCounts) -Cursor $null -NextCursor $null `
                    -WindowExhausted $false -HasMoreCandidates $false
            } elseif ($Mode -ieq 'Findings') {
                if ($findingsSelected.Count -gt 0) {
                    $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_NOT_FOUND'
                    $Envelope.message = 'Selected Findings record IDs cannot exist because the CES store is absent.'
                    $Envelope.data = $null
                    return 4
                }
                if ($null -ne $findingCursor) {
                    $Envelope.status = 'partial'; $Envelope.reason_code = 'CODE_SHOW_CURSOR_STALE'
                    $Envelope.message = 'The CES store vanished since the earlier Findings page.'
                    return 2
                }
                $Envelope.data = [ordered]@{
                    source_root = $root; mode = 'Findings'; selection_scope = 'scan_window'
                    selected_record_ids = $null; selected_record_count = $null
                    counts_scope = 'only_the_current_scan_page_not_the_whole_store'
                    matched_finding_count = $null; omitted_matching_count = $null; results_truncated = $null
                    findings = @(); returned_count = 0
                    record_count = 0; scanned_record_count = 0; scanned_finding_count = 0
                    scan_window_records = $script:CodeShowFindingWindowRecords; scan_window_exhausted = $false
                    limit = $Limit; filters = [ordered]@{
                        severity = if ([string]::IsNullOrEmpty($FindingSeverity)) { $null } else { $FindingSeverity }
                        layer = if ([string]::IsNullOrEmpty($FindingLayer)) { $null } else { $FindingLayer }
                        path_exact = if ([string]::IsNullOrEmpty($FindingPath)) { $null } else { $FindingPath }
                        source_mode = if ([string]::IsNullOrEmpty($FindingSourceMode)) { $null } else { $FindingSourceMode }
                    }
                    after_finding_cursor = $null; next_after_finding_cursor = $null
                    has_more_candidates = $false; record_integrity_verified = $true
                    record_authorship_authenticated = $false; source_revalidated = $false
                    finding_semantics_verified = $false; snapshot_atomic = $false
                }
            } else {
                $Envelope.data = [ordered]@{
                    source_root = $root; mode = 'List'; records = @(); record_count = 0
                    returned_count = 0; limit = $Limit; after_record_id = $AfterRecordId
                    next_after_record_id = $null; has_more = $false
                    record_integrity_verified = $true; record_authorship_authenticated = $false
                    source_revalidated = $false; snapshot_atomic = $false
                }
            }
            return 0
        }
    } catch {
        $Envelope.status = 'unavailable'; $Envelope.reason_code = 'CODE_SHOW_STORE_UNSAFE_OR_UNAVAILABLE'
        $Envelope.message = 'CES storage ownership, tracked Git boundary or local path safety could not be verified.'
        $Envelope.warnings = @((Limit-Text (Redact-CesKnownPaths -Message $_.Exception.Message -SensitivePaths @($root, $RepoPath)) 320))
        return 5
    }

    try {
        if ($Mode -ieq 'Sequence') {
            $Envelope.data = Get-CodeShowSequence -Directory $store.directory -VerifiedRoot $root `
                -RecordIds $sequenceSelected -Top $SequenceTop -Path $(if ($SequencePathExplicit) { $SequencePath } else { $null }) `
                -FindingRecordId $(if ($SequenceFindingRecordIdExplicit) { $SequenceFindingRecordId } else { $null }) `
                -FindingId $(if ($SequenceFindingIdExplicit) { $SequenceFindingId } else { $null }) `
                -AnchorIndex $(if ($SequenceAnchorIndexExplicit) { $SequenceAnchorIndex } else { $null }) `
                -PairIndex $(if ($SequencePairIndexExplicit) { $SequencePairIndex } else { $null }) `
                -PairOverviewIndex $(if ($SequencePairOverviewIndexExplicit) { $SequencePairOverviewIndex } else { $null }) `
                -PairPathIndex $(if ($SequencePairPathIndexExplicit) { $SequencePairPathIndex } else { $null }) `
                -PairPathAnchorIndex $(if ($SequencePairPathAnchorIndexExplicit) { $SequencePairPathAnchorIndex } else { $null }) `
                -PairPathAnchorFindingSide $(if ($SequencePairPathAnchorFindingSideExplicit) { $SequencePairPathAnchorFindingSide } else { $null }) `
                -PairPathAnchorFindingIndex $(if ($SequencePairPathAnchorFindingIndexExplicit) { $SequencePairPathAnchorFindingIndex } else { $null }) `
                -PairPathAnchorFindingCounterpartIndex $(if ($SequencePairPathAnchorFindingCounterpartIndexExplicit) { $SequencePairPathAnchorFindingCounterpartIndex } else { $null })
        } elseif ($Mode -ieq 'Recurrence') {
            $Envelope.data = Get-CodeShowRecurrencePage -Directory $store.directory -VerifiedRoot $root `
                -Limit $Limit -Top $RecurrenceTop -MinRecords $RecurrenceMinRecords `
                -SourceMode $RecurrenceSourceMode -Path $RecurrencePath `
                -Cursor $recurrenceCursor -QueryHash $recurrenceQueryHash `
                -SelectedRecordIds $recurrenceSelected
        } elseif ($Mode -ieq 'Triage') {
            $Envelope.data = Get-CodeShowTriagePage -Directory $store.directory -VerifiedRoot $root `
                -Limit $Limit -Top $TriageTop -SourceMode $TriageSourceMode `
                -Cursor $triageCursor -QueryHash $triageQueryHash -SelectedRecordIds $triageSelected
        } elseif ($Mode -ieq 'Overview') {
            $Envelope.data = Get-CodeShowOverviewPage -Directory $store.directory -VerifiedRoot $root `
                -Limit $Limit -SourceMode $OverviewSourceMode -Cursor $overviewCursor `
                -QueryHash $overviewQueryHash -SelectedRecordIds $overviewSelected
        } elseif ($Mode -ieq 'Trace') {
            $Envelope.data = Get-CodeShowTracePage -Directory $store.directory -VerifiedRoot $root `
                -SeedRecordId $RecordId -SeedFindingId $FindingId -Limit $Limit `
                -Cursor $traceCursor -SelectedRecordIds $traceSelected
        } elseif ($Mode -ieq 'Compare') {
            $Envelope.data = Get-CodeShowCompare -Directory $store.directory -VerifiedRoot $root -LeftRecordId $LeftRecordId -RightRecordId $RightRecordId
        } elseif ($Mode -ieq 'Findings') {
            $Envelope.data = Get-CodeShowFindingsPage -Directory $store.directory -VerifiedRoot $root `
                -Limit $Limit -Cursor $findingCursor -FilterHash $filterHash `
                -Severity $FindingSeverity -Layer $FindingLayer -Path $FindingPath `
                -SourceMode $FindingSourceMode -SelectedRecordIds $findingsSelected
        } elseif ($Mode -ieq 'Detail') {
            $recordPath = Join-Path $store.directory ($RecordId + '.json')
            if ($null -eq (Get-CodeShowOptionalItem -Path $recordPath)) {
                $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_NOT_FOUND'
                $Envelope.message = 'Requested record ID does not exist in this local CES store.'
                return 4
            }
            $selected = Read-CodeShowRecord -Directory $store.directory -Id $RecordId -VerifiedRoot $root
            $Envelope.data = [ordered]@{
                source_root = $root; mode = 'Detail'
                record_id = $selected.id; record_sha256 = $selected.sha256; record_path = $selected.path
                record_integrity_verified = $true; record_authorship_authenticated = $false
                source_revalidated = $false; snapshot_atomic = $false
                record = $selected.record
            }
        } else {
            $allIds = @(Get-CodeShowRecordIds -Directory $store.directory)
            $entries = [System.Collections.Generic.List[object]]::new()
            $lastId = $null
            $hasMore = $false
            foreach ($id in $allIds) {
                if (-not [string]::IsNullOrEmpty($AfterRecordId) -and
                    [string]::Compare($id, $AfterRecordId, [System.StringComparison]::Ordinal) -le 0) { continue }
                if ($entries.Count -ge $Limit) { $hasMore = $true; break }
                $selected = Read-CodeShowRecord -Directory $store.directory -Id $id -VerifiedRoot $root
                $text = [string]$selected.record.summary
                # List is metadata-first; full findings are released only by Detail.
                if ($text.Length -gt 180) { $text = $text.Substring(0, 180) + '…' }
                $entries.Add([ordered]@{
                    record_id = $selected.id
                    record_sha256 = $selected.sha256
                    source_mode = $selected.record.source_mode
                    finding_count = $selected.record.finding_count
                    summary_preview = $text
                    saved_collect_sha256 = $selected.record.saved_collect_sha256
                    packet_sha256 = $selected.record.packet_sha256
                })
                $lastId = $id
            }
            $afterIds = @(Get-CodeShowRecordIds -Directory $store.directory)
            if (($allIds -join '|') -cne ($afterIds -join '|')) {
                throw 'CES record directory membership changed during enumeration.'
            }
            $Envelope.data = [ordered]@{
                source_root = $root; mode = 'List'; records = $entries.ToArray()
                record_count = $allIds.Count; returned_count = $entries.Count
                limit = $Limit; after_record_id = $AfterRecordId
                next_after_record_id = if ($hasMore) { $lastId } else { $null }
                has_more = $hasMore
                record_integrity_verified = $true; record_authorship_authenticated = $false
                source_revalidated = $false; snapshot_atomic = $false
            }
        }
        # Defensive late path/owner recheck. No file creation, cleanup or Git
        # mutation is performed by the Show action under any circumstance.
        [void](Test-CodeSaveRegularItem -Path (Join-Path $root '.codex') -Directory $true)
        [void](Test-CodeSaveRegularItem -Path (Join-Path (Join-Path $root '.codex') 'ces') -Directory $true)
        [void](Test-CodeSaveRegularItem -Path $store.directory -Directory $true)
        Assert-CodeShowOwnerMarker -Path $store.owner
    } catch {
        if ($Mode -ieq 'Sequence' -and $_.Exception.Message.StartsWith('CODE_SHOW_SEQUENCE_RECORD_NOT_FOUND:', [System.StringComparison]::Ordinal)) {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_NOT_FOUND'
            $Envelope.message = 'At least one selected Sequence saved record is missing from the verified store inventory.'
            $Envelope.data = $null
            return 4
        }
        if ($Mode -ieq 'Sequence' -and $_.Exception.Message.StartsWith('CODE_SHOW_SEQUENCE_SCOPE_MISMATCH:', [System.StringComparison]::Ordinal)) {
            $Envelope.status = 'partial'; $Envelope.reason_code = 'CODE_SHOW_SEQUENCE_SCOPE_MISMATCH'
            $Envelope.message = 'Selected record source modes differ; no adjacent evidence-anchor absence comparison is valid.'
            $Envelope.data = $null
            return 2
        }
        if ($Mode -ieq 'Sequence' -and $_.Exception.Message.StartsWith('CODE_SHOW_SEQUENCE_PAIR_PATH_ANCHOR_FINDING_COUNTERPART_NOT_FOUND:', [System.StringComparison]::Ordinal)) {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SEQUENCE_PAIR_PATH_ANCHOR_FINDING_COUNTERPART_NOT_FOUND'
            $Envelope.message = 'No original record-scoped Finding exists at that one-based index in the opposite saved report endpoint for the selected pair/path/anchor.'
            $Envelope.data = $null
            return 4
        }
        if ($Mode -ieq 'Sequence' -and $_.Exception.Message.StartsWith('CODE_SHOW_SEQUENCE_PAIR_PATH_ANCHOR_FINDING_NOT_FOUND:', [System.StringComparison]::Ordinal)) {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SEQUENCE_PAIR_PATH_ANCHOR_FINDING_NOT_FOUND'
            $Envelope.message = 'No original record-scoped Finding has that one-based ordinal index at the selected pair/path/anchor endpoint.'
            $Envelope.data = $null
            return 4
        }
        if ($Mode -ieq 'Sequence' -and $_.Exception.Message.StartsWith('CODE_SHOW_SEQUENCE_PAIR_PATH_ANCHOR_NOT_FOUND:', [System.StringComparison]::Ordinal)) {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SEQUENCE_PAIR_PATH_ANCHOR_NOT_FOUND'
            $Envelope.message = 'No exact saved quote anchor has that one-based index at the selected indexed report-pair path.'
            $Envelope.data = $null
            return 4
        }
        if ($Mode -ieq 'Sequence' -and $_.Exception.Message.StartsWith('CODE_SHOW_SEQUENCE_PAIR_PATH_NOT_FOUND:', [System.StringComparison]::Ordinal)) {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SEQUENCE_PAIR_PATH_NOT_FOUND'
            $Envelope.message = 'No saved path has that one-based ordinal index in the selected report-pair overview.'
            $Envelope.data = $null
            return 4
        }
        if ($Mode -ieq 'Sequence' -and $_.Exception.Message.StartsWith('CODE_SHOW_SEQUENCE_PAIR_NOT_FOUND:', [System.StringComparison]::Ordinal)) {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SEQUENCE_PAIR_NOT_FOUND'
            $Envelope.message = 'No report pair has that canonical index in the selected caller-ordered saved records.'
            $Envelope.data = $null
            return 4
        }
        if ($Mode -ieq 'Sequence' -and $_.Exception.Message.StartsWith('CODE_SHOW_SEQUENCE_ANCHOR_NOT_FOUND:', [System.StringComparison]::Ordinal)) {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SEQUENCE_ANCHOR_NOT_FOUND'
            $Envelope.message = 'No canonical saved quote anchor has that one-based index at the exact selected path and record set.'
            $Envelope.data = $null
            return 4
        }
        if ($Mode -ieq 'Sequence' -and $_.Exception.Message.StartsWith('CODE_SHOW_SEQUENCE_FINDING_NOT_FOUND:', [System.StringComparison]::Ordinal)) {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_SEQUENCE_FINDING_NOT_FOUND'
            $Envelope.message = 'The requested original Finding ID is absent from that selected saved record at the explicitly chosen literal path.'
            $Envelope.data = $null
            return 4
        }
        if ($Mode -ieq 'Findings' -and $_.Exception.Message.StartsWith('CODE_SHOW_FINDINGS_RECORD_NOT_FOUND:', [System.StringComparison]::Ordinal)) {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_NOT_FOUND'
            $Envelope.message = 'At least one explicitly selected Findings record is missing from the verified inventory.'
            $Envelope.data = $null
            return 4
        }
        if ($Mode -ieq 'Overview' -and $_.Exception.Message.StartsWith('CODE_SHOW_OVERVIEW_RECORD_NOT_FOUND:', [System.StringComparison]::Ordinal)) {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_NOT_FOUND'
            $Envelope.message = 'At least one selected Overview record ID is missing from the verified CES store.'
            $Envelope.data = $null
            return 4
        }
        if ($Mode -ieq 'Triage' -and $_.Exception.Message.StartsWith('CODE_SHOW_TRIAGE_RECORD_NOT_FOUND:', [System.StringComparison]::Ordinal)) {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_NOT_FOUND'
            $Envelope.message = 'At least one selected Triage saved record ID is missing from the verified CES store.'
            $Envelope.data = $null
            return 4
        }
        if ($Mode -ieq 'Recurrence' -and $_.Exception.Message.StartsWith('CODE_SHOW_RECURRENCE_RECORD_NOT_FOUND:', [System.StringComparison]::Ordinal)) {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_NOT_FOUND'
            $Envelope.message = 'At least one selected saved record ID is missing from the verified CES store.'
            $Envelope.data = $null
            return 4
        }
        if ($Mode -ieq 'Trace' -and $_.Exception.Message.StartsWith('CODE_SHOW_TRACE_RECORD_NOT_FOUND:', [System.StringComparison]::Ordinal)) {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_NOT_FOUND'
            $Envelope.message = 'At least one selected Trace record is missing from the verified CES store.'
            $Envelope.data = $null
            return 4
        }
        if ($Mode -ieq 'Trace' -and $_.Exception.Message.StartsWith('CODE_SHOW_TRACE_SEED_NOT_FOUND:', [System.StringComparison]::Ordinal)) {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_NOT_FOUND'
            $Envelope.message = 'The selected CES Trace seed record is missing.'
            $Envelope.data = $null
            return 4
        }
        if ($Mode -ieq 'Trace' -and $_.Exception.Message.StartsWith('CODE_SHOW_TRACE_FINDING_NOT_FOUND:', [System.StringComparison]::Ordinal)) {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_TRACE_FINDING_NOT_FOUND'
            $Envelope.message = 'The requested exact FindingId is absent from the selected saved record.'
            $Envelope.data = $null
            return 4
        }
        if ($Mode -ieq 'Trace' -and $_.Exception.Message.StartsWith('CODE_SHOW_TRACE_CURSOR_MISMATCH:', [System.StringComparison]::Ordinal)) {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_TRACE_CURSOR_MISMATCH'
            $Envelope.message = 'Trace cursor does not match the current repository and seed Finding anchor.'
            $Envelope.data = $null
            return 4
        }
        if ($Mode -ieq 'Compare' -and $_.Exception.Message.StartsWith('CODE_SHOW_COMPARE_NOT_FOUND:', [System.StringComparison]::Ordinal)) {
            $Envelope.status = 'invalid_input'; $Envelope.reason_code = 'CODE_SHOW_NOT_FOUND'
            $Envelope.message = 'At least one selected CES record does not exist in the verified store.'
            $Envelope.data = $null
            return 4
        }
        $Envelope.status = 'partial'
        $Envelope.reason_code = if ($_.Exception.Message.StartsWith('CODE_SHOW_SCAN_LIMIT:', [System.StringComparison]::Ordinal)) {
            'CODE_SHOW_SCAN_LIMIT'
        } elseif ($_.Exception.Message.StartsWith('CODE_SHOW_CURSOR_STALE:', [System.StringComparison]::Ordinal)) {
            'CODE_SHOW_CURSOR_STALE'
        } else { 'CODE_SHOW_RECORD_INVALID_OR_CHANGED' }
        $Envelope.message = 'A stored record, directory sample or inventory bound could not be verified; no record contents were accepted.'
        $Envelope.data = $null
        $Envelope.warnings = @((Limit-Text $_.Exception.Message 320))
        return 2
    }
    $Envelope.coverage.code_records_integrity_checked = $true
    if ($Mode -ieq 'Compare' -and -not $Envelope.data.comparable) {
        $Envelope.status = 'partial'; $Envelope.reason_code = 'CODE_SHOW_COMPARE_SCOPE_MISMATCH'
        $Envelope.message = 'Both records passed local integrity checks, but their source modes differ; no Finding absence/overlap comparison was performed.'
        return 2
    }
    $Envelope.status = 'success'
    $Envelope.reason_code = if (($Mode -ieq 'List' -or $Mode -ieq 'Findings' -or $Mode -ieq 'Overview' -or $Mode -ieq 'Triage' -or $Mode -ieq 'Recurrence') -and $Envelope.data.record_count -eq 0) { 'CODE_SHOW_EMPTY' } elseif (($Mode -ieq 'Findings' -and $Envelope.data.returned_count -eq 0) -or ($Mode -ieq 'Trace' -and $Envelope.data.returned_record_count -eq 0) -or ($Mode -ieq 'Overview' -and $Envelope.data.included_record_count -eq 0) -or ($Mode -ieq 'Triage' -and $Envelope.data.returned_group_count -eq 0) -or ($Mode -ieq 'Recurrence' -and $Envelope.data.returned_anchor_count -eq 0)) { 'CODE_SHOW_NO_MATCHES' } else { 'CODE_SHOW_OK' }
    $Envelope.message = if ($Envelope.reason_code -eq 'CODE_SHOW_EMPTY') {
        'The CES local store contains no records; no files were created.'
    } elseif ($Mode -ieq 'List') {
        'Bounded local records listed with individual digest/schema checks for returned entries; no authorship or source freshness proof.'
    } elseif ($Mode -ieq 'Findings') {
        if ($findingsSelected.Count -gt 0) {
            'Only the explicitly selected historical records were fully checked; matching count includes omitted output rows, and no unselected records or current source were validated.'
        } else {
            'Bounded saved Finding scan completed for this page; has_more_candidates indicates unscanned candidates, not guaranteed matching findings.'
        }
    } elseif ($Mode -ieq 'Overview') {
        if ($overviewSelected.Count -gt 0) {
            'Historical saved-report counters cover only the explicitly selected verified records across their SHA pages, not the full inventory, fresh source or verified defects.'
        } else {
            'Verified saved-report counters cover only this bounded scan page, not the full inventory or verified defects.'
        }
    } elseif ($Mode -ieq 'Recurrence') {
        if ($recurrenceSelected.Count -gt 0) {
            'Repeated exact anchors across the explicitly selected verified records are historical model reports; selection spans SHA pages but does not verify all other records or prove defects, resolution or chronology.'
        } else {
            'Repeated exact quotation anchors in this bounded saved-record page are historical model reports, not issue identity, confirmed defects, fix state or chronology.'
        }
    } elseif ($Mode -ieq 'Triage') {
        if ($triageSelected.Count -gt 0) {
            'Historical saved-report Git paths were ranked across only the explicitly selected verified records, including different SHA pages; unselected records, present risk and chronology were not verified.'
        } else {
            'Verified historical saved-report Git paths were ranked only within this bounded record window; no present risk or store-wide priority is asserted.'
        }
    } elseif ($Mode -ieq 'Sequence') {
        'Selected historical records were checked in caller-provided order, and adjacent exact anchors compared. Neither order nor an absent report proves dates, issue state, fixed defects or present risks.'
    } elseif ($Mode -ieq 'Compare') {
        'Two saved Finding sets compared by exact quotation anchors; no fix, identity, time order or semantic equivalence is asserted.'
    } elseif ($Mode -ieq 'Trace') {
        if ($traceSelected.Count -gt 0) {
            'Historical exact-anchor occurrences are checked only in the explicitly selected saved records across SHA windows; unselected bodies and live source were not read.'
        } else {
            'Bounded historical exact-anchor trace completed; saved ID ordering is not chronology, and unvisited candidates may still match.'
        }
    } else {
        'Stored record SHA-256 and schema verified; source freshness, model authenticity and finding semantics were not checked.'
    }
    return 0
}
