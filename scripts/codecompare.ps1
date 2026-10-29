#requires -Version 7.0
<#
    EC-011: Compare two explicitly selected, integrity-checked local saved
    CodeInsight records by EXACT quoted-evidence anchor membership.

    This is a comparison of historical MODEL-REPORTED findings, not a source
    diff, issue lifecycle, fix confirmation, semantic deduplication, or an
    authenticated finding. No Git content, evidence quote or patch is opened.
    Multiple findings sharing one anchor are preserved as separate statements.
#>

function Get-CodeCompareAnchorKey {
    param([System.Collections.IDictionary] $Anchor)

    # The original path is untrusted Unicode and may contain delimiter-like
    # characters. Length prefixes make every field boundary unambiguous.
    $builder = [System.Text.StringBuilder]::new()
    foreach ($name in @('source_mode','layer','path','path_endpoint','quote_sha256','quote_presence')) {
        $value = [string]$Anchor[$name]
        [void]$builder.Append($value.Length)
        [void]$builder.Append(':')
        [void]$builder.Append($value)
    }
    return $builder.ToString()
}

function Get-CodeCompareGroups {
    param([System.Collections.IDictionary] $Record)

    $groups = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::Ordinal)
    foreach ($finding in $Record.checked_findings) {
        $anchor = [ordered]@{
            source_mode = [string]$Record.source_mode
            layer = [string]$finding.layer
            path = [string]$finding.path
            path_endpoint = [string]$finding.path_endpoint
            quote_sha256 = [string]$finding.quote_sha256
            quote_presence = [string]$finding.quote_presence
        }
        $key = Get-CodeCompareAnchorKey -Anchor $anchor
        if (-not $groups.ContainsKey($key)) {
            $groups.Add($key, [pscustomobject]@{
                anchor = $anchor
                # Finding IDs are unique (case-insensitively) within each
                # already-validated record; ordinal order is still explicit.
                findings = [System.Collections.Generic.SortedDictionary[string,object]]::new([System.StringComparer]::Ordinal)
            })
        }
        # Show how the model's interpretation changed on the SAME anchor,
        # without inventing an identity relationship between finding IDs.
        # Include no raw evidence quote, patch, file body or source reread.
        $groups[$key].findings.Add([string]$finding.id, [ordered]@{
            id = $finding.id
            title = $finding.title
            severity = $finding.severity
            confidence = $finding.confidence
            line_start_claimed = $finding.line_start_claimed
            line_end_claimed = $finding.line_end_claimed
            line_numbers_verified = $false
            reasoning = $finding.reasoning
            impact = $finding.impact
            recommendation = $finding.recommendation
        })
    }
    return ,$groups
}

function Get-CodeCompareFindingArray {
    param([AllowNull()][object] $Group)
    $results = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $Group) {
        foreach ($id in $Group.findings.Keys) { $results.Add($Group.findings[$id]) }
    }
    return ,($results.ToArray())
}

function Get-CodeCompareRecordSummary {
    param([pscustomobject] $Checked, [AllowNull()][object] $AnchorCount)
    return [ordered]@{
        record_id = $Checked.id
        record_sha256 = $Checked.sha256
        source_mode = $Checked.record.source_mode
        saved_collect_sha256 = $Checked.record.saved_collect_sha256
        packet_sha256 = $Checked.record.packet_sha256
        finding_count = $Checked.record.finding_count
        anchor_count = $AnchorCount
    }
}

function Get-CodeShowCompare {
    param(
        [string] $Directory,
        [string] $VerifiedRoot,
        [string] $LeftRecordId,
        [string] $RightRecordId
    )

    # Full bounded filename inventory detects unknown entries and makes absent
    # user-requested IDs an explicit not-found result, not a partial match.
    # Only the two selected record bodies (up to 40 findings each) are read.
    $beforeIds = @(Get-CodeShowRecordIds -Directory $Directory)
    if (-not ($beforeIds -ccontains $LeftRecordId) -or -not ($beforeIds -ccontains $RightRecordId)) {
        throw 'CODE_SHOW_COMPARE_NOT_FOUND: at least one selected saved record is absent.'
    }
    $left = Read-CodeShowRecord -Directory $Directory -Id $LeftRecordId -VerifiedRoot $VerifiedRoot
    $right = if ($LeftRecordId -ceq $RightRecordId) { $left } else {
        Read-CodeShowRecord -Directory $Directory -Id $RightRecordId -VerifiedRoot $VerifiedRoot
    }
    $afterIds = @(Get-CodeShowRecordIds -Directory $Directory)
    if (($beforeIds -join '|') -cne ($afterIds -join '|')) {
        throw 'CES record directory membership changed during Compare.'
    }

    # Both selected records have already passed full CodeSave v1 schema and
    # root/digest checks. Mixed source modes would yield misleading "missing"
    # anchors; report non-comparability instead of false issue resolution.
    if ($left.record.source_mode -cne $right.record.source_mode) {
        return [ordered]@{
            source_root = $VerifiedRoot; mode = 'Compare'; comparable = $false
            comparison_basis = 'exact_saved_finding_quote_anchor'
            left_record = (Get-CodeCompareRecordSummary -Checked $left -AnchorCount $null)
            right_record = (Get-CodeCompareRecordSummary -Checked $right -AnchorCount $null)
            counts = $null; shared_anchors = @(); left_only_anchors = @(); right_only_anchors = @()
            explanation = 'Different saved source modes have no defined evidence-anchor comparison; no absence or resolution inference.'
            record_integrity_verified = $true; record_authorship_authenticated = $false
            source_revalidated = $false; finding_semantics_verified = $false
            claimed_lines_verified = $false; snapshot_atomic = $false
        }
    }

    $leftGroups = Get-CodeCompareGroups -Record $left.record
    $rightGroups = Get-CodeCompareGroups -Record $right.record
    $keys = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($key in $leftGroups.Keys) { [void]$keys.Add($key) }
    foreach ($key in $rightGroups.Keys) { [void]$keys.Add($key) }

    $shared = [System.Collections.Generic.List[object]]::new()
    $leftOnly = [System.Collections.Generic.List[object]]::new()
    $rightOnly = [System.Collections.Generic.List[object]]::new()
    $sharedLeftFindings = 0
    $sharedRightFindings = 0
    foreach ($key in $keys) {
        $onLeft = $leftGroups.ContainsKey($key)
        $onRight = $rightGroups.ContainsKey($key)
        $leftGroup = if ($onLeft) { $leftGroups[$key] } else { $null }
        $rightGroup = if ($onRight) { $rightGroups[$key] } else { $null }
        $anchor = if ($onLeft) { $leftGroup.anchor } else { $rightGroup.anchor }
        $leftFindings = Get-CodeCompareFindingArray -Group $leftGroup
        $rightFindings = Get-CodeCompareFindingArray -Group $rightGroup
        $entry = [ordered]@{
            anchor = $anchor
            left_finding_count = $leftFindings.Count
            right_finding_count = $rightFindings.Count
            left_findings = $leftFindings
            right_findings = $rightFindings
        }
        if ($onLeft -and $onRight) {
            $shared.Add($entry)
            $sharedLeftFindings += $leftFindings.Count
            $sharedRightFindings += $rightFindings.Count
        } elseif ($onLeft) { $leftOnly.Add($entry) }
        else { $rightOnly.Add($entry) }
    }
    return [ordered]@{
        source_root = $VerifiedRoot
        mode = 'Compare'
        comparable = $true
        comparison_basis = 'exact_saved_finding_quote_anchor'
        left_record = (Get-CodeCompareRecordSummary -Checked $left -AnchorCount $leftGroups.Count)
        right_record = (Get-CodeCompareRecordSummary -Checked $right -AnchorCount $rightGroups.Count)
        counts = [ordered]@{
            shared_anchor_count = $shared.Count
            left_only_anchor_count = $leftOnly.Count
            right_only_anchor_count = $rightOnly.Count
            shared_anchor_left_finding_count = $sharedLeftFindings
            shared_anchor_right_finding_count = $sharedRightFindings
        }
        shared_anchors = $shared.ToArray()
        left_only_anchors = $leftOnly.ToArray()
        right_only_anchors = $rightOnly.ToArray()
        explanation = 'Same anchor = same saved source mode, layer, case-sensitive path, path endpoint, quotation SHA-256 and quote proof category. No finding identity, source freshness, chronological sequence or fix is inferred.'
        record_integrity_verified = $true
        record_authorship_authenticated = $false
        source_revalidated = $false
        finding_semantics_verified = $false
        claimed_lines_verified = $false
        snapshot_atomic = $false
    }
}
