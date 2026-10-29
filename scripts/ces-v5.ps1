#requires -Version 7.0
<#
.SYNOPSIS
    CES unified entry point — V5.53 / R243, delegating legacy R150.
.DESCRIPTION
    With no -RequestPath, delegates every legacy R150 invocation to the original
    unmodified ces.ps1. With explicit -Action/-Mode/-RequestPath, invokes the
    allowlisted V5.53 Python dispatcher. External host-bound operations reject
    without independent authorization. A handler response is NOT a business
    completion receipt, CodeSave grant or evidence of enterprise identity.
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action Inspect -RepoPath /path/to/repo -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action Collect -Mode WorkingTree -RepoPath /path/to/repo -IncludePatches -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action Collect -Mode DeliveredTarget -RepoPath /path/to/repo -BaseSha <full> -TargetSha <full> -TargetRef refs/heads/main -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action Reconcile -Mode Snapshot -RepoPath /path/to/repo -EvidencePath /path/to/saved-collect.json -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodePrepare -Mode Snapshot -RepoPath /path/to/repo -EvidencePath /path/to/saved-collect.json -IncludePatches -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeValidate -Mode Snapshot -RepoPath /path/to/repo -EvidencePath /path/to/saved-collect.json -InputPath /path/to/review-draft.json -IncludePatches -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeSave -Mode Snapshot -RepoPath /path/to/repo -EvidencePath /path/to/saved-collect.json -InputPath /path/to/review-draft.json -IncludePatches -ApprovePersist -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode List -RepoPath /path/to/repo -Limit 50 -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Detail -RepoPath /path/to/repo -RecordId ci-<sha256> -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Findings -RepoPath /path/to/repo -FindingSeverity high -Limit 25 -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Findings -RepoPath /path/to/repo -FindingsRecordIds 'ci-<sha256>,ci-<sha256>' -FindingSeverity high -Limit 25 -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Compare -RepoPath /path/to/repo -LeftRecordId ci-<sha256> -RightRecordId ci-<sha256> -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Trace -RepoPath /path/to/repo -RecordId ci-<sha256> -FindingId F1 -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Trace -RepoPath /path/to/repo -RecordId ci-<sha256> -FindingId F1 -TraceRecordIds 'ci-<seed-sha256>,ci-<other-sha256>' -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Overview -RepoPath /path/to/repo -OverviewSourceMode working_tree_diff -Limit 10 -Json
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Overview -RepoPath /path/to/repo -OverviewRecordIds 'ci-<sha256>,ci-<sha256>' -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Triage -RepoPath /path/to/repo -TriageSourceMode working_tree_diff -TriageTop 15 -Limit 24 -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Triage -RepoPath /path/to/repo -TriageRecordIds 'ci-<sha256>,ci-<sha256>' -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Recurrence -RepoPath /path/to/repo -RecurrenceSourceMode working_tree_diff -RecurrenceMinRecords 2 -RecurrenceTop 15 -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Recurrence -RepoPath /path/to/repo -RecurrenceRecordIds 'ci-<sha256>,ci-<sha256>' -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Sequence -RepoPath /path/to/repo -SequenceRecordIds 'ci-<first>,ci-<second>' -SequenceTop 10 -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Sequence -RepoPath /path/to/repo -SequenceRecordIds 'ci-<first>,ci-<second>' -SequencePath 'src/module.ps1' -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Sequence -RepoPath /path/to/repo -SequenceRecordIds 'ci-<first>,ci-<second>' -SequencePath 'src/module.ps1' -SequenceFindingRecordId ci-<first> -SequenceFindingId F1 -Json
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Sequence -RepoPath /path/to/repo -SequenceRecordIds 'ci-<first>,ci-<second>' -SequencePath 'src/module.ps1' -SequenceAnchorIndex 1 -Json
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Sequence -RepoPath /path/to/repo -SequenceRecordIds 'ci-<first>,ci-<second>' -SequencePath 'src/module.ps1' -SequencePairIndex 1 -Json
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Sequence -RepoPath /path/to/repo -SequenceRecordIds 'ci-<first>,ci-<second>' -SequencePairOverviewIndex 1 -Json
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Sequence -RepoPath /path/to/repo -SequenceRecordIds 'ci-<first>,ci-<second>' -SequencePairOverviewIndex 1 -SequencePairPathIndex 1 -Json
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Sequence -RepoPath /path/to/repo -SequenceRecordIds 'ci-<first>,ci-<second>' -SequencePairOverviewIndex 1 -SequencePairPathIndex 1 -SequencePairPathAnchorIndex 1 -Json
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Sequence -RepoPath /path/to/repo -SequenceRecordIds 'ci-<first>,ci-<second>' -SequencePairOverviewIndex 1 -SequencePairPathIndex 1 -SequencePairPathAnchorIndex 1 -SequencePairPathAnchorFindingSide left -SequencePairPathAnchorFindingIndex 1 -Json
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Sequence -RepoPath /path/to/repo -SequenceRecordIds 'ci-<first>,ci-<second>' -SequencePairOverviewIndex 1 -SequencePairPathIndex 1 -SequencePairPathAnchorIndex 1 -SequencePairPathAnchorFindingSide left -SequencePairPathAnchorFindingIndex 1 -SequencePairPathAnchorFindingCounterpartIndex 1 -Json
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string] $Action = 'Inspect',

    [Parameter()]
    [AllowEmptyString()]
    [string] $RepoPath,

    [Parameter()]
    [switch] $Json,

    [Parameter()]
    [string] $Mode = 'WorkingTree',

    [Parameter()]
    [switch] $IncludePatches,

    [Parameter()]
    [switch] $IncludeUntrackedContent,

    [Parameter()]
    [AllowEmptyString()]
    [string] $BaseSha,

    [Parameter()]
    [AllowEmptyString()]
    [string] $TargetSha,

    [Parameter()]
    [AllowEmptyString()]
    [string] $TargetRef,

    [Parameter()]
    [AllowEmptyString()]
    [string] $EvidencePath,

    [Parameter()]
    [AllowEmptyString()]
    [string] $InputPath,

    [Parameter()]
    [switch] $ApprovePersist,

    [Parameter()]
    [AllowEmptyString()]
    [string] $RecordId,

    [Parameter()]
    [AllowEmptyString()]
    [string] $AfterRecordId,

    [Parameter()]
    [int] $Limit = 50,

    [Parameter()]
    [AllowEmptyString()]
    [string] $AfterFindingCursor,

    [Parameter()]
    [AllowEmptyString()]
    [string] $FindingSeverity,

    [Parameter()]
    [AllowEmptyString()]
    [string] $FindingLayer,

    [Parameter()]
    [AllowEmptyString()]
    [string] $FindingPath,

    [Parameter()]
    [AllowEmptyString()]
    [string] $FindingSourceMode,

    [Parameter()]
    [AllowEmptyString()]
    [string] $FindingsRecordIds,

    [Parameter()]
    [AllowEmptyString()]
    [string] $LeftRecordId,

    [Parameter()]
    [AllowEmptyString()]
    [string] $RightRecordId,

    [Parameter()]
    [AllowEmptyString()]
    [string] $FindingId,

    [Parameter()]
    [AllowEmptyString()]
    [string] $AfterTraceCursor,

    [Parameter()]
    [AllowEmptyString()]
    [string] $TraceRecordIds,

    [Parameter()]
    [AllowEmptyString()]
    [string] $AfterOverviewCursor,

    [Parameter()]
    [AllowEmptyString()]
    [string] $OverviewSourceMode,

    [Parameter()]
    [AllowEmptyString()]
    [string] $OverviewRecordIds,

    [Parameter()]
    [AllowEmptyString()]
    [string] $AfterTriageCursor,

    [Parameter()]
    [AllowEmptyString()]
    [string] $TriageSourceMode,

    [Parameter()]
    [int] $TriageTop = 15,

    [Parameter()]
    [AllowEmptyString()]
    [string] $TriageRecordIds,

    [Parameter()]
    [AllowEmptyString()]
    [string] $AfterRecurrenceCursor,

    [Parameter()]
    [AllowEmptyString()]
    [string] $RecurrenceSourceMode,

    [Parameter()]
    [AllowEmptyString()]
    [string] $RecurrencePath,

    [Parameter()]
    [int] $RecurrenceMinRecords = 2,

    [Parameter()]
    [int] $RecurrenceTop = 15,

    [Parameter()]
    [AllowEmptyString()]
    [string] $RecurrenceRecordIds,

    [Parameter()]
    [AllowEmptyString()]
    [string] $SequenceRecordIds,

    [Parameter()]
    [int] $SequenceTop = 10,

    [Parameter()]
    [AllowEmptyString()]
    [string] $SequencePath,

    [Parameter()]
    [AllowEmptyString()]
    [string] $SequenceFindingRecordId,

    [Parameter()]
    [AllowEmptyString()]
    [string] $SequenceFindingId,

    [Parameter()]
    [AllowEmptyString()]
    [string] $SequenceAnchorIndex,

    [Parameter()]
    [AllowEmptyString()]
    [string] $SequencePairIndex,

    [Parameter()]
    [AllowEmptyString()]
    [string] $SequencePairOverviewIndex,

    [Parameter()]
    [AllowEmptyString()]
    [string] $SequencePairPathIndex,

    [Parameter()]
    [AllowEmptyString()]
    [string] $SequencePairPathAnchorIndex,

    [Parameter()]
    [AllowEmptyString()]
    [string] $SequencePairPathAnchorFindingSide,

    [Parameter()]
    [AllowEmptyString()]
    [string] $SequencePairPathAnchorFindingIndex,

    [Parameter()]
    [AllowEmptyString()]
    [string] $SequencePairPathAnchorFindingCounterpartIndex,

    [Parameter()]
    [AllowEmptyString()]
    [string] $RequestPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Legacy route owns *all* R150 handler checks, exactly as before EC241.
# Do not touch or re-register the historical scripts/ces.ps1 source: EC233
# and EC237 bind its original byte hash to the already-reviewed registry.
if (-not $PSBoundParameters.ContainsKey('RequestPath')) {
    $legacyParams = @{}
    foreach ($key in $PSBoundParameters.Keys) {
        $legacyParams[$key] = $PSBoundParameters[$key]
    }
    & (Join-Path $PSScriptRoot 'ces.ps1') @legacyParams
    exit $LASTEXITCODE
}

# EC241: route ONLY explicit new Action/Mode+request calls to a fixed
# package-relative Python dispatcher. Never feed request JSON into the old
# CodeSave gate, and never pass unrelated legacy options through this bridge.
# A handler return is not business success or a new approval grant.
if ($PSBoundParameters.ContainsKey('RequestPath')) {
    $bridgeAllowed = @('Action', 'Mode', 'RequestPath', 'Json')
    $bridgeInvalid = @($PSBoundParameters.Keys | Where-Object { $_ -notin $bridgeAllowed })
    $reason = $null
    $exitCode = 4
    $bridgeAttempted = $false
    if ($bridgeInvalid.Count -gt 0) {
        $reason = 'ROUTER_LEGACY_PARAMETER_NOT_ACCEPTED'
    } elseif (-not $PSBoundParameters.ContainsKey('Action') -or
              -not $PSBoundParameters.ContainsKey('Mode') -or
              [string]::IsNullOrWhiteSpace($RequestPath)) {
        $reason = 'ROUTER_EXPLICIT_ACTION_MODE_REQUEST_REQUIRED'
    } elseif (-not [System.IO.Path]::IsPathFullyQualified($RequestPath)) {
        $reason = 'ROUTER_ABSOLUTE_REQUEST_FILE_REQUIRED'
    } else {
        $bridgeScript = Join-Path $PSScriptRoot 'ces_router.py'
        $py = Get-Command python3 -CommandType Application -ErrorAction SilentlyContinue
        if ($null -eq $py) {
            $py = Get-Command python -CommandType Application -ErrorAction SilentlyContinue
        }
        if ($null -eq $py -or -not (Test-Path -LiteralPath $bridgeScript -PathType Leaf)) {
            $reason = 'ROUTER_PYTHON_RUNTIME_UNAVAILABLE'
            $exitCode = 5
        } else {
            # '&' invokes a fixed executable with a literal argument vector:
            # no eval, shell concatenation, or caller-controlled module paths.
            $bridgeAttempted = $true
            $bridgeOutput = @(& $py.Source -I $bridgeScript -Action $Action -Mode $Mode -RequestPath $RequestPath 2>$null)
            $nativeCode = $LASTEXITCODE
            if ($bridgeOutput.Count -eq 1 -and $bridgeOutput[0] -is [string]) {
                try {
                    $parsed = ConvertFrom-Json -InputObject $bridgeOutput[0] -ErrorAction Stop
                    # EC243: do not accept a forged `success` or an exit/status
                    # contradiction from a child, even if it claims our schema.
                    $canonicalExits = @{
                        'partial' = 2
                        'offline' = 3
                        'denied' = 3
                        'invalid' = 4
                        'unavailable' = 5
                    }
                    $childStatus = [string]$parsed.status
                    $expectedExit = $canonicalExits[$childStatus]
                    $proofFieldsAreFalse = (
                        $parsed.business_effect_verified -is [bool] -and
                        $parsed.business_effect_verified -eq $false -and
                        $parsed.permissions_granted_by_router -is [bool] -and
                        $parsed.permissions_granted_by_router -eq $false -and
                        $parsed.external_identity_authenticated_by_router -is [bool] -and
                        $parsed.external_identity_authenticated_by_router -eq $false -and
                        $parsed.tasks_advanced_by_router -is [bool] -and
                        $parsed.tasks_advanced_by_router -eq $false
                    )
                    $resultIsCoherent = (
                        $parsed.handler_invoked -is [bool] -and
                        $parsed.handler_attempted -is [bool] -and
                        ($parsed.handler_invoked -eq $false -or $parsed.handler_attempted -eq $true) -and
                        ($parsed.handler_invoked -eq $false -or $null -ne $parsed.handler_result) -and
                        ($parsed.handler_invoked -eq $true -or $null -eq $parsed.handler_result)
                    )
                    if ($parsed.schema -eq 'ces.unified_action_router.v2' -and
                        $parsed.version -eq 'V5.53' -and $parsed.build -eq 'R243' -and
                        $null -ne $expectedExit -and
                        ($parsed.normalized_exit_code -is [int] -or
                         $parsed.normalized_exit_code -is [long]) -and
                        $parsed.normalized_exit_code -eq $expectedExit -and
                        $nativeCode -eq $expectedExit -and
                        $proofFieldsAreFalse -and $resultIsCoherent) {
                        Write-Output $bridgeOutput[0]
                        exit $nativeCode
                    }
                } catch {
                    # Discard invalid/untrusted output; never imply success.
                }
            }
            $reason = 'ROUTER_INVALID_CHILD_OUTPUT_OR_RUNTIME'
            $exitCode = 5
        }
    }
    # This is a PowerShell bridge rejection, not a handler result or proof.
    $normalized = if ($exitCode -eq 5) { 'unavailable' } else { 'invalid' }
    $rejected = [ordered]@{
        schema = 'ces.unified_action_router.v2'
        version = 'V5.53'
        build = 'R243'
        action = $Action
        mode = $Mode
        status = $normalized
        reason_code = $reason
        normalized_exit_code = $exitCode
        outcome_basis = 'powershell_bridge_refusal'
        handler_outcome_consistent = $true
        coverage_assessment = 'NOT_OBSERVED_NO_VALID_HANDLER_RESULT'
        coverage_missing_claims = @()
        route_kind = $null
        handler = $null
        effect_class = $null
        handler_invoked = $false
        handler_attempted = $bridgeAttempted
        handler_exit_code = $null
        handler_status = $null
        handler_result = $null
        business_effect_verified = $false
        external_identity_authenticated_by_router = $false
        permissions_granted_by_router = $false
        tasks_advanced_by_router = $false
        native_powershell_runtime_tested = $false
        limitations = 'PowerShell bridge rejected; no handler result or business effect is proven'
    }
    Write-Output (ConvertTo-Json -InputObject $rejected -Depth 5 -Compress)
    exit $exitCode
}

