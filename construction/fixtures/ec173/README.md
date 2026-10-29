# EC173 synthetic input fixtures — not provenance or operational permissions

The four `ces.code_prepare_multisource.v1` fixtures are **synthetic** source
contexts with domain-separated, locally recalculable SHA-256. They are not
signed Provider/native responses and contain neither tokens nor live repo
code. They are for offline unit-test/reference comparison only:

- `authorized-local.v1.json`: WorkingTree, independently scoped EC170 content
  release, complete observed inventory; illustrative success/0.
- `denied-local.v1.json`: metadata only, no EC170 content release; EC173 must
  refuse writing AI material.
- `partial-local.v1.json`: text released, explicitly incomplete synthetic
  coverage; if otherwise eligible, EC173 preserves `partial/2`, never success.
- `historical-proposal.v1.json`: EC165 synthetic selected patch, EC170 explicit
  ProposedPR consent; EC173 additionally requires `allow_historical_proposal`
  and remains `partial/2` without source-currentness or delivery proof.

Dates in these files are historical/fixed. EC173 **rejects stale timestamps**:
do not bypass age checking or invent a recent observation to make a fixture
look like real live source. The Python test cases refresh only synthetic
fixture timestamps for bounded temporary-directory functional exercises.

`test_handoff_input.py` generates real random EC171 RunId/HandoffId values in
memory, commits a private EC172 stage in a disposable directory and exercises
EC173 private no-clobber input production. It covers denied/mismatched consent,
old observation, expired stage/input, revision/replay conflicts, historical
proposal, partial coverage, secrets/path blocking, symlink/hardlink/mode,
transaction uncertainty, simultaneous calls and independent in-memory read.
No secret scan of arbitrary source code is comprehensive, and no fixture
should be submitted to real AI or treated as an authenticated Provider claim.
