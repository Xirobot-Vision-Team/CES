# Development and validation

Use Python 3.12 or 3.13. The maintained operator test suite has no third-party
runtime dependency. Optional legacy modules use requirements-local.txt. PowerShell
7 is needed for native smoke tests; real GitHub credentials are not needed.

```text
python -B -m unittest discover -s operator -p "test_*.py"
python -B tools/release_check.py
pwsh -NoProfile -File tests/Inspect.Smoke.ps1
pwsh -NoProfile -File tests/CodeValidate.Smoke.ps1
```

Do not run every legacy module under recursive discovery on Windows: some
require Linux permissions, local isolation hosts or platform-specific fixtures.
The CI workflow distinguishes the operator matrix from two selected native
smokes. CodeSequence has a documented historical failure and is not silently
reported as passing.

## Editing the maintained layer

Keep changes localized and run tests that exercise the observable behavior. A
unit-test pass is not proof of real project execution, notification delivery or
Issue closure. Extend mock server tests for publication and source-binding
tests for execution.

After source edits, the current product manifest will intentionally fail until
the reviewed release is resealed. `tools/prepare_release.py` builds a separate
clean source directory, checks protected legacy bytes against the historical
baseline, records omissions and regenerates the public current manifest. It
does not edit the source deployment, create Git commits, send messages or push.

```text
python -B tools/prepare_release.py --destination /outside/source/ces-release
python -B /outside/source/ces-release/tools/release_check.py
```

The destination must not exist and must be outside the product tree. The tool
does not overwrite a previous package. Review its output before initializing Git.
It excludes environments, project state, private validation output and itself
never downloads dependencies.

## Dependencies and release scope

requirements-local.txt records the direct optional legacy dependencies used in
the local packaging environment. It is not a complete hashed multi-platform
lockfile. THIRD_PARTY.md records observed licenses and provenance limits. A
release must not claim that an unsigned checksum or a local test result is an
independent audit.
