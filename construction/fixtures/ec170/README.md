# EC170 fixture/test notes

EC170 intentionally uses generated in-memory fixtures from the existing EC165/EC166 test helpers rather than committing real repository source, patches, tokens, Provider payloads, absolute user paths or credentials.

Focused suite: `construction/test_codeprepare_multisource.py` (31 cases). It covers explicit mode selection, cross-source input/permission isolation, native `CODE_PREPARE_READY` and `CODE_PREPARE_EMPTY` compatibility, stable-root/Git-pin/path constraints, all-content withholding on path/byte budgets, EC165 bounded snapshot consumption, EC166 fresh/stale/baseline binding, EC169 label-only behavior, strict JSON decoding and stdout-only execution. The round also reruns the complete EC165 (33) and EC166 (25) development suites: 88 combined cases.

These are offline development checks only. No fixture is evidence of a live GitHub/GitLab request, authenticated Provider actor, remote delivery/deployment, native PowerShell route, Windows/macOS behavior or final acceptance.
