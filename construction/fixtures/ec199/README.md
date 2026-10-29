# EC199 synthetic development fixtures

`../test_report_render.py` uses the real EC192 through EC198 Python implementations
and their existing offline synthetic fixtures to construct full, reproducible
EC198 Handoff JSON, EC197 release and EC198 review-only policies. No private
tokens, raw third-party repositories, authenticated approvals or actual CI data.

Coverage focuses on complete replay, per-repository citation/period/source pins,
static Markdown source and CI unknown semantics, separate render/save permission,
private POSIX atomic storage, no-overwrite version history, CAS and retry tokens,
corrupt index/content rejection, symlink/private-mode denial, and no publishing.

Run from `ces/construction`:
`python -m unittest -q test_report_render`

OS/provider/native PowerShell/malicious actor/final acceptance remain NOT_RUN.
