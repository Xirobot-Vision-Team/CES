# EC205 real local development fixture conventions

`test_knowledge_chapters.py` creates all content in disposable `TemporaryDirectory`
fixtures at test time (not as persistent examples):

- Two real local Git commits, a signed selected target, signed predecessor
  statement and actual Git old/new SHA and modes. All signing keys are randomly
  generated *ephemeral development keys*, never organizational trusted keys.
- A separate local CES snapshot folder with one byte-exact, SHA-matched
  `ces-snapshot.v1.json` and selected Markdown chapters. Markers refer to a
  request-authorized `repository` source. Both source and manifest can drift.
- Rejected/uncertain paths: tampered manifest/bytes, no raw chapter grant, no
  matching explicit source anchor, ambiguous/double annotations, fenced/inline
  examples, unknown source, unsupported document extension, absent signature,
  worktree or branch drift, in-flight snapshot edits, source digest disclosure
  denial, Unicode and structural bounds. No business repository is modified by
  production `KnowledgeChapters.map_chapters()`; setup/attack simulations mutate
  **temporary test fixtures only**.

Use `python -m unittest -q test_knowledge_chapters.py` from `construction/`
when development dependencies are present. This is not the native PowerShell,
organizational authorization or final assisted acceptance test.
