# EC210 temporary-only fixture

See `construction/test_knowledge_lifecycle.py`: tests generate disposable Git commits, EC202 Markdown snapshot, EC206 private candidates, EC207 selection/individual read grants, EC208 exclusive append journal and ephemeral Ed25519 keys. No production credentials, business repository, source Markdown or publication endpoints are modified.

Expected final product: the original source Markdown stays unchanged, private versions are queryable only through EC210+EC202+EC207/206 per-section lineage permissions, and `DocsOnlyPublish` is never invoked.
