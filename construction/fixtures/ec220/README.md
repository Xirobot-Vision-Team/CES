# EC220 synthetic fixtures and limitations

The focused local tests reuse `fixtures/ec211/` GH/GL sample Issues with
synthetic token labels. In-memory fake responses add explicit `has_issues`/
`issues_enabled` fields for strict EC220 scope. They are not real provider
identity, confidential Issue permission or writable repository fixtures.
No actual token, source evidence, writable old Issue, signature, or live
provider transaction is embedded. Run no mutation operation against user
repositories; final user-assisted real read-only acceptance is deferred.
