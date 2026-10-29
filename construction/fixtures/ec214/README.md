# EC214 synthetic IssueMatch test fixtures (no personal or provider credentials)

`../../test_issue_match.py` uses the original `../ec211/github_repository.json`,
`../ec211/github_issue.json`, `../ec211/gitlab_project.json`, and
`../ec211/gitlab_issue.json`; it builds up to eight **exact** synthetic
per-Issue GET triples, edits only in-memory copies of numbers/global IDs and
private titles, and injects a fake transport plus fixed UTC clock into the
*actual* EC211 reader reused by EC214.

No real provider authorization, network or commits. Coverage includes exact
anchor equality vs changed commit/path/line/digest, independent Match/read/title
grants, title confidentiality `STANDARD` / `NOT_REPORTED` / `CONFIDENTIAL`,
CJK/Latin lexical overlap, redaction, stable global ID drift, 404 hidden,
partial unknown, freshness/expiry, request fingerprint mismatch, offline CLI,
and strict Draft2020-12 schemas. No true duplicate/absent label exists.

Injected callbacks are synthetic even if crafted to look like public GitHub or
GitLab. A live wrapped built-in HTTPS provider observation, authorized host
issuer, private rights, real remote rename/ABA race, PowerShell and OS/NFS
behavior remain for the **deferred joint final acceptance**.
