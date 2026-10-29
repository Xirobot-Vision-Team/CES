# EC194 development fixture notes

EC194 intentionally keeps its focused cases in `test_actor_report_subject.py` rather than shipping identity-provider payloads or personnel data fixtures. Test identities are synthetic opaque strings and all evidence is digest-only.

The local development suite exercises: EC193 canonical replay; repository-scoped actor-key stability across period/report/clone changes; cross-repository separation; same-display-name non-collapse; display-label hashing; explicit report authorization windows; missing identity receipt blocking attribution; unknown and known-but-unauthorized evidence remaining unattributed; exact repository/report/source-binding checks; half-open time-window enforcement; deterministic ordering; bounded actor/evidence lists; canonical JSON replay; tamper rejection; and Draft2020-12 response validation.

These are development-only synthetic checks. No real GitHub/GitLab/enterprise directory identity, authorization signature, real personnel record, Git/CI event, PowerShell7/native CES route, multi-OS behavior, E63-E66 performance or final user-assisted acceptance is exercised here.
