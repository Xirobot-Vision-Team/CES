# EC191 local development scenarios (NOT production acceptance)

These 34 focused `unittest` cases are implemented in
`construction/test_due_calendar.py`. No external project config, saved run
ledger, scheduler installation, native CLI or real report is read or written.

Covered: day/week/month/year; timezone-dependent year crossover, ISO Monday
53rd-week boundary, leap February, DST spring/fall days, half-hour DST,
midnight gaps and repeats, Samoa's wholly skipped civil date; exact processed
boundary vs completion timestamp; `DUE`, `OVERDUE`, `NOT_DUE`, `UNKNOWN`;
invalid IANA zone/abbreviation/naive instant; invalid/future processing marker;
clock failures, date overflow and strict Draft2020-12 response shape.

Run `cd ces/construction && python -m unittest -q test_due_calendar`.
Python 3.11+ `zoneinfo` and an installed IANA timezone database, plus
`jsonschema`, are needed for these tests. Rules and historical transition
times depend on the test host's (un-pinned) tzdb release. All results are
synthetic, local development only; final real-system acceptance is NOT_RUN.
