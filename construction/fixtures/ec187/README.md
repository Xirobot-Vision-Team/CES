# EC187 synthetic no-execution host fixtures

[`../../test_quality_run_budget.py`](../../test_quality_run_budget.py) uses temporary POSIX roots, test-only split HMAC keys, a controllable monotonic clock, and an in-process FakeBroker that returns **claims** instead of launching anything. Even its `host_reported_exit_code=0` is not a real test execution, does not prove a sealed checkout/kernel sandbox, and is never PASS.

Focused scenarios include 45 cases for opt-ins, allowlist/budget ceilings, CPU/wall/process coupling, output byte capture and sanitization, exact limit and signed receipt binding, authorization mutation/drift and forged lease refusal, explicit cancellation, wall timeout, resource limit signals, missing/regressing telemetry, frame/poll abuse, broker failures and uncertain termination. Strict Draft 2020-12 schema acceptance/rejection is exercised alongside those fixtures.

No production broker, runner image, host signing material, provider credential, real test command, benchmark, operating-system isolate or actual cancellation event is in this directory. These fake sessions must never be used for deployed code execution.
