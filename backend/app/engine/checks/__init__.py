"""Security check implementations for SentinelAPI scanner.

SAFETY RULES FOR THIS PHASE:
1. Read-only by default: TestCases whose endpoint method is not GET are NEVER
   executed against pre-existing (seed/discovered) objects. Write-method BOLA tests
   (PUT/PATCH/DELETE) run ONLY against objects the scanner itself created in this scan,
   tracked for cleanup.
2. Every request goes through Executor.execute (scope guard, rate cap, budget, redaction).
3. Raw ResponseRecords stay in memory. Anything stored in Findings/Evidence or printed
   must be redacted or masked (redaction.py from Phase 4).
4. A check that crashes must never kill the scan: exceptions are caught per check,
   logged (no secrets), and reported as a 'check_error' note.
"""

from app.engine.checks.base import CHECKS, BaseCheck, register_check, run_checks
import app.engine.checks.bfla
import app.engine.checks.bola
import app.engine.checks.data_exposure
import app.engine.checks.input_handling
import app.engine.checks.rate_limit
import app.engine.checks.unauth_access

__all__ = [
    "CHECKS",
    "BaseCheck",
    "register_check",
    "run_checks",
]
