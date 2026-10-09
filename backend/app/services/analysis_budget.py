"""One cooperative monotonic budget for analysis, cache and history storage.

Socket timeouts are not wall-clock cancellation. See ANALYSIS_TIME_POLICY.md.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import time

from botocore.config import Config


REQUEST_BUDGET_SECONDS = 12.0
ANALYSIS_RESERVE_SECONDS = 2.0  # history storage + response assembly
RESPONSE_RESERVE_SECONDS = 1.0
VT_CALL_CAP_SECONDS = 3.0
CACHE_CALL_CAP_SECONDS = 0.4
STORAGE_CALL_CAP_SECONDS = 0.75
MIN_CALL_SECONDS = 0.05


class AnalysisBudgetExceeded(RuntimeError):
    pass


class AnalysisBudget:
    def __init__(self, *, seconds=REQUEST_BUDGET_SECONDS, clock=None):
        self.clock = clock or time.monotonic
        self.deadline = self.clock() + seconds
        self.exhausted = False

    def remaining(self, *, reserve=0.0):
        return max(0.0, self.deadline - self.clock() - reserve)

    def allowance(self, cap, *, storage=False):
        reserve = RESPONSE_RESERVE_SECONDS if storage else ANALYSIS_RESERVE_SECONDS
        available = min(cap, self.remaining(reserve=reserve))
        if available < MIN_CALL_SECONDS:
            self.exhausted = True
            raise AnalysisBudgetExceeded("Analysis time budget exhausted")
        return available


_current_budget: ContextVar[AnalysisBudget | None] = ContextVar(
    "qr_analysis_budget", default=None,
)


def current_budget():
    return _current_budget.get()


@contextmanager
def budget_scope(budget):
    token = _current_budget.set(budget)
    try:
        yield budget
    finally:
        _current_budget.reset(token)


def request_budget(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        budget = current_budget() or AnalysisBudget()
        with budget_scope(budget):
            result = function(*args, **kwargs)
            if budget.exhausted:
                result.setdefault("analysis_flags", {})["analysis_budget_exhausted"] = True
            return result
    return wrapped


def ensure_local_analysis_time():
    budget = current_budget()
    if budget and budget.remaining(reserve=RESPONSE_RESERVE_SECONDS) <= 0:
        budget.exhausted = True
        raise AnalysisBudgetExceeded("No time to start local URL analysis")


def io_timeout(cap, *, storage=False):
    budget = current_budget()
    available = budget.allowance(cap, storage=storage) if budget else cap
    # Socket timeouts do not cancel a whole operation. Split the allowance so
    # connect and one idle read do not each get the whole remaining budget.
    return available * 0.25, available * 0.75


def dynamodb_config(*, storage=False):
    cap = STORAGE_CALL_CAP_SECONDS if storage else CACHE_CALL_CAP_SECONDS
    connect, read = io_timeout(cap, storage=storage)
    return Config(
        connect_timeout=connect,
        read_timeout=read,
        retries={"mode": "standard", "total_max_attempts": 1},
    )
