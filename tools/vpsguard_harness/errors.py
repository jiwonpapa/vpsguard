"""Structured harness failures shared by governance and orchestration."""

from __future__ import annotations


class HarnessError(RuntimeError):
    """Problem, cause, impact and remediation for one failed harness action."""

    def __init__(
        self,
        *,
        code: str,
        problem: str,
        cause: str,
        impact: str,
        next_action: str,
    ) -> None:
        self.code = code
        self.problem = problem
        self.cause = cause
        self.impact = impact
        self.next_action = next_action
        super().__init__(self._message())

    def _message(self) -> str:
        return (
            f"[{self.code}] {self.problem}\n"
            f"cause: {self.cause}\n"
            f"impact: {self.impact}\n"
            f"next: {self.next_action}"
        )
