"""Detection review lifecycle and the deployment gate.

`DetectionStatus` says where a rule sits operationally; `review_status` says
whether the rule has been reviewed for production. Keeping them separate lets
an already-deployed rule be flagged for re-review after a substantive edit
without pretending the rule is no longer running.

The gate is intentionally narrow: it blocks *transitions into* `deployed`.
Rules that are already deployed may still be edited (the edit flips them back
to `draft`, which surfaces the re-review need) so operators are never locked
out of a production rule.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from app.models.customer import (
    Detection,
    DetectionReviewEvent,
    DetectionReviewStatus,
)

DEPLOYMENT_APPROVAL_REQUIRED = (
    "Approval required: submit this detection for review and get it approved "
    "before marking it deployed."
)
DEPLOYMENT_EDIT_REVIEW_REQUIRED = (
    "Approval required: substantive edits need a new review before deployment."
)
GLOBAL_RULE_REVIEW_REQUIRED = (
    "Approval required: customizing a global rule creates a new rule that "
    "must be reviewed before deployment."
)
GLOBAL_RULE_REVIEW_REFUSED = (
    "Global rules cannot be reviewed directly. Customize the rule first."
)


class ReviewAction(str, enum.Enum):
    SUBMIT = "submit"
    APPROVE = "approve"
    REQUEST_CHANGES = "request_changes"
    RESET = "reset"


class ReviewTransitionError(ValueError):
    """Raised when an action is not valid from the current review state."""


_ACTION_TARGET: dict[ReviewAction, DetectionReviewStatus] = {
    ReviewAction.SUBMIT: DetectionReviewStatus.IN_REVIEW,
    ReviewAction.APPROVE: DetectionReviewStatus.APPROVED,
    ReviewAction.REQUEST_CHANGES: DetectionReviewStatus.CHANGES_REQUESTED,
    ReviewAction.RESET: DetectionReviewStatus.DRAFT,
}

_ALLOWED_FROM: dict[ReviewAction, set[DetectionReviewStatus]] = {
    ReviewAction.SUBMIT: {
        DetectionReviewStatus.DRAFT,
        DetectionReviewStatus.CHANGES_REQUESTED,
    },
    ReviewAction.APPROVE: {DetectionReviewStatus.IN_REVIEW},
    ReviewAction.REQUEST_CHANGES: {DetectionReviewStatus.IN_REVIEW},
    ReviewAction.RESET: {
        DetectionReviewStatus.DRAFT,
        DetectionReviewStatus.IN_REVIEW,
        DetectionReviewStatus.APPROVED,
        DetectionReviewStatus.CHANGES_REQUESTED,
    },
}


def review_status_value(value) -> str:
    """Return the plain string for a review status (enum or string)."""
    if value is None:
        return DetectionReviewStatus.DRAFT.value
    return value.value if hasattr(value, "value") else str(value)


def parse_review_status(value: str) -> DetectionReviewStatus:
    try:
        return DetectionReviewStatus(value)
    except ValueError as exc:
        raise ValueError(f"invalid review_status: {value!r}") from exc


def parse_review_action(value: str) -> ReviewAction:
    try:
        return ReviewAction(value)
    except ValueError as exc:
        raise ValueError(f"invalid review action: {value!r}") from exc


def deployment_block_reason(detection: Detection) -> Optional[str]:
    """Return the reason a rule cannot be promoted to `deployed`, if any."""
    if review_status_value(detection.review_status) == DetectionReviewStatus.APPROVED.value:
        return None
    return DEPLOYMENT_APPROVAL_REQUIRED


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _event(
    detection: Detection,
    *,
    action: str,
    from_status: str,
    to_status: str,
    actor_email: Optional[str],
    note: Optional[str],
    now: datetime,
) -> DetectionReviewEvent:
    return DetectionReviewEvent(
        id=uuid.uuid4(),
        detection_id=detection.id,
        action=action,
        from_status=from_status,
        to_status=to_status,
        note=note or None,
        actor_email=actor_email,
        created_at=now,
    )


def apply_review_action(
    detection: Detection,
    action: ReviewAction,
    *,
    actor_email: Optional[str],
    note: Optional[str] = None,
    reviewer_email: Optional[str] = None,
    due_at: Optional[datetime] = None,
    now: Optional[datetime] = None,
) -> DetectionReviewEvent:
    """Apply a review transition in memory and return the audit event.

    The caller owns the session; this function does not commit. It mutates the
    detection row and returns the event so the API can add it to the same
    transaction.
    """
    current = review_status_value(detection.review_status)
    try:
        current_status = DetectionReviewStatus(current)
    except ValueError as exc:
        raise ReviewTransitionError(
            f"detection has an unknown review state: {current!r}"
        ) from exc

    allowed = _ALLOWED_FROM[action]
    if current_status not in allowed:
        raise ReviewTransitionError(
            f"cannot {action.value} a detection whose review status is {current}"
        )

    target = _ACTION_TARGET[action]
    timestamp = now or _utcnow()
    event = _event(
        detection,
        action=action.value,
        from_status=current,
        to_status=target.value,
        actor_email=actor_email,
        note=note,
        now=timestamp,
    )

    detection.review_status = target.value
    if action == ReviewAction.SUBMIT:
        detection.review_requested_at = timestamp
        detection.reviewed_at = None
        detection.reviewer_email = reviewer_email or None
        detection.review_due_at = due_at
        detection.review_note = note or None
    elif action in (ReviewAction.APPROVE, ReviewAction.REQUEST_CHANGES):
        detection.reviewed_at = timestamp
        detection.reviewer_email = detection.reviewer_email or actor_email
        detection.review_note = note or None
    elif action == ReviewAction.RESET:
        detection.review_requested_at = None
        detection.reviewed_at = None
        detection.reviewer_email = None
        detection.review_due_at = None
        detection.review_note = None

    return event


def invalidate_review(
    detection: Detection,
    *,
    actor_email: Optional[str],
    reason: str,
    now: Optional[datetime] = None,
) -> Optional[DetectionReviewEvent]:
    """Drop an approval (or pending submission) after a substantive edit.

    Returns the audit event when the state actually changed. A rule already in
    `draft` or `changes_requested` keeps its state; the edit is the expected
    work in those states, not a reason to record another transition.
    """
    current = review_status_value(detection.review_status)
    if current not in {
        DetectionReviewStatus.APPROVED.value,
        DetectionReviewStatus.IN_REVIEW.value,
    }:
        return None

    target = DetectionReviewStatus.DRAFT.value
    timestamp = now or _utcnow()
    event = _event(
        detection,
        action="invalidated",
        from_status=current,
        to_status=target,
        actor_email=actor_email,
        note=reason,
        now=timestamp,
    )
    detection.review_status = target
    detection.review_requested_at = None
    detection.reviewed_at = None
    detection.reviewer_email = None
    detection.review_due_at = None
    detection.review_note = None
    return event


__all__ = [
    "DEPLOYMENT_APPROVAL_REQUIRED",
    "DEPLOYMENT_EDIT_REVIEW_REQUIRED",
    "GLOBAL_RULE_REVIEW_REFUSED",
    "GLOBAL_RULE_REVIEW_REQUIRED",
    "ReviewAction",
    "ReviewTransitionError",
    "apply_review_action",
    "deployment_block_reason",
    "invalidate_review",
    "parse_review_action",
    "parse_review_status",
    "review_status_value",
]
