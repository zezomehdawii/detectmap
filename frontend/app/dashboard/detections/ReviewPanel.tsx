'use client';

import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Chip,
  Divider,
  Paper,
  Stack,
  TextField,
  Typography,
} from '@mui/material';

import {
  DetectionDetail,
  DetectionReviewAction,
  apiErrorMessage,
  getDetection,
  isDetectionVersionConflict,
  patchDetection,
  reviewDetection,
} from '@/lib/api';
import { ChangePurposeAction, ChangePurposeDialog } from './UseCaseChange';

const REVIEW_META: Record<
  string,
  { label: string; color: 'default' | 'primary' | 'success' | 'warning' }
> = {
  draft: { label: 'Draft', color: 'default' },
  in_review: { label: 'In review', color: 'primary' },
  approved: { label: 'Approved', color: 'success' },
  changes_requested: { label: 'Changes requested', color: 'warning' },
};

const ACTION_LABELS: Record<string, string> = {
  submit: 'Submitted for review',
  approve: 'Approved',
  request_changes: 'Changes requested',
  reset: 'Review reset',
  invalidated: 'Approval invalidated by edit',
};

function fmtDateTime(value: string | null): string {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
}

function dateInputValue(value: string | null): string {
  if (!value) return '';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '';
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

function dateInputToIso(value: string): string | undefined {
  if (!value) return undefined;
  const d = new Date(`${value}T17:00:00`);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

export function DetectionReviewPanel({
  detail,
  canEdit,
  onChanged,
}: {
  detail: DetectionDetail;
  canEdit: boolean;
  onChanged: (next: DetectionDetail) => void;
}) {
  const editable = canEdit && detail.source !== 'global';
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [stale, setStale] = useState(false);
  const [owner, setOwner] = useState(detail.owner ?? '');
  const [note, setNote] = useState('');
  const [reviewer, setReviewer] = useState('');
  const [dueDate, setDueDate] = useState('');
  const [ownerAction, setOwnerAction] = useState<ChangePurposeAction | null>(null);

  // Reset the form when the drawer switches to another detection, and keep the
  // owner field in sync when a save returns a fresh row.
  useEffect(() => {
    setOwner(detail.owner ?? '');
    setNote('');
    setReviewer('');
    setDueDate(dateInputValue(detail.review_due_at));
    setError(null);
    setStale(false);
    setOwnerAction(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [detail.id]);

  useEffect(() => {
    setOwner(detail.owner ?? '');
  }, [detail.owner]);

  const reviewStatus = detail.review_status;
  const deployedUnapproved =
    detail.detection_status === 'deployed' && reviewStatus !== 'approved';
  const meta = REVIEW_META[reviewStatus] ?? {
    label: reviewStatus.replace('_', ' '),
    color: 'default' as const,
  };
  const canSubmit =
    reviewStatus === 'draft' || reviewStatus === 'changes_requested';
  const inReview = reviewStatus === 'in_review';
  const overdue = useMemo(() => {
    if (!detail.review_due_at || reviewStatus === 'approved') return false;
    const due = new Date(detail.review_due_at).getTime();
    return !Number.isNaN(due) && due < Date.now();
  }, [detail.review_due_at, reviewStatus]);

  async function act(action: DetectionReviewAction) {
    setBusy(action);
    setError(null);
    setStale(false);
    try {
      const next = await reviewDetection(detail.id, {
        action,
        note: note.trim() || undefined,
        reviewer_email: reviewer.trim() || undefined,
        review_due_at:
          action === 'submit' ? dateInputToIso(dueDate) : undefined,
        expected_version: detail.version,
      });
      setNote('');
      onChanged(next);
    } catch (e) {
      setStale(isDetectionVersionConflict(e));
      setError(apiErrorMessage(e, 'review action failed'));
    } finally {
      setBusy(null);
    }
  }

  async function reload() {
    setBusy('reload');
    try {
      onChanged(await getDetection(detail.id));
      setError(null);
      setStale(false);
    } catch (err) {
      setError(apiErrorMessage(err, 'Could not reload the use case.'));
    } finally {
      setBusy(null);
    }
  }

  function confirmOwnerChange() {
    const nextOwner = owner.trim();
    setOwnerAction({
      title: 'Change owner',
      description: nextOwner ? `Assign this use case to ${nextOwner}.` : 'Clear the owner of this use case.',
      onSave: async (purpose) => {
        const next = await patchDetection(detail.id, {
          owner: nextOwner,
          change_reason: purpose,
          expected_version: detail.version,
        });
        onChanged(next);
      },
      onReload: async () => onChanged(await getDetection(detail.id)),
    });
  }

  return (
    <Paper variant="outlined" sx={{ p: 2 }}>
      <Stack direction="row" alignItems="center" spacing={1}>
        <Typography variant="subtitle2" sx={{ flex: 1, fontWeight: 700 }}>
          Review
        </Typography>
        <Chip
          size="small"
          label={deployedUnapproved ? 'Re-review needed' : meta.label}
          color={deployedUnapproved ? 'warning' : meta.color}
        />
      </Stack>

      {detail.source === 'global' && (
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5 }}>
          Global catalog rules are read-only. Customize the rule to assign an owner or run a review.
        </Typography>
      )}

      {deployedUnapproved && (
        <Alert severity="warning" sx={{ mt: 1 }}>
          This rule is deployed but its approval is out of date. Complete a new
          review, or move the status back out of deployed until it is approved.
        </Alert>
      )}

      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} sx={{ mt: 1.5 }} alignItems="flex-start">
        <TextField
          label="Owner"
          size="small"
          value={owner}
          onChange={(e) => setOwner(e.target.value)}
          inputProps={{ maxLength: 200 }}
          disabled={!editable || busy !== null}
          fullWidth
        />
        {editable && (
          <Button
            size="small"
            variant="outlined"
            onClick={confirmOwnerChange}
            disabled={busy !== null || owner.trim() === (detail.owner ?? '').trim()}
            sx={{ mt: { xs: 0, sm: 0.25 }, whiteSpace: 'nowrap' }}
          >
            Save owner
          </Button>
        )}
      </Stack>

      <Stack direction="row" spacing={2} flexWrap="wrap" useFlexGap sx={{ mt: 1.25 }}>
        <Typography variant="caption" color="text.secondary">
          Reviewer: {detail.reviewer_email || '—'}
        </Typography>
        <Typography variant="caption" color="text.secondary">
          Requested: {fmtDateTime(detail.review_requested_at)}
        </Typography>
        <Typography variant="caption" color="text.secondary">
          Reviewed: {fmtDateTime(detail.reviewed_at)}
        </Typography>
        <Typography variant="caption" color={overdue ? 'error' : 'text.secondary'}>
          Due: {detail.review_due_at ? fmtDateTime(detail.review_due_at) : '—'}
          {overdue ? ' (overdue)' : ''}
        </Typography>
      </Stack>

      {detail.review_note && (
        <Alert severity="info" sx={{ mt: 1.25 }}>
          {detail.review_note}
        </Alert>
      )}

      {editable && (
        <>
          <Divider sx={{ my: 1.5 }} />
          <Stack spacing={1}>
            <TextField
              label="Review note"
              size="small"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              multiline
              minRows={2}
              disabled={busy !== null}
              placeholder="Context for the reviewer, or the reason for a change request"
            />
            {canSubmit && (
              <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
                <TextField
                  label="Reviewer email"
                  size="small"
                  type="email"
                  value={reviewer}
                  onChange={(e) => setReviewer(e.target.value)}
                  disabled={busy !== null}
                  fullWidth
                />
                <TextField
                  label="Review due"
                  size="small"
                  type="date"
                  value={dueDate}
                  onChange={(e) => setDueDate(e.target.value)}
                  disabled={busy !== null}
                  InputLabelProps={{ shrink: true }}
                  fullWidth
                />
              </Stack>
            )}
            <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
              {canSubmit && (
                <Button
                  size="small"
                  variant="contained"
                  onClick={() => act('submit')}
                  disabled={busy !== null}
                >
                  {busy === 'submit' ? 'Submitting…' : 'Submit for review'}
                </Button>
              )}
              {inReview && (
                <Button
                  size="small"
                  variant="contained"
                  color="success"
                  onClick={() => act('approve')}
                  disabled={busy !== null}
                >
                  {busy === 'approve' ? 'Approving…' : 'Approve'}
                </Button>
              )}
              {inReview && (
                <Button
                  size="small"
                  variant="outlined"
                  color="warning"
                  onClick={() => act('request_changes')}
                  disabled={busy !== null}
                >
                  Request changes
                </Button>
              )}
              {reviewStatus !== 'draft' && (
                <Button
                  size="small"
                  variant="text"
                  onClick={() => act('reset')}
                  disabled={busy !== null}
                >
                  Reset review
                </Button>
              )}
            </Stack>
            {canSubmit && (
              <Typography variant="caption" color="text.secondary">
                Approval is required before the status can be set to deployed.
              </Typography>
            )}
          </Stack>
        </>
      )}

      {error && (
        <Alert
          severity="error"
          sx={{ mt: 1.25 }}
          action={stale ? (
            <Button color="inherit" size="small" onClick={reload} disabled={busy !== null}>
              Reload latest version
            </Button>
          ) : undefined}
        >
          {error}
        </Alert>
      )}

      {detail.review_events.length > 0 && (
        <>
          <Divider sx={{ my: 1.5 }} />
          <Typography variant="caption" color="text.secondary">
            Review history
          </Typography>
          <Stack spacing={0.75} sx={{ mt: 0.75, maxHeight: 190, overflowY: 'auto' }}>
            {detail.review_events.map((event) => (
              <Box key={event.id}>
                <Typography variant="caption" sx={{ fontWeight: 600 }}>
                  {ACTION_LABELS[event.action] ?? event.action}
                  {event.actor_email ? ` · ${event.actor_email}` : ''}
                </Typography>
                <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>
                  {fmtDateTime(event.created_at)}
                  {event.note ? ` — ${event.note}` : ''}
                </Typography>
              </Box>
            ))}
          </Stack>
        </>
      )}
      {ownerAction && editable && (
        <ChangePurposeDialog action={ownerAction} onClose={() => setOwnerAction(null)} />
      )}
    </Paper>
  );
}
