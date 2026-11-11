'use client';

import { FormEvent, useEffect, useId, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  TextField,
  Typography,
} from '@mui/material';
import { apiErrorMessage, fetchMe, isDetectionVersionConflict } from '@/lib/api';
import { getActiveCustomer } from '@/lib/auth';
import { useFeatures } from '@/lib/features';

export function useCanEditDetections(): boolean {
  const [canEdit, setCanEdit] = useState(false);
  const { customer, isEnabled } = useFeatures();

  useEffect(() => {
    let active = true;
    fetchMe(getActiveCustomer() ?? undefined)
      .then((me) => { if (active) setCanEdit(me.can_edit_detections === true); })
      .catch(() => { if (active) setCanEdit(false); });
    return () => { active = false; };
  }, [customer]);

  return canEdit && isEnabled('detection_editing');
}

export function ChangePurposeField({
  value,
  onChange,
  disabled,
}: {
  value: string;
  onChange: (value: string) => void;
  disabled: boolean;
}) {
  return (
    <TextField
      label="Purpose of change"
      placeholder="For example, reduce alerts from authorized maintenance"
      value={value}
      onChange={(event) => onChange(event.target.value)}
      disabled={disabled}
      required
      fullWidth
      multiline
      minRows={2}
      maxRows={6}
      inputProps={{ maxLength: 2000 }}
    />
  );
}

export interface ChangePurposeAction {
  title: string;
  description: string;
  onSave: (purpose: string) => Promise<void>;
  onReload?: () => Promise<void> | void;
}

export function ChangePurposeDialog({
  action,
  onClose,
}: {
  action: ChangePurposeAction;
  onClose: () => void;
}) {
  const titleId = useId();
  const [purpose, setPurpose] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [stale, setStale] = useState(false);

  async function save(event: FormEvent) {
    event.preventDefault();
    if (saving || stale || !purpose.trim()) return;
    setSaving(true);
    setError(null);
    try {
      await action.onSave(purpose.trim());
      onClose();
    } catch (err) {
      setStale(isDetectionVersionConflict(err));
      setError(apiErrorMessage(err, 'Could not save the change.'));
    } finally {
      setSaving(false);
    }
  }

  async function reload() {
    setSaving(true);
    try {
      await action.onReload?.();
      onClose();
    } catch (err) {
      setError(apiErrorMessage(err, 'Could not reload the use case.'));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog
      open
      fullWidth
      maxWidth="xs"
      aria-labelledby={titleId}
      onClose={saving ? undefined : onClose}
    >
      <Box component="form" onSubmit={save}>
        <DialogTitle id={titleId}>{action.title}</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            {action.description}
          </Typography>
          <ChangePurposeField value={purpose} onChange={setPurpose} disabled={saving || stale} />
          {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose} disabled={saving}>Cancel</Button>
          {stale && action.onReload ? (
            <Button onClick={reload} variant="contained" disabled={saving}>Reload latest version</Button>
          ) : (
            <Button type="submit" variant="contained" disabled={saving || stale || !purpose.trim()}>
              {saving ? 'Saving…' : 'Save change'}
            </Button>
          )}
        </DialogActions>
      </Box>
    </Dialog>
  );
}
