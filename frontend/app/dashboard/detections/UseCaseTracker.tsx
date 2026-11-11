'use client';

import { FormEvent, useEffect, useId, useState } from 'react';
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Paper,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import ExpandMoreRoundedIcon from '@mui/icons-material/ExpandMoreRounded';
import {
  DetectionDetail,
  DetectionVersion,
  apiErrorMessage,
  getDetection,
  isDetectionVersionConflict,
  listDetectionVersions,
  patchDetection,
} from '@/lib/api';
import { ChangePurposeField } from './UseCaseChange';

export function ChangeDate({ value }: { value: string }) {
  const date = new Date(value);
  return (
    <time dateTime={value} title={value}>
      {date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}
    </time>
  );
}

export function EditUseCaseDialog({
  detail,
  onClose,
  onChanged,
}: {
  detail: DetectionDetail;
  onClose: () => void;
  onChanged: (detail: DetectionDetail) => void;
}) {
  const titleId = useId();
  const originalYaml = detail.raw_yaml ?? '';
  const [yaml, setYaml] = useState(originalYaml);
  const [title, setTitle] = useState(detail.title);
  const [description, setDescription] = useState(detail.description ?? '');
  const [breadth, setBreadth] = useState(String(detail.score_breadth));
  const [depth, setDepth] = useState(String(detail.score_depth));
  const [purpose, setPurpose] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [stale, setStale] = useState(false);

  const editMetadata = !originalYaml && !yaml.trim();
  const titleChanged = editMetadata && title.trim() !== detail.title;
  const descriptionChanged = editMetadata && description !== (detail.description ?? '');
  const yamlChanged = yaml !== originalYaml && !!yaml.trim();
  const breadthChanged = breadth !== String(detail.score_breadth);
  const depthChanged = depth !== String(detail.score_depth);
  const changed = yamlChanged || titleChanged || descriptionChanged || breadthChanged || depthChanged;
  const scoresValid = (!breadthChanged || /^[0-5]$/.test(breadth)) && (!depthChanged || /^[0-5]$/.test(depth));
  const canSave = changed && scoresValid && purpose.trim() && (editMetadata ? title.trim() : yaml.trim());
  const global = detail.source === 'global';

  async function save(event: FormEvent) {
    event.preventDefault();
    if (!canSave || saving || stale) return;
    setSaving(true);
    setError(null);
    try {
      const updated = await patchDetection(detail.id, {
        ...(yamlChanged ? { raw_yaml: yaml } : {}),
        ...(titleChanged ? { title: title.trim() } : {}),
        ...(descriptionChanged ? { description } : {}),
        ...(breadthChanged ? { score_breadth: Number(breadth) } : {}),
        ...(depthChanged ? { score_depth: Number(depth) } : {}),
        change_reason: purpose.trim(),
        expected_version: detail.version,
      });
      onChanged(updated);
      onClose();
    } catch (err) {
      setStale(isDetectionVersionConflict(err));
      setError(apiErrorMessage(err, 'Could not save the use case.'));
    } finally {
      setSaving(false);
    }
  }

  async function reload() {
    setSaving(true);
    try {
      onChanged(await getDetection(detail.id));
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
      maxWidth="md"
      aria-labelledby={titleId}
      onClose={saving ? undefined : onClose}
      PaperProps={{ component: 'form', onSubmit: save, noValidate: true }}
    >
      <DialogTitle id={titleId}>{global ? 'Customize use case' : 'Edit use case'}</DialogTitle>
      <DialogContent dividers>
        <Stack spacing={2}>
          <Typography variant="body2" color="text.secondary">
            {global
              ? 'Save your edits as a workspace copy of this catalog rule.'
              : `Editing version ${detail.version} of ${detail.title}.`}
          </Typography>
          {editMetadata && (
            <>
              <TextField
                label="Title"
                value={title}
                onChange={(event) => setTitle(event.target.value)}
                disabled={saving}
                inputProps={{ maxLength: 500 }}
                required
              />
              <TextField
                label="Description"
                value={description}
                onChange={(event) => setDescription(event.target.value)}
                disabled={saving}
                multiline
                minRows={2}
                maxRows={5}
              />
            </>
          )}
          <TextField
            label="Sigma YAML"
            value={yaml}
            onChange={(event) => setYaml(event.target.value)}
            disabled={saving}
            required={!!originalYaml}
            multiline
            minRows={5}
            maxRows={13}
            helperText="Edit the rule logic, severity, and ATT&CK tags in its Sigma YAML. Keep the existing rule ID."
            inputProps={{ spellCheck: false, style: { fontFamily: 'monospace', fontSize: '0.85rem' } }}
          />
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
            <TextField
              label="Breadth score"
              type="number"
              value={breadth}
              onChange={(event) => setBreadth(event.target.value)}
              disabled={saving}
              inputProps={{ min: 0, max: 5, step: 1 }}
              fullWidth
            />
            <TextField
              label="Depth score"
              type="number"
              value={depth}
              onChange={(event) => setDepth(event.target.value)}
              disabled={saving}
              inputProps={{ min: 0, max: 5, step: 1 }}
              fullWidth
            />
          </Stack>
          <ChangePurposeField value={purpose} onChange={setPurpose} disabled={saving} />
          {error && <Alert severity="error" sx={{ whiteSpace: 'pre-wrap' }}>{error}</Alert>}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={saving}>Cancel</Button>
        {stale ? (
          <Button onClick={reload} variant="contained" disabled={saving}>Reload latest version</Button>
        ) : (
          <Button type="submit" variant="contained" disabled={saving || !canSave}>
            {saving ? 'Saving…' : 'Save changes'}
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
}

const FIELD_LABELS: Record<string, string> = {
  raw_yaml: 'Sigma YAML',
  detection_status: 'Status',
  sigma_status: 'Sigma status',
  level: 'Severity',
  tags: 'Tags',
  logsource: 'Log source',
  detection: 'Detection logic',
  falsepositives: 'False positives',
  sigma_references: 'References',
  score_breadth: 'Breadth score',
  score_depth: 'Depth score',
};

const HISTORY_SOURCE_LABELS: Record<DetectionVersion['source'], string> = {
  baseline: 'Baseline',
  created: 'Created',
  manual: 'Edit',
  bulk: 'Bulk edit',
};

function VersionValue({ label, value }: { label: string; value: unknown }) {
  const missing = value == null || value === '';
  const formatted = missing
    ? '—'
    : typeof value === 'object'
      ? JSON.stringify(value, null, 2)
      : String(value);
  return (
    <Paper variant="outlined" sx={{ p: 1.25, minWidth: 0 }}>
      <Typography variant="caption" color="text.secondary">{label}</Typography>
      <Box
        component="pre"
        sx={{
          my: 0.5,
          maxHeight: 240,
          overflow: 'auto',
          overflowWrap: 'anywhere',
          whiteSpace: 'pre-wrap',
          fontSize: '0.8rem',
        }}
      >
        {formatted}
      </Box>
    </Paper>
  );
}

function VersionEntry({ entry }: { entry: DetectionVersion }) {
  const summaryId = useId();
  const fields = Object.entries(entry.changes);
  const author = entry.changed_by_name && entry.changed_by_email
    ? `${entry.changed_by_name} (${entry.changed_by_email})`
    : entry.changed_by_name || entry.changed_by_email || '—';
  return (
    <Accordion
      disableGutters
      variant="outlined"
      slotProps={{ transition: { unmountOnExit: true } }}
    >
      <AccordionSummary expandIcon={<ExpandMoreRoundedIcon />} id={summaryId} aria-controls={`${summaryId}-details`}>
        <Stack spacing={0.5} sx={{ minWidth: 0 }}>
          <Stack direction="row" spacing={1} alignItems="center">
            <Typography variant="subtitle2" fontWeight={700}>Version {entry.version}</Typography>
            <Chip label={HISTORY_SOURCE_LABELS[entry.source]} size="small" variant="outlined" />
          </Stack>
          <Typography variant="body2" sx={{ overflowWrap: 'anywhere', whiteSpace: 'pre-wrap' }}>
            {entry.change_reason}
          </Typography>
          <Typography variant="caption" color="text.secondary" sx={{ overflowWrap: 'anywhere' }}>
            <ChangeDate value={entry.changed_at} /> · {author}
          </Typography>
        </Stack>
      </AccordionSummary>
      <AccordionDetails>
        {fields.length === 0 ? (
          <Typography variant="body2" color="text.secondary">No field changes recorded.</Typography>
        ) : (
          <Stack spacing={2}>
            {fields.map(([key, values]) => (
              <Box key={key}>
                <Typography variant="subtitle2" sx={{ mb: 0.5, textTransform: 'capitalize' }}>
                  {FIELD_LABELS[key] ?? key.replaceAll('_', ' ')}
                </Typography>
                <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr' }, gap: 1 }}>
                  <VersionValue label="Before" value={values.before} />
                  <VersionValue label="After" value={values.after} />
                </Box>
              </Box>
            ))}
          </Stack>
        )}
      </AccordionDetails>
    </Accordion>
  );
}

export function UseCaseHistoryDialog({
  detail,
  onClose,
}: {
  detail: DetectionDetail;
  onClose: () => void;
}) {
  const titleId = useId();
  const [entries, setEntries] = useState<DetectionVersion[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    listDetectionVersions(detail.id)
      .then((data) => { if (active) setEntries(data); })
      .catch((err) => { if (active) setError(apiErrorMessage(err, 'Could not load the version history.')); });
    return () => { active = false; };
  }, [detail.id]);

  return (
    <Dialog open fullWidth maxWidth="md" onClose={onClose} aria-labelledby={titleId}>
      <DialogTitle id={titleId}>Version history</DialogTitle>
      <DialogContent dividers>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>{detail.title}</Typography>
        {error ? (
          <Alert severity="error">{error}</Alert>
        ) : entries === null ? (
          <CircularProgress size={22} aria-label="Loading version history" />
        ) : entries.length === 0 ? (
          <Typography variant="body2" color="text.secondary">No versions are available.</Typography>
        ) : (
          entries.map((entry) => <VersionEntry key={entry.version} entry={entry} />)
        )}
      </DialogContent>
      <DialogActions><Button onClick={onClose}>Close</Button></DialogActions>
    </Dialog>
  );
}
