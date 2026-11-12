'use client';

import { useEffect, useState } from 'react';
import {
  Alert,
  Button,
  Checkbox,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  ListItemText,
  MenuItem,
  Stack,
  TextField,
} from '@mui/material';
import {
  ASSET_COMPLIANCE_FRAMEWORKS,
  ASSET_CRITICALITIES,
  ASSET_DATA_CLASSIFICATIONS,
  ASSET_ENVIRONMENTS,
  ASSET_KINDS,
  ASSET_STATUSES,
  CMF_CATEGORIES,
  type AssetOut,
  createAsset,
  updateAsset,
} from '@/lib/api';

export default function AssetEditor({
  codename,
  target,
  onClose,
  onSaved,
}: {
  codename?: string;
  target: AssetOut | 'new' | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const open = target !== null;
  const isNew = target === 'new';
  const existing = target && target !== 'new' ? target : null;

  const [name, setName] = useState('');
  const [kind, setKind] = useState<string>('server');
  const [hostname, setHostname] = useState('');
  const [ipAddress, setIpAddress] = useState('');
  const [os, setOs] = useState('');
  const [environment, setEnvironment] = useState('production');
  const [location, setLocation] = useState('');
  const [owner, setOwner] = useState('');
  const [businessFunction, setBusinessFunction] = useState('');
  const [cmfCategory, setCmfCategory] = useState('');
  const [criticality, setCriticality] = useState('medium');
  const [dataClassification, setDataClassification] = useState('');
  const [complianceScope, setComplianceScope] = useState<string[]>([]);
  const [status, setStatus] = useState('active');
  const [tagsText, setTagsText] = useState('');
  const [notes, setNotes] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open && existing) {
      setName(existing.name);
      setKind(existing.kind);
      setHostname(existing.hostname ?? '');
      setIpAddress(existing.ip_address ?? '');
      setOs(existing.os ?? '');
      setEnvironment(existing.environment);
      setLocation(existing.location ?? '');
      setOwner(existing.owner ?? '');
      setBusinessFunction(existing.business_function ?? '');
      setCmfCategory(existing.cmf_category ?? '');
      setCriticality(existing.criticality);
      setDataClassification(existing.data_classification ?? '');
      setComplianceScope(existing.compliance_scope ?? []);
      setStatus(existing.status);
      setTagsText((existing.tags ?? []).join(', '));
      setNotes(existing.notes ?? '');
    } else if (open && isNew) {
      setName('');
      setKind('server');
      setHostname('');
      setIpAddress('');
      setOs('');
      setEnvironment('production');
      setLocation('');
      setOwner('');
      setBusinessFunction('');
      setCmfCategory('');
      setCriticality('medium');
      setDataClassification('');
      setComplianceScope([]);
      setStatus('active');
      setTagsText('');
      setNotes('');
    }
    setError(null);
  }, [open, isNew, existing?.id]);

  async function save() {
    setSaving(true);
    setError(null);
    const payload = {
      name: name.trim(),
      kind,
      hostname: hostname || null,
      ip_address: ipAddress || null,
      os: os || null,
      environment,
      location: location || null,
      owner: owner || null,
      business_function: businessFunction || null,
      cmf_category: cmfCategory || null,
      criticality,
      data_classification: dataClassification || null,
      compliance_scope: complianceScope,
      status,
      tags: tagsText
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean),
      notes: notes || null,
    };
    try {
      if (existing) {
        await updateAsset(existing.id, payload, codename);
      } else {
        await createAsset(payload, codename);
      }
      onSaved();
    } catch (e: any) {
      const detail = e?.response?.data?.detail;
      setError(
        typeof detail === 'string'
          ? detail
          : Array.isArray(detail)
            ? detail.map((d: any) => d.msg ?? '').join('; ')
            : 'save failed',
      );
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={open} onClose={saving ? undefined : onClose} maxWidth="md" fullWidth>
      <DialogTitle>
        {isNew ? 'Add asset' : `Edit ${existing?.name ?? 'asset'}`}
      </DialogTitle>
      <DialogContent dividers>
        <Stack spacing={2} sx={{ pt: 1 }}>
          {error && <Alert severity="error">{error}</Alert>}
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5}>
            <TextField
              size="small"
              label="Name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              sx={{ flex: 2 }}
              required
            />
            <TextField
              select
              size="small"
              label="Kind"
              value={kind}
              onChange={(e) => setKind(e.target.value)}
              sx={{ flex: 1 }}
            >
              {ASSET_KINDS.map((k) => (
                <MenuItem key={k} value={k}>{k.replace('_', ' ')}</MenuItem>
              ))}
            </TextField>
            <TextField
              select
              size="small"
              label="Criticality"
              value={criticality}
              onChange={(e) => setCriticality(e.target.value)}
              sx={{ flex: 1 }}
            >
              {ASSET_CRITICALITIES.map((c) => (
                <MenuItem key={c} value={c}>{c}</MenuItem>
              ))}
            </TextField>
          </Stack>

          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5}>
            <TextField
              size="small"
              label="Hostname"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              sx={{ flex: 1 }}
            />
            <TextField
              size="small"
              label="Primary IP"
              value={ipAddress}
              onChange={(e) => setIpAddress(e.target.value)}
              sx={{ flex: 1 }}
            />
            <TextField
              size="small"
              label="OS"
              value={os}
              onChange={(e) => setOs(e.target.value)}
              sx={{ flex: 1 }}
            />
          </Stack>

          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5}>
            <TextField
              select
              size="small"
              label="Environment"
              value={environment}
              onChange={(e) => setEnvironment(e.target.value)}
              sx={{ flex: 1 }}
            >
              {ASSET_ENVIRONMENTS.map((e) => (
                <MenuItem key={e} value={e}>{e}</MenuItem>
              ))}
            </TextField>
            <TextField
              select
              size="small"
              label="Status"
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              sx={{ flex: 1 }}
            >
              {ASSET_STATUSES.map((s) => (
                <MenuItem key={s} value={s}>{s}</MenuItem>
              ))}
            </TextField>
            <TextField
              size="small"
              label="Location"
              value={location}
              onChange={(e) => setLocation(e.target.value)}
              sx={{ flex: 1 }}
            />
          </Stack>

          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5}>
            <TextField
              size="small"
              label="Owner"
              value={owner}
              onChange={(e) => setOwner(e.target.value)}
              sx={{ flex: 1 }}
            />
            <TextField
              size="small"
              label="Business function"
              value={businessFunction}
              onChange={(e) => setBusinessFunction(e.target.value)}
              sx={{ flex: 1 }}
              placeholder="Business unit"
            />
            <TextField
              select
              size="small"
              label="CMF category"
              value={cmfCategory}
              onChange={(e) => setCmfCategory(e.target.value)}
              sx={{ flex: 1 }}
              helperText="Functional grouping"
            >
              <MenuItem value=""><em>— none —</em></MenuItem>
              {CMF_CATEGORIES.map((c) => (
                <MenuItem key={c} value={c}>{c}</MenuItem>
              ))}
            </TextField>
            <TextField
              select
              size="small"
              label="Data classification"
              value={dataClassification}
              onChange={(e) => setDataClassification(e.target.value)}
              sx={{ flex: 1 }}
            >
              <MenuItem value=""><em>— none —</em></MenuItem>
              {ASSET_DATA_CLASSIFICATIONS.map((c) => (
                <MenuItem key={c} value={c}>{c}</MenuItem>
              ))}
            </TextField>
          </Stack>

          <TextField
            select
            size="small"
            label="Compliance scope"
            SelectProps={{
              multiple: true,
              renderValue: (sel) => (sel as string[]).join(', '),
            }}
            value={complianceScope}
            onChange={(e) => {
              const v = e.target.value;
              setComplianceScope(Array.isArray(v) ? (v as string[]) : []);
            }}
            helperText="Pick the frameworks the asset is in scope for."
          >
            {ASSET_COMPLIANCE_FRAMEWORKS.map((f) => (
              <MenuItem key={f} value={f}>
                <Checkbox size="small" checked={complianceScope.includes(f)} />
                <ListItemText primary={f} />
              </MenuItem>
            ))}
          </TextField>

          <TextField
            size="small"
            label="Tags (comma-separated)"
            value={tagsText}
            onChange={(e) => setTagsText(e.target.value)}
            placeholder="payroll, pii, public-facing"
          />

          <TextField
            label="Notes"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            multiline
            minRows={2}
            maxRows={6}
            size="small"
          />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={saving}>Cancel</Button>
        <Button
          variant="contained"
          onClick={save}
          disabled={saving || name.trim().length < 1}
        >
          {saving ? <CircularProgress size={16} /> : isNew ? 'Create' : 'Save'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
