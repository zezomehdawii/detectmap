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

export function assetFormValues(asset?: Partial<AssetOut> | null) {
  return {
    name: asset?.name ?? '',
    kind: asset?.kind ?? 'server',
    hostname: asset?.hostname ?? '',
    ipAddress: asset?.ip_address ?? '',
    os: asset?.os ?? '',
    environment: asset?.environment ?? 'production',
    location: asset?.location ?? '',
    owner: asset?.owner ?? '',
    businessFunction: asset?.business_function ?? '',
    cmfCategory: asset?.cmf_category ?? '',
    criticality: asset?.criticality ?? 'medium',
    dataClassification: asset?.data_classification ?? '',
    complianceScope: asset?.compliance_scope ?? [] as string[],
    status: asset?.status ?? 'active',
    tagsText: (asset?.tags ?? []).join(', '),
    notes: asset?.notes ?? '',
    externalId: asset?.external_id ?? '',
  };
}

export type AssetFormValues = ReturnType<typeof assetFormValues>;

export function assetFormPayload(fields: AssetFormValues) {
  return {
    name: fields.name.trim(),
    kind: fields.kind,
    hostname: fields.hostname || null,
    ip_address: fields.ipAddress || null,
    os: fields.os || null,
    environment: fields.environment,
    location: fields.location || null,
    owner: fields.owner || null,
    business_function: fields.businessFunction || null,
    cmf_category: fields.cmfCategory || null,
    criticality: fields.criticality,
    data_classification: fields.dataClassification || null,
    compliance_scope: fields.complianceScope,
    status: fields.status,
    tags: fields.tagsText.split(',').map((tag) => tag.trim()).filter(Boolean),
    notes: fields.notes || null,
  };
}

export function AssetFields({
  value,
  onChange,
  capture = false,
}: {
  value: AssetFormValues;
  onChange: (changes: Partial<AssetFormValues>) => void;
  capture?: boolean;
}) {
  const {
    name, kind, hostname, ipAddress, os, environment, location, owner, businessFunction,
    cmfCategory, criticality, dataClassification, complianceScope, status, tagsText, notes, externalId,
  } = value;

  return (
    <Stack spacing={2}>
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5}>
        <TextField
          size="small"
          label="Name"
          inputProps={{ maxLength: 200 }}
          value={name}
          onChange={(e) => onChange({ name: e.target.value })}
          sx={{ flex: 2 }}
          required
        />
        <TextField
          select
          size="small"
          label="Kind"
          value={kind}
          onChange={(e) => onChange({ kind: e.target.value })}
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
          onChange={(e) => onChange({ criticality: e.target.value })}
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
          inputProps={{ maxLength: 255 }}
          value={hostname}
          onChange={(e) => onChange({ hostname: e.target.value })}
          sx={{ flex: 1 }}
        />
        <TextField
          size="small"
          label="Primary IP"
          InputProps={{ readOnly: capture }}
          value={ipAddress}
          onChange={(e) => onChange({ ipAddress: e.target.value })}
          sx={{ flex: 1 }}
        />
        <TextField
          size="small"
          label="OS"
          inputProps={{ maxLength: 120 }}
          value={os}
          onChange={(e) => onChange({ os: e.target.value })}
          sx={{ flex: 1 }}
        />
      </Stack>

      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5}>
        <TextField
          select
          size="small"
          label="Environment"
          value={environment}
          onChange={(e) => onChange({ environment: e.target.value })}
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
          onChange={(e) => onChange({ status: e.target.value })}
          sx={{ flex: 1 }}
        >
          {ASSET_STATUSES.map((s) => (
            <MenuItem key={s} value={s}>{s}</MenuItem>
          ))}
        </TextField>
        <TextField
          size="small"
          label="Location"
          inputProps={{ maxLength: 200 }}
          value={location}
          onChange={(e) => onChange({ location: e.target.value })}
          sx={{ flex: 1 }}
        />
      </Stack>

      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5}>
        <TextField
          size="small"
          label="Owner"
          inputProps={{ maxLength: 200 }}
          value={owner}
          onChange={(e) => onChange({ owner: e.target.value })}
          sx={{ flex: 1 }}
        />
        <TextField
          size="small"
          label="Business function"
          inputProps={{ maxLength: 200 }}
          value={businessFunction}
          onChange={(e) => onChange({ businessFunction: e.target.value })}
          sx={{ flex: 1 }}
          placeholder="Business unit"
        />
        <TextField
          select
          size="small"
          label="CMF category"
          value={cmfCategory}
          onChange={(e) => onChange({ cmfCategory: e.target.value })}
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
          onChange={(e) => onChange({ dataClassification: e.target.value })}
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
          onChange({ complianceScope: Array.isArray(v) ? (v as string[]) : [] });
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
        onChange={(e) => onChange({ tagsText: e.target.value })}
        placeholder="payroll, pii, public-facing"
      />

      <TextField
        label="Notes"
        inputProps={{ maxLength: capture ? 4000 : undefined }}
        value={notes}
        onChange={(e) => onChange({ notes: e.target.value })}
        multiline
        minRows={2}
        maxRows={6}
        size="small"
      />
      {capture && (
        <TextField
          size="small"
          label="External ID"
          value={externalId}
          inputProps={{ maxLength: 120 }}
          onChange={(event) => onChange({ externalId: event.target.value })}
        />
      )}
    </Stack>
  );
}

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

  const [fields, setFields] = useState(() => assetFormValues());
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) setFields(assetFormValues(existing));
    setError(null);
  }, [open, isNew, existing?.id]);

  async function save() {
    setSaving(true);
    setError(null);
    const payload = assetFormPayload(fields);
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
          <AssetFields value={fields} onChange={(changes) => setFields((current) => ({ ...current, ...changes }))} />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={saving}>Cancel</Button>
        <Button
          variant="contained"
          onClick={save}
          disabled={saving || fields.name.trim().length < 1}
        >
          {saving ? <CircularProgress size={16} /> : isNew ? 'Create' : 'Save'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
