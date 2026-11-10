'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Autocomplete,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  IconButton,
  LinearProgress,
  MenuItem,
  Stack,
  TextField,
  Tooltip,
  Typography,
  alpha,
} from '@mui/material';
import AddRoundedIcon from '@mui/icons-material/AddRounded';
import AutoFixHighRoundedIcon from '@mui/icons-material/AutoFixHighRounded';
import DeleteOutlineRoundedIcon from '@mui/icons-material/DeleteOutlineRounded';
import EditRoundedIcon from '@mui/icons-material/EditRounded';

import {
  AssetOut,
  AssetDataSourceOut,
  listAssetDataSources,
  CMF_DRIVERS,
  CMF_PLAN_STATUSES,
  CMF_PRIORITIES,
  CMF_REQUIREMENT_STATUSES,
  CmfPlanItem,
  CmfPlanItemInput,
  CmfQuery,
  CmfRequirement,
  CmfRequirementInput,
  DataSourceVocabItem,
  createCmfPlanItem,
  createCmfRequirement,
  deleteCmfPlanItem,
  deleteCmfRequirement,
  listAssets,
  listAttackDataSourceVocab,
  listCmfPlan,
  listCmfRequirements,
  seedCmfPlanFromGaps,
  updateCmfPlanItem,
  updateCmfRequirement,
} from '@/lib/api';
import { apiErrorMessage, formatAttackDataSource } from '@/lib/cmf-utils';
import { coverage } from '../../theme';

const human = (s: string) => s.replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase());

const PRIORITY_COLOR: Record<string, string> = {
  critical: coverage.red,
  high: coverage.amber,
  medium: coverage.blue,
  low: coverage.grey,
};

const PLAN_STATUS_COLOR: Record<string, string> = {
  proposed: coverage.grey,
  approved: coverage.blue,
  in_progress: coverage.amber,
  collected: coverage.green,
  validated: coverage.green,
  deferred: coverage.idea,
};

const REQ_STATUS_COLOR: Record<string, string> = {
  proposed: coverage.grey,
  active: coverage.blue,
  satisfied: coverage.green,
  archived: coverage.idea,
};

// ===== Requirements ========================================================

const EMPTY_REQ: CmfRequirementInput = {
  title: '',
  driver: 'ttx',
  priority: 'medium',
  status: 'proposed',
  attack_technique_ids: [],
};

function RequirementDialog({
  open,
  onClose,
  initial,
  editingId,
  onSaved,
}: {
  open: boolean;
  onClose: () => void;
  initial: CmfRequirement | null;
  editingId: string | null;
  onSaved: () => void;
}) {
  const [form, setForm] = useState<CmfRequirementInput>(EMPTY_REQ);
  const [tidText, setTidText] = useState('');
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setForm(initial ? { ...initial } : EMPTY_REQ);
      setTidText((initial?.attack_technique_ids ?? []).join(', '));
      setErr(null);
    }
  }, [open, initial]);

  const set = (p: Partial<CmfRequirementInput>) => setForm((f) => ({ ...f, ...p }));

  const save = async () => {
    if (!form.title?.trim()) {
      setErr('Title is required.');
      return;
    }
    setSaving(true);
    setErr(null);
    try {
      const payload: CmfRequirementInput = {
        ...form,
        attack_technique_ids: tidText
          .split(',')
          .map((s) => s.trim().toUpperCase())
          .filter(Boolean),
      };
      if (editingId) await updateCmfRequirement(editingId, payload);
      else await createCmfRequirement(payload);
      onSaved();
      onClose();
    } catch (e: any) {
      setErr(apiErrorMessage(e, 'Save failed.'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{editingId ? 'Edit requirement' : 'New collection requirement'}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {err && <Alert severity="error">{err}</Alert>}
          <TextField
            label="Title"
            size="small"
            value={form.title ?? ''}
            onChange={(e) => set({ title: e.target.value })}
            placeholder="e.g. Detect Kerberoasting (from TTX-2026-03)"
            required
          />
          <TextField
            label="Description"
            size="small"
            multiline
            minRows={2}
            value={form.description ?? ''}
            onChange={(e) => set({ description: e.target.value })}
          />
          <Stack direction="row" spacing={2}>
            <TextField
              select
              label="Driver"
              size="small"
              fullWidth
              value={form.driver ?? 'ttx'}
              onChange={(e) => set({ driver: e.target.value })}
            >
              {CMF_DRIVERS.map((d) => (
                <MenuItem key={d} value={d}>
                  {human(d)}
                </MenuItem>
              ))}
            </TextField>
            <TextField
              select
              label="Priority"
              size="small"
              fullWidth
              value={form.priority ?? 'medium'}
              onChange={(e) => set({ priority: e.target.value })}
            >
              {CMF_PRIORITIES.map((p) => (
                <MenuItem key={p} value={p}>
                  {human(p)}
                </MenuItem>
              ))}
            </TextField>
            <TextField
              select
              label="Status"
              size="small"
              fullWidth
              value={form.status ?? 'proposed'}
              onChange={(e) => set({ status: e.target.value })}
            >
              {CMF_REQUIREMENT_STATUSES.map((s) => (
                <MenuItem key={s} value={s}>
                  {human(s)}
                </MenuItem>
              ))}
            </TextField>
          </Stack>
          <TextField
            label="ATT&CK techniques (comma-separated)"
            size="small"
            value={tidText}
            onChange={(e) => setTidText(e.target.value)}
            placeholder="T1558.003, T1003.001"
            helperText="Optional references for this collection requirement"
          />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" onClick={save} disabled={saving}>
          {saving ? 'Saving…' : 'Save'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export function RequirementsTab() {
  const [items, setItems] = useState<CmfRequirement[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<CmfRequirement | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setItems(await listCmfRequirements());
    } catch (e: any) {
      setError(
        apiErrorMessage(e, 'Failed to load collection records.'),
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const remove = async (id: string) => {
    try { await deleteCmfRequirement(id); await load(); }
    catch (e) { setError(apiErrorMessage(e, 'Could not delete the requirement.')); }
  };

  return (
    <Card>
      <CardContent sx={{ p: { xs: 2, md: 2.5 } }}>
        <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1.5 }}>
          <Box>
            <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
              Collection requirements ({items.length})
            </Typography>
            <Typography variant="body2" color="text.secondary">
              The drivers behind what you collect — from tabletop exercises, risk management, threat
              modeling, incidents.
            </Typography>
          </Box>
          <Button
            variant="contained"
            size="small"
            startIcon={<AddRoundedIcon />}
            onClick={() => {
              setEditing(null);
              setDialogOpen(true);
            }}
          >
            New requirement
          </Button>
        </Stack>

        {error && <Alert severity="warning">{error}</Alert>}
        {loading && <LinearProgress />}

        {!loading && !error && items.length === 0 && (
          <Alert severity="info">
            No requirements yet. Capture the drivers (TTX, risk, threat modeling) that justify your
            collection, then build a plan against them.
          </Alert>
        )}

        {!loading && items.length > 0 && (
          <Stack spacing={1}>
            {items.map((r) => (
              <Box
                key={r.id}
                sx={{
                  p: 1.5,
                  borderRadius: 1.5,
                  border: '1px solid',
                  borderColor: 'divider',
                }}
              >
                <Stack direction="row" justifyContent="space-between" alignItems="flex-start">
                  <Box sx={{ minWidth: 0 }}>
                    <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                        {r.title}
                      </Typography>
                      <Chip size="small" label={human(r.driver)} />
                      <Chip
                        size="small"
                        label={human(r.priority)}
                        sx={{ bgcolor: alpha(PRIORITY_COLOR[r.priority] ?? coverage.grey, 0.18) }}
                      />
                      <Chip
                        size="small"
                        label={human(r.status)}
                        sx={{ bgcolor: alpha(REQ_STATUS_COLOR[r.status] ?? coverage.grey, 0.18) }}
                      />
                    </Stack>
                    {r.description && (
                      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                        {r.description}
                      </Typography>
                    )}
                    <Stack direction="row" spacing={1.5} sx={{ mt: 0.75 }} flexWrap="wrap" useFlexGap>
                      <Typography variant="caption" color="text.secondary">
                        {r.plan_item_count} plan item{r.plan_item_count === 1 ? '' : 's'}
                      </Typography>
                      {r.attack_technique_ids.length > 0 && (
                        <Typography
                          variant="caption"
                          color="text.secondary"
                          sx={{ fontFamily: 'var(--font-mono, monospace)' }}
                        >
                          {r.attack_technique_ids.join(', ')}
                        </Typography>
                      )}
                    </Stack>
                  </Box>
                  <Stack direction="row">
                    <IconButton
                      size="small"
                      onClick={() => {
                        setEditing(r);
                        setDialogOpen(true);
                      }}
                    >
                      <EditRoundedIcon fontSize="small" />
                    </IconButton>
                    <IconButton size="small" onClick={() => remove(r.id)}>
                      <DeleteOutlineRoundedIcon fontSize="small" />
                    </IconButton>
                  </Stack>
                </Stack>
              </Box>
            ))}
          </Stack>
        )}

        <RequirementDialog
          open={dialogOpen}
          onClose={() => setDialogOpen(false)}
          initial={editing}
          editingId={editing?.id ?? null}
          onSaved={load}
        />
      </CardContent>
    </Card>
  );
}

// ===== Collection plan / implementation tracker ============================

const EMPTY_PLAN: CmfPlanItemInput = {
  data_source: '',
  priority: 'medium',
  status: 'proposed',
};

function PlanItemDialog({
  open,
  onClose,
  initial,
  editingId,
  requirements,
  assets,
  vocab,
  onSaved,
}: {
  open: boolean;
  onClose: () => void;
  initial: CmfPlanItemInput | null;
  editingId: string | null;
  requirements: CmfRequirement[];
  assets: AssetOut[];
  vocab: DataSourceVocabItem[];
  onSaved: () => void;
}) {
  const [form, setForm] = useState<CmfPlanItemInput>(EMPTY_PLAN);
  const [sources, setSources] = useState<AssetDataSourceOut[]>([]);
  const [sourcesLoading, setSourcesLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setForm(initial ?? EMPTY_PLAN);
      setErr(null);
    }
  }, [open, initial]);

  useEffect(() => {
    let cancelled = false;
    setSources([]);
    if (!open || !form.target_asset_id) { setSourcesLoading(false); return; }
    setSourcesLoading(true);
    listAssetDataSources(form.target_asset_id)
      .then((rows) => { if (!cancelled) setSources(rows); })
      .catch((e) => { if (!cancelled) setErr(apiErrorMessage(e, 'Could not load collection sources.')); })
      .finally(() => { if (!cancelled) setSourcesLoading(false); });
    return () => { cancelled = true; };
  }, [open, form.target_asset_id]);

  const set = (p: Partial<CmfPlanItemInput>) => setForm((f) => ({ ...f, ...p }));

  const save = async () => {
    if (!form.data_source?.trim()) {
      setErr('Data source is required.');
      return;
    }
    if (['collected', 'validated'].includes(form.status ?? '') && !form.asset_data_source_id) {
      setErr('Link the implemented collection source before marking this item collected or validated.');
      return;
    }
    if (form.status === 'validated' && !form.notes?.trim()) {
      setErr('Record the test and its result before marking this item validated.');
      return;
    }
    setSaving(true);
    setErr(null);
    try {
      const payload: CmfPlanItemInput = {
        ...form,
        requirement_id: form.requirement_id || null,
        target_asset_id: form.target_asset_id || null,
        asset_data_source_id: form.asset_data_source_id || null,
        due_date: form.due_date || null,
        notes: form.notes?.trim() || null,
      };
      if (editingId) await updateCmfPlanItem(editingId, payload);
      else await createCmfPlanItem(payload);
      onSaved();
      onClose();
    } catch (e: any) {
      setErr(apiErrorMessage(e, 'Save failed.'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{editingId ? 'Edit plan item' : 'Add plan item'}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {err && <Alert severity="error">{err}</Alert>}
          <Autocomplete
            freeSolo
            size="small"
            options={vocab.map((v) => v.raw)}
            value={form.data_source ?? ''}
            onChange={(_, v) => set({ data_source: v ?? '', asset_data_source_id: null })}
            onInputChange={(_, v, reason) => { if (reason === 'input' || reason === 'clear') set({ data_source: v, asset_data_source_id: null }); }}
            renderInput={(params) => (
              <TextField {...params} label="ATT&CK data source to collect" required />
            )}
          />
          <TextField
            label="Rationale"
            size="small"
            multiline
            minRows={2}
            value={form.rationale ?? ''}
            onChange={(e) => set({ rationale: e.target.value })}
          />
          <Stack direction="row" spacing={2}>
            <TextField
              select
              label="Requirement"
              size="small"
              fullWidth
              value={form.requirement_id ?? ''}
              onChange={(e) => set({ requirement_id: e.target.value })}
            >
              <MenuItem value="">— none —</MenuItem>
              {requirements.map((r) => (
                <MenuItem key={r.id} value={r.id}>
                  {r.title}
                </MenuItem>
              ))}
            </TextField>
            <TextField
              select
              label="Target asset"
              size="small"
              fullWidth
              value={form.target_asset_id ?? ''}
              onChange={(e) => set({ target_asset_id: e.target.value, asset_data_source_id: null })}
            >
              <MenuItem value="">— none —</MenuItem>
              {assets.map((a) => (
                <MenuItem key={a.id} value={a.id}>
                  {a.name}
                </MenuItem>
              ))}
            </TextField>
          </Stack>
          <TextField select label="Implemented collection source" size="small"
            value={sources.some((source) => source.id === form.asset_data_source_id) ? form.asset_data_source_id : ''}
            disabled={!form.target_asset_id || sourcesLoading}
            onChange={(e) => set({ asset_data_source_id: e.target.value || null })}
            helperText="Choose an enabled source matching this plan on the target asset. Use Record collection to add one.">
            <MenuItem value="">— not linked —</MenuItem>
            {sources.map((source) => <MenuItem key={source.id} value={source.id} disabled={!source.enabled || (formatAttackDataSource(source.attack_data_source, source.attack_data_component) || source.name).trim().toLowerCase() !== (form.data_source ?? '').trim().toLowerCase()}>{source.name} · {formatAttackDataSource(source.attack_data_source, source.attack_data_component) || 'unmapped'}{source.enabled ? '' : ' (disabled)'}</MenuItem>)}
          </TextField>
          <TextField label="Test / validation notes" size="small" multiline minRows={3}
            value={form.notes ?? ''} onChange={(e) => set({ notes: e.target.value })}
            helperText="Record test date, evidence reference, expected and observed result, and any remaining gap. Required for Validated." />
          <Stack direction="row" spacing={2}>
            <TextField
              select
              label="Priority"
              size="small"
              fullWidth
              value={form.priority ?? 'medium'}
              onChange={(e) => set({ priority: e.target.value })}
            >
              {CMF_PRIORITIES.map((p) => (
                <MenuItem key={p} value={p}>
                  {human(p)}
                </MenuItem>
              ))}
            </TextField>
            <TextField
              select
              label="Status"
              size="small"
              fullWidth
              value={form.status ?? 'proposed'}
              onChange={(e) => set({ status: e.target.value })}
            >
              {CMF_PLAN_STATUSES.map((s) => (
                <MenuItem key={s} value={s}>
                  {human(s)}
                </MenuItem>
              ))}
            </TextField>
          </Stack>
          <Stack direction="row" spacing={2}>
            <TextField
              label="Assigned to"
              size="small"
              fullWidth
              value={form.assigned_to ?? ''}
              onChange={(e) => set({ assigned_to: e.target.value })}
            />
            <TextField
              label="Due date"
              size="small"
              type="date"
              InputLabelProps={{ shrink: true }}
              value={form.due_date ?? ''}
              onChange={(e) => set({ due_date: e.target.value || null })}
            />
          </Stack>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" onClick={save} disabled={saving}>
          {saving ? 'Saving…' : 'Save'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export function PlanTab({ q, onChanged, onImplement }: { q: CmfQuery; onChanged?: () => void; onImplement?: (item: CmfPlanItem) => void }) {
  const [items, setItems] = useState<CmfPlanItem[]>([]);
  const [requirements, setRequirements] = useState<CmfRequirement[]>([]);
  const [assets, setAssets] = useState<AssetOut[]>([]);
  const [vocab, setVocab] = useState<DataSourceVocabItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [seeding, setSeeding] = useState(false);
  const [seedMsg, setSeedMsg] = useState<string | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<CmfPlanItem | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [pl, rq, as] = await Promise.all([
        listCmfPlan(),
        listCmfRequirements(),
        listAssets(),
      ]);
      setItems(pl);
      setRequirements(rq);
      setAssets(as);
    } catch (e: any) {
      setError(
        apiErrorMessage(e, 'Failed to load collection records.'),
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    listAttackDataSourceVocab().then(setVocab).catch(() => {});
  }, [load]);

  const statusCounts = useMemo(() => {
    const c: Record<string, number> = {};
    items.forEach((i) => {
      c[i.status] = (c[i.status] ?? 0) + 1;
    });
    return c;
  }, [items]);

  const seed = async () => {
    setSeeding(true);
    setSeedMsg(null);
    try {
      const res = await seedCmfPlanFromGaps(q, 15);
      setSeedMsg(
        res.created > 0
          ? `Seeded ${res.created} item${res.created === 1 ? '' : 's'} from gap analysis` +
              (res.skipped ? ` (${res.skipped} already in plan).` : '.')
          : `Nothing new to seed — ${res.skipped} top gaps already in the plan.`,
      );
      await load();
      onChanged?.();
    } catch (e: any) {
      setError(apiErrorMessage(e, 'Seeding failed.'));
    } finally {
      setSeeding(false);
    }
  };

  const changeStatus = async (item: CmfPlanItem, status: string) => {
    if (['collected', 'validated'].includes(status)) {
      setEditing({ ...item, status });
      setDialogOpen(true);
      return;
    }
    try {
      await updateCmfPlanItem(item.id, { status });
      await load();
      onChanged?.();
    } catch (e) { setError(apiErrorMessage(e, 'Could not update the plan status.')); }
  };
  const remove = async (id: string) => {
    try {
      await deleteCmfPlanItem(id);
      await load();
      onChanged?.();
    } catch (e) { setError(apiErrorMessage(e, 'Could not delete the plan item.')); }
  };

  return (
    <Card>
      <CardContent sx={{ p: { xs: 2, md: 2.5 } }}>
        <Stack
          direction={{ xs: 'column', sm: 'row' }}
          justifyContent="space-between"
          alignItems={{ sm: 'center' }}
          spacing={1.5}
          sx={{ mb: 1.5 }}
        >
          <Box>
            <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
              Collection plan &amp; implementation ({items.length})
            </Typography>
            <Typography variant="body2" color="text.secondary">
              What to collect to close the gaps, and where each item is in onboarding.
            </Typography>
          </Box>
          <Stack direction="row" spacing={1}>
            <Tooltip title="Create proposed plan items from the current visibility gaps">
              <span>
                <Button
                  variant="outlined"
                  size="small"
                  startIcon={<AutoFixHighRoundedIcon />}
                  onClick={seed}
                  disabled={seeding || (q.denominator !== 'full' && !q.ref)}
                >
                  {seeding ? 'Seeding…' : 'Seed from gaps'}
                </Button>
              </span>
            </Tooltip>
            <Button
              variant="contained"
              size="small"
              startIcon={<AddRoundedIcon />}
              onClick={() => {
                setEditing(null);
                setDialogOpen(true);
              }}
            >
              Add item
            </Button>
          </Stack>
        </Stack>

        {seedMsg && (
          <Alert severity="success" sx={{ mb: 1.5 }} onClose={() => setSeedMsg(null)}>
            {seedMsg}
          </Alert>
        )}
        {error && <Alert severity="warning">{error}</Alert>}
        {loading && <LinearProgress />}

        {!loading && items.length > 0 && (
          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap sx={{ mb: 1.5 }}>
            {CMF_PLAN_STATUSES.filter((s) => statusCounts[s]).map((s) => (
              <Chip
                key={s}
                size="small"
                label={`${human(s)} · ${statusCounts[s]}`}
                sx={{ bgcolor: alpha(PLAN_STATUS_COLOR[s] ?? coverage.grey, 0.18) }}
              />
            ))}
          </Stack>
        )}

        {!loading && !error && items.length === 0 && (
          <Alert severity="info">
            No plan items yet. Hit <strong>Seed from gaps</strong> to turn the current visibility
            recommendations into a collection plan, or add items by hand.
          </Alert>
        )}

        {!loading && items.length > 0 && (
          <Box sx={{ overflowX: 'auto' }}>
            <Box component="table" sx={{ width: '100%', borderCollapse: 'collapse', fontSize: 14 }}>
              <Box component="thead">
                <Box component="tr" sx={{ '& th': { textAlign: 'left', py: 1, px: 1, color: 'text.secondary', fontWeight: 600, fontSize: 12, textTransform: 'uppercase', letterSpacing: 0.5 } }}>
                  <th>Data source</th>
                  <th>Priority</th>
                  <th>Status</th>
                  <th>Requirement</th>
                  <th>Target asset</th>
                  <th style={{ textAlign: 'right' }}>Techniques</th>
                  <th />
                </Box>
              </Box>
              <Box component="tbody">
                {items.map((it) => (
                  <Box
                    component="tr"
                    key={it.id}
                    sx={{ borderTop: '1px solid', borderColor: 'divider', '& td': { py: 1, px: 1, verticalAlign: 'middle' } }}
                  >
                    <td>
                      <Typography variant="body2" sx={{ fontWeight: 600 }}>
                        {it.data_source}
                      </Typography>
                      {it.notes && <Typography variant="caption" display="block" sx={{ maxWidth: 320, whiteSpace: 'pre-wrap' }}>{it.notes}</Typography>}
                      {it.source_kind === 'gap_seed' && (
                        <Chip size="small" label="from gaps" sx={{ height: 18, fontSize: 10, mt: 0.25 }} />
                      )}
                    </td>
                    <td>
                      <Chip
                        size="small"
                        label={human(it.priority)}
                        sx={{ bgcolor: alpha(PRIORITY_COLOR[it.priority] ?? coverage.grey, 0.18) }}
                      />
                    </td>
                    <td>
                      <TextField
                        select
                        size="small"
                        value={it.status}
                        onChange={(e) => changeStatus(it, e.target.value)}
                        variant="standard"
                        sx={{ minWidth: 130 }}
                        SelectProps={{
                          sx: {
                            fontSize: 13,
                            '&:before': { borderColor: alpha(PLAN_STATUS_COLOR[it.status] ?? coverage.grey, 0.5) },
                          },
                        }}
                      >
                        {CMF_PLAN_STATUSES.map((s) => (
                          <MenuItem key={s} value={s}>
                            {human(s)}
                          </MenuItem>
                        ))}
                      </TextField>
                    </td>
                    <td>
                      <Typography variant="body2" color="text.secondary">
                        {it.requirement_title ?? '—'}
                      </Typography>
                    </td>
                    <td>
                      <Typography variant="body2" color="text.secondary">
                        {it.target_asset_name ?? '—'}
                      </Typography>
                      {it.asset_data_source_id && <Typography variant="caption" display="block" color="success.main">Collection source linked</Typography>}
                    </td>
                    <td style={{ textAlign: 'right' }}>{it.technique_count || '—'}</td>
                    <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                      <Tooltip title={it.target_asset_id ? 'Record a source on the target asset and link it to this plan' : 'Edit this plan item and choose a target asset first'}>
                        <span><Button size="small" disabled={!it.target_asset_id} onClick={() => onImplement?.(it)}>Record collection</Button></span>
                      </Tooltip>
                      <IconButton
                        size="small"
                        onClick={() => {
                          setEditing(it);
                          setDialogOpen(true);
                        }}
                      >
                        <EditRoundedIcon fontSize="small" />
                      </IconButton>
                      <IconButton size="small" onClick={() => remove(it.id)}>
                        <DeleteOutlineRoundedIcon fontSize="small" />
                      </IconButton>
                    </td>
                  </Box>
                ))}
              </Box>
            </Box>
          </Box>
        )}

        <PlanItemDialog
          open={dialogOpen}
          onClose={() => setDialogOpen(false)}
          initial={
            editing
              ? {
                  data_source: editing.data_source,
                  rationale: editing.rationale ?? '',
                  requirement_id: editing.requirement_id ?? '',
                  target_asset_id: editing.target_asset_id ?? '',
                  asset_data_source_id: editing.asset_data_source_id ?? '',
                  notes: editing.notes ?? '',
                  priority: editing.priority,
                  status: editing.status,
                  assigned_to: editing.assigned_to ?? '',
                  due_date: editing.due_date ?? '',
                }
              : null
          }
          editingId={editing?.id ?? null}
          requirements={requirements}
          assets={assets}
          vocab={vocab}
          onSaved={() => {
            load();
            onChanged?.();
          }}
        />
      </CardContent>
    </Card>
  );
}
