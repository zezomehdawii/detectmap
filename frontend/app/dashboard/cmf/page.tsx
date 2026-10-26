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
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  Drawer,
  FormControlLabel,
  IconButton,
  LinearProgress,
  MenuItem,
  Stack,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
  alpha,
} from '@mui/material';
import AddRoundedIcon from '@mui/icons-material/AddRounded';
import CloseRoundedIcon from '@mui/icons-material/CloseRounded';
import DeleteOutlineRoundedIcon from '@mui/icons-material/DeleteOutlineRounded';
import EditRoundedIcon from '@mui/icons-material/EditRounded';
import OpenInNewRoundedIcon from '@mui/icons-material/OpenInNewRounded';
import LightbulbRoundedIcon from '@mui/icons-material/LightbulbRounded';

import {
  APTListItem,
  AssetDataSourceInput,
  AssetDataSourceOut,
  AssetOut,
  CmfOverview,
  DataSourceRecommendation,
  DataSourceVocabItem,
  SectorProfileSummary,
  VisibilityCell,
  VisibilityMatrix,
  VisibilityStateValue,
  createAssetDataSource,
  deleteAssetDataSource,
  getCmfOverview,
  getCmfRecommendations,
  getCmfVisibilityMatrix,
  listAPTPaginated,
  listAssetDataSources,
  listAssets,
  listAttackDataSourceVocab,
  listSectorProfiles,
  updateAssetDataSource,
} from '@/lib/api';
import { coverage } from '../../theme';
import { PlanTab, RequirementsTab } from './CmfLifecycle';

type Kind = 'full' | 'sector' | 'apt';
type TabKey =
  | 'overview'
  | 'requirements'
  | 'plan'
  | 'register'
  | 'matrix'
  | 'recommendations';

const DOMAINS = ['enterprise', 'ics', 'mobile'] as const;

const TACTIC_LABELS: Record<string, string> = {
  reconnaissance: 'Reconnaissance',
  'resource-development': 'Resource development',
  'initial-access': 'Initial access',
  execution: 'Execution',
  persistence: 'Persistence',
  'privilege-escalation': 'Privilege escalation',
  'defense-evasion': 'Defense evasion',
  'credential-access': 'Credential access',
  discovery: 'Discovery',
  'lateral-movement': 'Lateral movement',
  collection: 'Collection',
  'command-and-control': 'Command & control',
  exfiltration: 'Exfiltration',
  impact: 'Impact',
  uncategorised: 'Uncategorised',
};

const VIS_STATE: Record<VisibilityStateValue, { label: string; color: string }> = {
  visible: { label: 'Visible', color: coverage.green },
  partial: { label: 'Partial', color: coverage.amber },
  not_collected: { label: 'Not collected', color: coverage.red },
  no_data_source: { label: 'No ATT&CK data source', color: coverage.grey },
  out_of_scope: { label: 'Out of scope', color: coverage.idea },
};

const QUALITY_DIMS: { key: keyof AssetDataSourceInput; label: string }[] = [
  { key: 'device_completeness_q', label: 'Device completeness' },
  { key: 'data_field_completeness_q', label: 'Data field completeness' },
  { key: 'timeliness_q', label: 'Timeliness' },
  { key: 'consistency_q', label: 'Consistency' },
  { key: 'retention_q', label: 'Retention' },
];

function avgQuality(d: AssetDataSourceOut): number | null {
  const vals = [
    d.device_completeness_q,
    d.data_field_completeness_q,
    d.timeliness_q,
    d.consistency_q,
    d.retention_q,
  ].filter((v): v is number => v !== null && v !== undefined);
  return vals.length ? vals.reduce((a, b) => a + b, 0) / vals.length : null;
}

function gradeColor(grade: string): string {
  return { A: coverage.green, B: coverage.blue, C: coverage.amber, D: coverage.red }[grade] ?? coverage.grey;
}

// ---- small presentational pieces -----------------------------------------

function StatTile({
  label,
  value,
  sub,
  accent,
}: {
  label: string;
  value: React.ReactNode;
  sub?: string;
  accent?: string;
}) {
  return (
    <Card sx={{ flex: '1 1 160px', minWidth: 160 }}>
      <CardContent sx={{ p: { xs: 2, md: 2.5 } }}>
        <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 0.6 }}>
          {label}
        </Typography>
        <Typography variant="h4" sx={{ mt: 0.5, fontWeight: 700, color: accent }}>
          {value}
        </Typography>
        {sub && (
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
            {sub}
          </Typography>
        )}
      </CardContent>
    </Card>
  );
}

function GradeBadge({ grade }: { grade: string }) {
  return (
    <Box
      component="span"
      sx={{
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        width: 36,
        height: 36,
        borderRadius: 1.5,
        fontWeight: 800,
        color: '#08111f',
        bgcolor: gradeColor(grade),
      }}
    >
      {grade}
    </Box>
  );
}

// ---- denominator picker ----------------------------------------------------

function DenominatorPicker({
  domain,
  setDomain,
  kind,
  setKind,
  refValue,
  setRef,
  sectors,
  groups,
  groupQuery,
  setGroupQuery,
}: {
  domain: string;
  setDomain: (v: string) => void;
  kind: Kind;
  setKind: (v: Kind) => void;
  refValue: string;
  setRef: (v: string) => void;
  sectors: SectorProfileSummary[];
  groups: APTListItem[];
  groupQuery: string;
  setGroupQuery: (v: string) => void;
}) {
  return (
    <Card>
      <CardContent sx={{ p: { xs: 2, md: 2.5 } }}>
        <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} alignItems={{ md: 'center' }}>
          <TextField
            select
            size="small"
            label="Domain"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            sx={{ minWidth: 140 }}
          >
            {DOMAINS.map((d) => (
              <MenuItem key={d} value={d}>
                {d[0].toUpperCase() + d.slice(1)}
              </MenuItem>
            ))}
          </TextField>
          <TextField
            select
            size="small"
            label="In-scope set"
            value={kind}
            onChange={(e) => {
              setKind(e.target.value as Kind);
              setRef('');
            }}
            sx={{ minWidth: 180 }}
          >
            <MenuItem value="full">Full ATT&amp;CK</MenuItem>
            <MenuItem value="sector">Sector profile</MenuItem>
            <MenuItem value="apt">APT group</MenuItem>
          </TextField>
          {kind === 'sector' && (
            <TextField
              select
              size="small"
              label="Sector"
              value={refValue}
              onChange={(e) => setRef(e.target.value)}
              sx={{ minWidth: 220 }}
            >
              {sectors.map((s) => (
                <MenuItem key={s.sector} value={s.sector}>
                  {s.label} ({s.technique_count})
                </MenuItem>
              ))}
            </TextField>
          )}
          {kind === 'apt' && (
            <Autocomplete
              size="small"
              sx={{ minWidth: 280 }}
              options={groups}
              getOptionLabel={(o) => o.name}
              onInputChange={(_, v) => setGroupQuery(v)}
              onChange={(_, v) => setRef(v?.group_id ?? '')}
              isOptionEqualToValue={(o, v) => o.group_id === v.group_id}
              inputValue={groupQuery}
              renderInput={(params) => <TextField {...params} label="APT group" />}
            />
          )}
        </Stack>
      </CardContent>
    </Card>
  );
}

// ---- visibility matrix -----------------------------------------------------

function MatrixView({
  matrix,
  onSelect,
}: {
  matrix: VisibilityMatrix;
  onSelect: (c: VisibilityCell) => void;
}) {
  return (
    <Stack spacing={2}>
      <Stack direction="row" spacing={2} flexWrap="wrap" useFlexGap>
        {(Object.keys(VIS_STATE) as VisibilityStateValue[]).map((s) => (
          <Stack key={s} direction="row" spacing={0.75} alignItems="center">
            <Box sx={{ width: 14, height: 14, borderRadius: 0.5, bgcolor: VIS_STATE[s].color }} />
            <Typography variant="caption" color="text.secondary">
              {VIS_STATE[s].label}
            </Typography>
          </Stack>
        ))}
      </Stack>
      <Box sx={{ overflowX: 'auto', pb: 1 }}>
        <Stack direction="row" spacing={1} alignItems="flex-start" sx={{ minWidth: 'min-content' }}>
          {matrix.tactics.map((tac) => {
            const cells = matrix.by_tactic[tac] ?? [];
            return (
              <Box key={tac} sx={{ width: 150, flexShrink: 0 }}>
                <Typography
                  variant="caption"
                  sx={{ fontWeight: 700, display: 'block', mb: 0.5, minHeight: 32 }}
                >
                  {TACTIC_LABELS[tac] ?? tac}
                  <Typography component="span" color="text.secondary" sx={{ ml: 0.5 }}>
                    {cells.length}
                  </Typography>
                </Typography>
                <Stack spacing={0.5}>
                  {cells.map((c) => (
                    <Tooltip
                      key={`${tac}-${c.technique_id}`}
                      title={`${c.technique_id} · ${c.name} — ${VIS_STATE[c.state].label}`}
                      arrow
                    >
                      <Box
                        onClick={() => onSelect(c)}
                        sx={{
                          cursor: 'pointer',
                          px: 0.75,
                          py: 0.5,
                          borderRadius: 0.75,
                          fontSize: 11,
                          fontFamily: 'var(--font-mono, monospace)',
                          color: '#08111f',
                          bgcolor: VIS_STATE[c.state].color,
                          opacity: c.state === 'no_data_source' ? 0.55 : 1,
                          ml: c.is_subtechnique ? 1.25 : 0,
                          whiteSpace: 'nowrap',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          '&:hover': { outline: '2px solid', outlineColor: 'primary.main' },
                        }}
                      >
                        {c.technique_id}
                      </Box>
                    </Tooltip>
                  ))}
                </Stack>
              </Box>
            );
          })}
        </Stack>
      </Box>
    </Stack>
  );
}

// ---- manage dialog ---------------------------------------------------------

const EMPTY_FORM: AssetDataSourceInput & { asset_id?: string } = { name: '', enabled: true };

function DataSourceDialog({
  open,
  onClose,
  assets,
  vocab,
  initial,
  editing,
  onSaved,
}: {
  open: boolean;
  onClose: () => void;
  assets: AssetOut[];
  vocab: DataSourceVocabItem[];
  initial: (AssetDataSourceInput & { asset_id?: string; id?: string }) | null;
  editing: { assetId: string; dsId: string } | null;
  onSaved: () => void;
}) {
  const [form, setForm] = useState<AssetDataSourceInput & { asset_id?: string }>(EMPTY_FORM);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setForm({ ...EMPTY_FORM, ...(initial ?? {}) });
      setErr(null);
    }
  }, [open, initial]);

  const set = (patch: Partial<AssetDataSourceInput & { asset_id?: string }>) =>
    setForm((f) => ({ ...f, ...patch }));

  const save = async () => {
    if (!form.asset_id || !form.name?.trim()) {
      setErr('Asset and source name are required.');
      return;
    }
    setSaving(true);
    setErr(null);
    try {
      const { asset_id, ...payload } = form;
      if (editing) {
        await updateAssetDataSource(editing.assetId, editing.dsId, payload);
      } else {
        await createAssetDataSource(asset_id, payload);
      }
      onSaved();
      onClose();
    } catch (e: any) {
      setErr(e?.response?.data?.detail ?? 'Save failed.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{editing ? 'Edit collection source' : 'Add collection source'}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {err && <Alert severity="error">{err}</Alert>}
          <TextField
            select
            label="Asset"
            size="small"
            value={form.asset_id ?? ''}
            onChange={(e) => set({ asset_id: e.target.value })}
            disabled={!!editing}
            required
          >
            {assets.map((a) => (
              <MenuItem key={a.id} value={a.id}>
                {a.name} · {a.kind}
              </MenuItem>
            ))}
          </TextField>
          <TextField
            label="Source name"
            size="small"
            value={form.name ?? ''}
            onChange={(e) => set({ name: e.target.value })}
            placeholder="e.g. Sysmon, EDR telemetry, WinEventLog:Security"
            required
          />
          <Autocomplete
            freeSolo
            size="small"
            options={vocab.map((v) => v.raw)}
            value={form.attack_data_source ?? ''}
            onChange={(_, v) => set({ attack_data_source: v ?? '' })}
            onInputChange={(_, v) => set({ attack_data_source: v })}
            renderInput={(params) => (
              <TextField
                {...params}
                label="ATT&CK data source"
                helperText="Maps this feed to the techniques it illuminates"
              />
            )}
          />
          <Stack direction="row" spacing={2}>
            <TextField
              label="Log source / channel"
              size="small"
              fullWidth
              value={form.log_source ?? ''}
              onChange={(e) => set({ log_source: e.target.value })}
            />
            <TextField
              label="Retention (days)"
              size="small"
              type="number"
              sx={{ width: 160 }}
              value={form.retention_days ?? ''}
              onChange={(e) =>
                set({ retention_days: e.target.value === '' ? null : Number(e.target.value) })
              }
            />
          </Stack>
          <Divider textAlign="left">
            <Typography variant="caption" color="text.secondary">
              DeTT&amp;CT data quality (0–5, blank = unscored)
            </Typography>
          </Divider>
          <Stack direction="row" spacing={1.5} flexWrap="wrap" useFlexGap>
            {QUALITY_DIMS.map((q) => (
              <TextField
                key={q.key as string}
                select
                size="small"
                label={q.label}
                sx={{ width: 150 }}
                value={(form[q.key] as number | null | undefined) ?? ''}
                onChange={(e) =>
                  set({ [q.key]: e.target.value === '' ? null : Number(e.target.value) } as any)
                }
              >
                <MenuItem value="">—</MenuItem>
                {[0, 1, 2, 3, 4, 5].map((n) => (
                  <MenuItem key={n} value={n}>
                    {n}
                  </MenuItem>
                ))}
              </TextField>
            ))}
          </Stack>
          <FormControlLabel
            control={
              <Switch
                checked={form.enabled ?? true}
                onChange={(e) => set({ enabled: e.target.checked })}
              />
            }
            label="Actively collected (enabled)"
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

// ---- page ------------------------------------------------------------------

interface RegisterRow extends AssetDataSourceOut {
  asset_name: string;
}

export default function CmfPage() {
  const [tab, setTab] = useState<TabKey>('overview');

  // denominator
  const [domain, setDomain] = useState('enterprise');
  const [kind, setKind] = useState<Kind>('full');
  const [refValue, setRef] = useState('');
  const [sectors, setSectors] = useState<SectorProfileSummary[]>([]);
  const [groups, setGroups] = useState<APTListItem[]>([]);
  const [groupQuery, setGroupQuery] = useState('');

  // data
  const [overview, setOverview] = useState<CmfOverview | null>(null);
  const [matrix, setMatrix] = useState<VisibilityMatrix | null>(null);
  const [recs, setRecs] = useState<DataSourceRecommendation[]>([]);
  const [assets, setAssets] = useState<AssetOut[]>([]);
  const [register, setRegister] = useState<RegisterRow[]>([]);
  const [vocab, setVocab] = useState<DataSourceVocabItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // drawer + dialog
  const [selected, setSelected] = useState<VisibilityCell | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [dialogInitial, setDialogInitial] = useState<
    (AssetDataSourceInput & { asset_id?: string; id?: string }) | null
  >(null);
  const [editing, setEditing] = useState<{ assetId: string; dsId: string } | null>(null);

  useEffect(() => {
    listSectorProfiles().then(setSectors).catch(() => {});
    listAttackDataSourceVocab().then(setVocab).catch(() => {});
  }, []);

  useEffect(() => {
    if (kind !== 'apt') return;
    const h = setTimeout(() => {
      listAPTPaginated(groupQuery || undefined, 1, 30)
        .then((r) => setGroups(r.items))
        .catch(() => {});
    }, 200);
    return () => clearTimeout(h);
  }, [kind, groupQuery]);

  const q = useMemo(
    () => ({ domain, denominator: kind, ref: kind === 'full' ? undefined : refValue }),
    [domain, kind, refValue],
  );

  const loadRegister = useCallback(async () => {
    const a = await listAssets();
    setAssets(a);
    const lists = await Promise.all(
      a.map((asset) =>
        listAssetDataSources(asset.id)
          .then((ds) => ds.map((d) => ({ ...d, asset_name: asset.name })))
          .catch(() => [] as RegisterRow[]),
      ),
    );
    setRegister(lists.flat());
  }, []);

  const load = useCallback(async () => {
    if (kind !== 'full' && !refValue) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const [ov, mx, rc] = await Promise.all([
        getCmfOverview(q),
        getCmfVisibilityMatrix(q),
        getCmfRecommendations(q, 25),
      ]);
      setOverview(ov);
      setMatrix(mx);
      setRecs(rc);
      await loadRegister();
    } catch (e: any) {
      setError(
        e?.response?.data?.detail ??
          'Failed to load — pick a customer in the topbar if you are an MSSP user.',
      );
    } finally {
      setLoading(false);
    }
  }, [q, kind, refValue, loadRegister]);

  useEffect(() => {
    load();
  }, [load]);

  const openAdd = (prefill?: Partial<AssetDataSourceInput>) => {
    setEditing(null);
    setDialogInitial({ name: '', enabled: true, ...(prefill ?? {}) });
    setDialogOpen(true);
  };
  const openEdit = (row: RegisterRow) => {
    setEditing({ assetId: row.asset_id, dsId: row.id });
    setDialogInitial({
      asset_id: row.asset_id,
      name: row.name,
      attack_data_source: row.attack_data_source ?? '',
      attack_data_component: row.attack_data_component ?? '',
      log_source: row.log_source ?? '',
      retention_days: row.retention_days,
      device_completeness_q: row.device_completeness_q,
      data_field_completeness_q: row.data_field_completeness_q,
      timeliness_q: row.timeliness_q,
      consistency_q: row.consistency_q,
      retention_q: row.retention_q,
      enabled: row.enabled,
      notes: row.notes ?? '',
    });
    setDialogOpen(true);
  };
  const removeRow = async (row: RegisterRow) => {
    await deleteAssetDataSource(row.asset_id, row.id);
    await Promise.all([loadRegister(), load()]);
  };

  const TABS: { key: TabKey; label: string }[] = [
    { key: 'overview', label: 'Overview' },
    { key: 'requirements', label: 'Requirements' },
    { key: 'plan', label: 'Collection plan' },
    { key: 'register', label: 'Collection register' },
    { key: 'matrix', label: 'Visibility matrix' },
    { key: 'recommendations', label: 'Recommendations' },
  ];

  const isAnalytics =
    tab === 'overview' || tab === 'matrix' || tab === 'recommendations' || tab === 'register';

  return (
    <Stack spacing={2.5}>
      <Box>
        <Typography variant="h4" sx={{ fontWeight: 700 }}>
          Collection management
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
          What telemetry you collect, from which assets, stored where and for how long — and the
          ATT&amp;CK techniques that collection lets you see.
        </Typography>
      </Box>

      <DenominatorPicker
        domain={domain}
        setDomain={setDomain}
        kind={kind}
        setKind={setKind}
        refValue={refValue}
        setRef={setRef}
        sectors={sectors}
        groups={groups}
        groupQuery={groupQuery}
        setGroupQuery={setGroupQuery}
      />

      <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
        {TABS.map((t) => (
          <Button
            key={t.key}
            size="small"
            variant={tab === t.key ? 'contained' : 'text'}
            onClick={() => setTab(t.key)}
          >
            {t.label}
          </Button>
        ))}
      </Stack>

      {/* Requirements + Plan are self-contained (load their own data) and
          don't depend on the visibility denominator load. */}
      {tab === 'requirements' && <RequirementsTab />}
      {tab === 'plan' && <PlanTab q={q} onChanged={load} />}

      {isAnalytics && error && <Alert severity="warning">{error}</Alert>}
      {isAnalytics && loading && <LinearProgress />}

      {isAnalytics && !loading && kind !== 'full' && !refValue && (
        <Alert severity="info">Pick a {kind === 'sector' ? 'sector' : 'APT group'} to scope the analysis.</Alert>
      )}

      {isAnalytics && !loading && !error && overview && (
        <>
          {tab === 'overview' && (
            <Stack spacing={2.5}>
              <Stack direction="row" spacing={2} flexWrap="wrap" useFlexGap>
                <Card sx={{ flex: '1 1 220px', minWidth: 220 }}>
                  <CardContent sx={{ p: { xs: 2, md: 2.5 } }}>
                    <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 0.6 }}>
                      Visibility breadth
                    </Typography>
                    <Stack direction="row" spacing={1.5} alignItems="center" sx={{ mt: 1 }}>
                      <GradeBadge grade={overview.score.visibility_grade} />
                      <Box>
                        <Typography variant="h5" sx={{ fontWeight: 700 }}>
                          {(overview.score.visibility_pct * 100).toFixed(0)}%
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {overview.score.visible_count + overview.score.partial_count} of{' '}
                          {overview.score.assessable_count} assessable techniques seen
                        </Typography>
                      </Box>
                    </Stack>
                  </CardContent>
                </Card>
                <Card sx={{ flex: '1 1 220px', minWidth: 220 }}>
                  <CardContent sx={{ p: { xs: 2, md: 2.5 } }}>
                    <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 0.6 }}>
                      Data quality
                    </Typography>
                    <Stack direction="row" spacing={1.5} alignItems="center" sx={{ mt: 1 }}>
                      <GradeBadge grade={overview.score.quality_grade} />
                      <Box>
                        <Typography variant="h5" sx={{ fontWeight: 700 }}>
                          {overview.score.quality_avg.toFixed(1)}
                          <Typography component="span" color="text.secondary" variant="body2">
                            {' '}/ 5
                          </Typography>
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          mean DeTT&amp;CT score across collected sources
                        </Typography>
                      </Box>
                    </Stack>
                  </CardContent>
                </Card>
                <StatTile label="Assets" value={overview.asset_count} />
                <StatTile
                  label="Data sources"
                  value={overview.data_source_count}
                  sub={`${overview.enabled_data_source_count} enabled · ${overview.distinct_attack_sources} ATT&CK-mapped`}
                />
                <StatTile
                  label="Quality scored"
                  value={`${overview.scored_source_count}/${overview.data_source_count}`}
                  sub={`${overview.unscored_source_count} unscored`}
                  accent={overview.unscored_source_count ? coverage.amber : coverage.green}
                />
              </Stack>

              <Stack direction={{ xs: 'column', md: 'row' }} spacing={2.5} alignItems="stretch">
                <Card sx={{ flex: 1 }}>
                  <CardContent sx={{ p: { xs: 2, md: 2.5 } }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1.5 }}>
                      Assets by collection category
                    </Typography>
                    {Object.keys(overview.assets_by_category).length === 0 ? (
                      <Typography variant="body2" color="text.secondary">
                        No assets yet.
                      </Typography>
                    ) : (
                      <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                        {Object.entries(overview.assets_by_category)
                          .sort((a, b) => b[1] - a[1])
                          .map(([cat, n]) => (
                            <Chip key={cat} label={`${cat} · ${n}`} size="small" />
                          ))}
                      </Stack>
                    )}
                  </CardContent>
                </Card>
                <Card sx={{ flex: 1 }}>
                  <CardContent sx={{ p: { xs: 2, md: 2.5 } }}>
                    <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1.5 }}>
                      <LightbulbRoundedIcon fontSize="small" sx={{ color: coverage.amber }} />
                      <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                        Top collection gaps
                      </Typography>
                    </Stack>
                    {overview.top_recommendations.length === 0 ? (
                      <Typography variant="body2" color="text.secondary">
                        No outstanding gaps in scope — nice.
                      </Typography>
                    ) : (
                      <Stack spacing={1}>
                        {overview.top_recommendations.map((r) => (
                          <Stack
                            key={r.raw}
                            direction="row"
                            spacing={1}
                            alignItems="center"
                            justifyContent="space-between"
                          >
                            <Typography variant="body2" sx={{ fontWeight: 600 }}>
                              {r.raw}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              {r.touches} techniques
                            </Typography>
                          </Stack>
                        ))}
                        <Button size="small" sx={{ alignSelf: 'flex-start' }} onClick={() => setTab('recommendations')}>
                          View all recommendations
                        </Button>
                      </Stack>
                    )}
                  </CardContent>
                </Card>
              </Stack>
            </Stack>
          )}

          {tab === 'matrix' && matrix && (
            <Card>
              <CardContent sx={{ p: { xs: 2, md: 2.5 } }}>
                <MatrixView matrix={matrix} onSelect={setSelected} />
              </CardContent>
            </Card>
          )}

          {tab === 'recommendations' && (
            <Card>
              <CardContent sx={{ p: { xs: 2, md: 2.5 } }}>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
                  Data sources you don&apos;t collect yet, ranked by how many in-scope techniques each
                  would illuminate. <strong>Unlocks</strong> = techniques that become fully visible if
                  this is the only missing source.
                </Typography>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>ATT&amp;CK data source</TableCell>
                      <TableCell align="right">Techniques touched</TableCell>
                      <TableCell align="right">Unlocks</TableCell>
                      <TableCell>Examples</TableCell>
                      <TableCell align="right">Action</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {recs.length === 0 && (
                      <TableRow>
                        <TableCell colSpan={5}>
                          <Typography variant="body2" color="text.secondary">
                            No recommendations — everything in scope is at least partially visible.
                          </Typography>
                        </TableCell>
                      </TableRow>
                    )}
                    {recs.map((r) => (
                      <TableRow key={r.raw} hover>
                        <TableCell sx={{ fontWeight: 600 }}>{r.raw}</TableCell>
                        <TableCell align="right">{r.touches}</TableCell>
                        <TableCell align="right">{r.unlocks}</TableCell>
                        <TableCell>
                          <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'var(--font-mono, monospace)' }}>
                            {r.sample_technique_ids.join(', ')}
                          </Typography>
                        </TableCell>
                        <TableCell align="right">
                          <Button
                            size="small"
                            startIcon={<AddRoundedIcon />}
                            onClick={() => openAdd({ attack_data_source: r.raw, name: r.raw })}
                          >
                            Collect
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}

          {tab === 'register' && (
            <Card>
              <CardContent sx={{ p: { xs: 2, md: 2.5 } }}>
                <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1.5 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                    Collection register ({register.length})
                  </Typography>
                  <Button
                    variant="contained"
                    size="small"
                    startIcon={<AddRoundedIcon />}
                    onClick={() => openAdd()}
                    disabled={assets.length === 0}
                  >
                    Add data source
                  </Button>
                </Stack>
                {assets.length === 0 ? (
                  <Alert severity="info">
                    No assets yet — add assets in the customer profile first, then record what each
                    one collects here.
                  </Alert>
                ) : (
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Asset</TableCell>
                        <TableCell>Source</TableCell>
                        <TableCell>ATT&amp;CK data source</TableCell>
                        <TableCell>Log source</TableCell>
                        <TableCell align="right">Retention</TableCell>
                        <TableCell align="center">Quality</TableCell>
                        <TableCell align="center">On</TableCell>
                        <TableCell align="right" />
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {register.length === 0 && (
                        <TableRow>
                          <TableCell colSpan={8}>
                            <Typography variant="body2" color="text.secondary">
                              No collection sources recorded yet.
                            </Typography>
                          </TableCell>
                        </TableRow>
                      )}
                      {register.map((row) => {
                        const qv = avgQuality(row);
                        return (
                          <TableRow key={row.id} hover>
                            <TableCell>{row.asset_name}</TableCell>
                            <TableCell sx={{ fontWeight: 600 }}>{row.name}</TableCell>
                            <TableCell>{row.attack_data_source ?? '—'}</TableCell>
                            <TableCell>{row.log_source ?? '—'}</TableCell>
                            <TableCell align="right">
                              {row.retention_days != null ? `${row.retention_days}d` : '—'}
                            </TableCell>
                            <TableCell align="center">
                              {qv != null ? (
                                <Chip
                                  size="small"
                                  label={qv.toFixed(1)}
                                  sx={{ bgcolor: alpha(gradeColor(qv >= 4 ? 'A' : qv >= 3 ? 'B' : qv >= 2 ? 'C' : 'D'), 0.18) }}
                                />
                              ) : (
                                <Typography variant="caption" color="text.secondary">
                                  unscored
                                </Typography>
                              )}
                            </TableCell>
                            <TableCell align="center">
                              <Box
                                sx={{
                                  width: 10,
                                  height: 10,
                                  borderRadius: '50%',
                                  mx: 'auto',
                                  bgcolor: row.enabled ? coverage.green : coverage.grey,
                                }}
                              />
                            </TableCell>
                            <TableCell align="right">
                              <IconButton size="small" onClick={() => openEdit(row)}>
                                <EditRoundedIcon fontSize="small" />
                              </IconButton>
                              <IconButton size="small" onClick={() => removeRow(row)}>
                                <DeleteOutlineRoundedIcon fontSize="small" />
                              </IconButton>
                            </TableCell>
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>
          )}
        </>
      )}

      {/* technique visibility drawer */}
      <Drawer anchor="right" open={!!selected} onClose={() => setSelected(null)}>
        <Box sx={{ width: 380, p: 3 }}>
          {selected && (
            <Stack spacing={2}>
              <Stack direction="row" justifyContent="space-between" alignItems="flex-start">
                <Box>
                  <Typography variant="overline" sx={{ fontFamily: 'var(--font-mono, monospace)' }}>
                    {selected.technique_id}
                  </Typography>
                  <Typography variant="h6" sx={{ fontWeight: 700, lineHeight: 1.2 }}>
                    {selected.name}
                  </Typography>
                </Box>
                <IconButton size="small" onClick={() => setSelected(null)}>
                  <CloseRoundedIcon fontSize="small" />
                </IconButton>
              </Stack>
              <Chip
                label={VIS_STATE[selected.state].label}
                size="small"
                sx={{ alignSelf: 'flex-start', bgcolor: alpha(VIS_STATE[selected.state].color, 0.2) }}
              />
              {selected.quality_avg != null && (
                <Typography variant="body2" color="text.secondary">
                  Data quality of covering sources: <strong>{selected.quality_avg.toFixed(1)} / 5</strong>
                </Typography>
              )}
              <Divider />
              <Box>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                  Required ATT&amp;CK data sources
                </Typography>
                {selected.required.length === 0 ? (
                  <Typography variant="body2" color="text.secondary">
                    ATT&amp;CK lists no data sources for this technique — it can&apos;t be assessed via
                    collection.
                  </Typography>
                ) : (
                  <Stack spacing={0.75}>
                    {selected.required.map((rq) => {
                      const collected = !selected.missing.includes(rq);
                      return (
                        <Stack key={rq} direction="row" spacing={1} alignItems="center">
                          <Box
                            sx={{
                              width: 10,
                              height: 10,
                              borderRadius: '50%',
                              bgcolor: collected ? coverage.green : coverage.red,
                            }}
                          />
                          <Typography variant="body2">{rq}</Typography>
                          <Typography variant="caption" color="text.secondary">
                            {collected ? 'collected' : 'missing'}
                          </Typography>
                        </Stack>
                      );
                    })}
                  </Stack>
                )}
              </Box>
              {selected.missing.length > 0 && (
                <Button
                  variant="contained"
                  startIcon={<AddRoundedIcon />}
                  onClick={() => {
                    openAdd({ attack_data_source: selected.missing[0], name: selected.missing[0] });
                    setSelected(null);
                  }}
                >
                  Collect {selected.missing[0]}
                </Button>
              )}
              <Button
                size="small"
                endIcon={<OpenInNewRoundedIcon />}
                href={`https://attack.mitre.org/techniques/${selected.technique_id.replace('.', '/')}/`}
                target="_blank"
                rel="noopener"
              >
                ATT&amp;CK reference
              </Button>
            </Stack>
          )}
        </Box>
      </Drawer>

      <DataSourceDialog
        open={dialogOpen}
        onClose={() => setDialogOpen(false)}
        assets={assets}
        vocab={vocab}
        initial={dialogInitial}
        editing={editing}
        onSaved={() => Promise.all([loadRegister(), load()])}
      />
    </Stack>
  );
}
