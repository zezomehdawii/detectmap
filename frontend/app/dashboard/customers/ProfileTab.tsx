'use client';
import { apiErrorMessage, splitAttackDataSource, formatAttackDataSource, validRetention } from '@/lib/cmf-utils';

// Customer profile tab content: asset inventory + emergency contacts.
//
// The drawer is mounted from the MSSP-facing /dashboard/customers page,
// so every request goes out with an explicit X-Customer override (we
// don't want to flip the topbar switcher to read someone else's tenant
// data). The lib/api functions all accept an optional `customer` arg
// that wins over the global active-customer interceptor.

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Autocomplete,
  Box,
  Button,
  Card,
  CardContent,
  Checkbox,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  FormControlLabel,
  IconButton,
  InputAdornment,
  LinearProgress,
  ListItemText,
  MenuItem,
  Paper,
  Stack,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import AddRoundedIcon from '@mui/icons-material/AddRounded';
import CloudUploadRoundedIcon from '@mui/icons-material/CloudUploadRounded';
import DeleteOutlineRoundedIcon from '@mui/icons-material/DeleteOutlineRounded';
import DownloadRoundedIcon from '@mui/icons-material/DownloadRounded';
import EditRoundedIcon from '@mui/icons-material/EditRounded';
import ImageRoundedIcon from '@mui/icons-material/ImageRounded';
import InsertDriveFileRoundedIcon from '@mui/icons-material/InsertDriveFileRounded';
import LinkRoundedIcon from '@mui/icons-material/LinkRounded';
import PictureAsPdfRoundedIcon from '@mui/icons-material/PictureAsPdfRounded';
import SearchRoundedIcon from '@mui/icons-material/SearchRounded';
import StorageRoundedIcon from '@mui/icons-material/StorageRounded';
import StarRoundedIcon from '@mui/icons-material/StarRounded';
import StarBorderRoundedIcon from '@mui/icons-material/StarBorderRounded';
import WarningAmberRoundedIcon from '@mui/icons-material/WarningAmberRounded';

import {
  ASSET_COMPLIANCE_FRAMEWORKS,
  ASSET_CRITICALITIES,
  ASSET_DATA_CLASSIFICATIONS,
  ASSET_ENVIRONMENTS,
  ASSET_KINDS,
  ASSET_STATUSES,
  AssetDataSourceInput,
  AssetDataSourceOut,
  AssetDetectionRef,
  AssetImportResult,
  AssetOut,
  CMF_CATEGORIES,
  ContactOut,
  CustomerOut,
  DataSourceVocabItem,
  DetectionListItem,
  DiagramOut,
  createAsset,
  createAssetDataSource,
  createContact,
  deleteAsset,
  deleteAssetDataSource,
  deleteContact,
  deleteDiagram,
  downloadDiagramFile,
  fetchDiagramBlobUrl,
  importAssets,
  listAssetDataSources,
  listAssetDetections,
  listAssets,
  listAttackDataSourceVocab,
  listContacts,
  listDetections,
  listDiagrams,
  replaceAssetDetections,
  updateAsset,
  updateAssetDataSource,
  updateContact,
  updateDiagram,
  uploadDiagram,
} from '@/lib/api';
import AssetDiscovery from '../_components/AssetDiscovery';

const CRITICALITY_COLOR: Record<string, 'default' | 'success' | 'warning' | 'error'> = {
  low: 'default',
  medium: 'success',
  high: 'warning',
  critical: 'error',
};


export default function ProfileTab({ customer }: { customer: CustomerOut }) {
  const codename = customer.codename;
  const archived = customer.status === 'archived';

  return (
    <Stack spacing={4}>
      <AssetsSection codename={codename} status={customer.status} />
      <Divider />
      <DiagramsSection codename={codename} archived={archived} />
      <Divider />
      <ContactsSection codename={codename} archived={archived} />
    </Stack>
  );
}

// ---- Assets --------------------------------------------------------------

function AssetsSection({ codename, status }: { codename: string; status: string }) {
  const archived = status === 'archived';
  const [items, setItems] = useState<AssetOut[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<AssetOut | 'new' | null>(null);
  const [linking, setLinking] = useState<AssetOut | null>(null);
  const [managing, setManaging] = useState<AssetOut | null>(null);
  const [importing, setImporting] = useState(false);
  const [q, setQ] = useState('');
  const [criticality, setCriticality] = useState('');
  const [environment, setEnvironment] = useState('');

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const rows = await listAssets(
        {
          q: q || undefined,
          criticality: criticality || undefined,
          environment: environment || undefined,
        },
        codename,
      );
      setItems(rows);
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'failed to load assets');
    } finally {
      setLoading(false);
    }
  }, [codename, q, criticality, environment]);

  useEffect(() => {
    reload();
  }, [reload]);

  const criticalCount = useMemo(
    () => items.filter((a) => a.criticality === 'critical').length,
    [items],
  );

  return (
    <Box>
      <Stack direction="row" alignItems="center" spacing={1} mb={1.5} flexWrap="wrap" useFlexGap>
        <Box sx={{ flex: 1, minWidth: 200 }}>
          <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
            Collection Management Framework ({items.length})
          </Typography>
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>
            What the customer has, the data each asset collects, where it's
            stored and for how long — the basis for visibility and detection
            coverage. Critical systems are flagged separately.
          </Typography>
        </Box>
        {criticalCount > 0 && (
          <Chip
            icon={<WarningAmberRoundedIcon />}
            label={`${criticalCount} critical`}
            size="small"
            color="error"
            variant="outlined"
          />
        )}
        <AssetDiscovery customer={codename} disabled={status !== 'active'} onImported={reload} />
        <Button
          size="small"
          variant="outlined"
          startIcon={<CloudUploadRoundedIcon />}
          onClick={() => setImporting(true)}
          disabled={archived}
        >
          Import
        </Button>
        <Button
          size="small"
          variant="contained"
          startIcon={<AddRoundedIcon />}
          onClick={() => setEditing('new')}
          disabled={archived}
        >
          Add asset
        </Button>
      </Stack>

      <Stack direction="row" spacing={1.5} mb={1.5}>
        <TextField
          size="small"
          placeholder="Search name or hostname"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          sx={{ flex: 1 }}
        />
        <TextField
          select
          size="small"
          label="Criticality"
          value={criticality}
          onChange={(e) => setCriticality(e.target.value)}
          sx={{ minWidth: 130 }}
        >
          <MenuItem value="">All</MenuItem>
          {ASSET_CRITICALITIES.map((c) => (
            <MenuItem key={c} value={c}>{c}</MenuItem>
          ))}
        </TextField>
        <TextField
          select
          size="small"
          label="Environment"
          value={environment}
          onChange={(e) => setEnvironment(e.target.value)}
          sx={{ minWidth: 140 }}
        >
          <MenuItem value="">All</MenuItem>
          {ASSET_ENVIRONMENTS.map((e) => (
            <MenuItem key={e} value={e}>{e}</MenuItem>
          ))}
        </TextField>
      </Stack>

      {error && <Alert severity="error" sx={{ mb: 1 }}>{error}</Alert>}

      {loading ? (
        <Box sx={{ py: 4, display: 'flex', justifyContent: 'center' }}>
          <CircularProgress />
        </Box>
      ) : items.length === 0 ? (
        <Typography variant="body2" color="text.secondary" sx={{ py: 2 }}>
          No assets yet. Click <strong>Add asset</strong> to inventory the
          first system, or <strong>Import</strong> a CMF spreadsheet.
        </Typography>
      ) : (
        <TableContainer component={Paper} variant="outlined">
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Kind</TableCell>
                <TableCell sx={{ width: 100 }}>Criticality</TableCell>
                <TableCell>Function</TableCell>
                <TableCell sx={{ width: 110 }}>Data sources</TableCell>
                <TableCell sx={{ width: 140 }}>Coverage</TableCell>
                <TableCell sx={{ width: 150 }} align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {items.map((a) => (
                <TableRow key={a.id} hover>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontWeight: 500 }}>
                      {a.name}
                    </Typography>
                    {(a.hostname || a.ip_address) && (
                      <Typography
                        variant="caption"
                        color="text.secondary"
                        sx={{ fontFamily: 'JetBrains Mono, monospace' }}
                      >
                        {a.hostname ?? ''}{a.hostname && a.ip_address ? ' · ' : ''}{a.ip_address ?? ''}
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell>{a.kind.replace('_', ' ')}</TableCell>
                  <TableCell>
                    <Chip
                      label={a.criticality}
                      size="small"
                      color={CRITICALITY_COLOR[a.criticality] ?? 'default'}
                      variant={a.criticality === 'critical' ? 'filled' : 'outlined'}
                    />
                  </TableCell>
                  <TableCell>
                    <Typography variant="caption" sx={{ display: 'block' }}>
                      {a.business_function ?? '—'}
                    </Typography>
                    {a.cmf_category && (
                      <Chip
                        label={a.cmf_category}
                        size="small"
                        variant="outlined"
                        sx={{ height: 18, fontSize: 11, mt: 0.25 }}
                      />
                    )}
                  </TableCell>
                  <TableCell>
                    <Chip
                      size="small"
                      variant="outlined"
                      label={`${a.data_source_count} source${a.data_source_count === 1 ? '' : 's'}`}
                      icon={<StorageRoundedIcon sx={{ fontSize: 14 }} />}
                      color={a.data_source_count === 0 ? 'default' : 'primary'}
                    />
                  </TableCell>
                  <TableCell>
                    <Tooltip
                      title={`${a.coverage.deployed_detections} deployed · ${a.coverage.techniques_covered} techniques`}
                    >
                      <Chip
                        size="small"
                        variant="outlined"
                        label={`${a.coverage.linked_detections} rules`}
                        icon={<LinkRoundedIcon sx={{ fontSize: 14 }} />}
                      />
                    </Tooltip>
                  </TableCell>
                  <TableCell align="right">
                    <Tooltip title="Collection sources">
                      <IconButton size="small" onClick={() => setManaging(a)} disabled={archived}>
                        <StorageRoundedIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Manage linked detections">
                      <IconButton size="small" onClick={() => setLinking(a)} disabled={archived}>
                        <LinkRoundedIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Edit asset">
                      <IconButton size="small" onClick={() => setEditing(a)} disabled={archived}>
                        <EditRoundedIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Delete asset">
                      <span>
                        <IconButton
                          size="small"
                          color="error"
                          disabled={archived}
                          onClick={async () => {
                            if (!confirm(`Delete asset "${a.name}"?`)) return;
                            await deleteAsset(a.id, codename);
                            reload();
                          }}
                        >
                          <DeleteOutlineRoundedIcon fontSize="small" />
                        </IconButton>
                      </span>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      <AssetEditor
        codename={codename}
        target={editing}
        onClose={() => setEditing(null)}
        onSaved={() => {
          setEditing(null);
          reload();
        }}
      />
      <DetectionLinkerDialog
        codename={codename}
        asset={linking}
        onClose={() => {
          setLinking(null);
          reload();
        }}
      />
      <DataSourcesDialog
        codename={codename}
        asset={managing}
        archived={archived}
        onClose={() => {
          setManaging(null);
          reload();
        }}
      />
      {importing && (
        <ImportDialog
          codename={codename}
          onClose={() => setImporting(false)}
          onDone={() => {
            setImporting(false);
            reload();
          }}
        />
      )}
    </Box>
  );
}

// ---- Asset editor (create + edit, sliding right) -------------------------

function AssetEditor({
  codename,
  target,
  onClose,
  onSaved,
}: {
  codename: string;
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
        await createAsset(payload as any, codename);
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
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
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

// ---- Detection linker dialog -------------------------------------------

// Status / source vocab kept inline — the detections API enforces the
// same allow-list. Sentence case for labels per CLAUDE.md.
const LINKER_STATUSES = ['idea', 'in_development', 'tuning', 'deployed', 'gap', 'not_applicable'] as const;
const LINKER_SOURCES = ['global', 'customized', 'custom'] as const;
const LINKER_PAGE_SIZE = 50;

function DetectionLinkerDialog({
  codename,
  asset,
  onClose,
}: {
  codename: string;
  asset: AssetOut | null;
  onClose: () => void;
}) {
  const open = asset !== null;

  // What's currently saved on the server (mirrored on open so we can show
  // titles for items not on the current search page) + the analyst's
  // pending edits (added / removed). Save commits the diff via the
  // wholesale-replace endpoint.
  const [pendingIds, setPendingIds] = useState<Set<string>>(new Set());
  // Cache of detection metadata we've seen — populated from the initial
  // /assets/{id}/detections fetch + every search response. Used to
  // render titles/status/source in the "selected" panel even when an
  // item is no longer in view.
  const [metaCache, setMetaCache] = useState<
    Record<string, Pick<DetectionListItem, 'title' | 'sigma_id' | 'detection_status'>>
  >({});

  const [initialLoading, setInitialLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Search state.
  const [q, setQ] = useState('');
  const [qDebounced, setQDebounced] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [page, setPage] = useState(1);
  const [searchLoading, setSearchLoading] = useState(false);
  const [results, setResults] = useState<DetectionListItem[]>([]);
  const [resultsTotal, setResultsTotal] = useState(0);

  // Debounce title search — typing fires no requests for 300ms after the
  // last keystroke, then we run one query.
  useEffect(() => {
    const h = setTimeout(() => setQDebounced(q.trim()), 300);
    return () => clearTimeout(h);
  }, [q]);

  // Snap back to page 1 when filters change, otherwise we'd land mid-list
  // on a query with fewer pages.
  useEffect(() => {
    setPage(1);
  }, [qDebounced, statusFilter, sourceFilter]);

  // Initial: pull currently-linked rules so the dialog can mirror them
  // before the analyst touches anything.
  useEffect(() => {
    if (!open || !asset) return;
    let cancelled = false;
    setInitialLoading(true);
    setError(null);
    setPendingIds(new Set());
    setMetaCache({});
    setQ('');
    setQDebounced('');
    setStatusFilter('');
    setSourceFilter('');
    setPage(1);
    listAssetDetections(asset.id, codename)
      .then((rows) => {
        if (cancelled) return;
        setPendingIds(new Set(rows.map((r) => r.detection_id)));
        // Show the linked rule titles immediately, before the search completes.
        setMetaCache(
          Object.fromEntries(
            rows.map((r) => [
              r.detection_id,
              {
                sigma_id: r.sigma_id,
                title: r.title,
                detection_status: r.detection_status,
              },
            ]),
          ),
        );
      })
      .catch((e) => !cancelled && setError(e?.response?.data?.detail ?? 'failed to load links'))
      .finally(() => !cancelled && setInitialLoading(false));
    return () => {
      cancelled = true;
    };
  }, [open, asset?.id, codename]);

  // Search-driven list. Always runs when the dialog is open — the empty
  // search lists everything (paginated).
  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    setSearchLoading(true);
    listDetections(
      {
        q: qDebounced || undefined,
        status: statusFilter || undefined,
        source: sourceFilter || undefined,
        page,
        page_size: LINKER_PAGE_SIZE,
      },
      codename,
    )
      .then((res) => {
        if (cancelled) return;
        setResults(res.items);
        setResultsTotal(res.total);
        setMetaCache((prev) => {
          const next = { ...prev };
          for (const it of res.items) next[it.id] = it;
          return next;
        });
      })
      .catch((e) => !cancelled && setError(e?.response?.data?.detail ?? 'search failed'))
      .finally(() => !cancelled && setSearchLoading(false));
    return () => {
      cancelled = true;
    };
  }, [open, qDebounced, statusFilter, sourceFilter, page, codename]);

  function toggle(id: string) {
    setPendingIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  async function commit() {
    if (!asset) return;
    setSaving(true);
    setError(null);
    try {
      await replaceAssetDetections(asset.id, Array.from(pendingIds), codename);
      onClose();
    } catch (e: any) {
      const detail = e?.response?.data?.detail;
      setError(
        typeof detail === 'string'
          ? detail
          : detail?.detail
            ? `${detail.detail}: ${(detail.missing ?? []).join(', ')}`
            : 'save failed',
      );
    } finally {
      setSaving(false);
    }
  }

  const pageCount = Math.max(1, Math.ceil(resultsTotal / LINKER_PAGE_SIZE));
  const selected = Array.from(pendingIds);

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>Linked detections — {asset?.name ?? ''}</DialogTitle>
      <DialogContent dividers>
        {error && <Alert severity="error" sx={{ mb: 1.5 }}>{error}</Alert>}
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1.5 }}>
          Search the tenant's Sigma rules and toggle them in or out for
          this asset. Coverage stats — techniques covered, deployed-rule
          count — are computed from this list at read time.
        </Typography>

        <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} sx={{ minHeight: 440 }}>
          {/* ---- left: search + paginated results ---- */}
          <Box sx={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
            <Stack direction="row" spacing={1} sx={{ mb: 1 }}>
              <TextField
                size="small"
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Search title"
                sx={{ flex: 1 }}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchRoundedIcon fontSize="small" />
                    </InputAdornment>
                  ),
                }}
              />
              <TextField
                select
                size="small"
                label="Status"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                sx={{ minWidth: 140 }}
              >
                <MenuItem value="">All</MenuItem>
                {LINKER_STATUSES.map((s) => (
                  <MenuItem key={s} value={s}>{s}</MenuItem>
                ))}
              </TextField>
              <TextField
                select
                size="small"
                label="Source"
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value)}
                sx={{ minWidth: 130 }}
              >
                <MenuItem value="">All</MenuItem>
                {LINKER_SOURCES.map((s) => (
                  <MenuItem key={s} value={s}>{s}</MenuItem>
                ))}
              </TextField>
            </Stack>

            {searchLoading && <LinearProgress sx={{ mb: 0.5 }} />}

            <Paper
              variant="outlined"
              sx={{ flex: 1, overflow: 'auto', minHeight: 320, maxHeight: 360 }}
            >
              {results.length === 0 && !searchLoading ? (
                <Box sx={{ p: 3, textAlign: 'center' }}>
                  <Typography variant="body2" color="text.secondary">
                    {resultsTotal === 0
                      ? 'No detections in this tenant match the filters.'
                      : 'Loading…'}
                  </Typography>
                </Box>
              ) : (
                <Stack divider={<Divider />}>
                  {results.map((d) => {
                    const checked = pendingIds.has(d.id);
                    return (
                      <Stack
                        key={d.id}
                        direction="row"
                        alignItems="center"
                        spacing={1}
                        onClick={() => toggle(d.id)}
                        sx={{
                          px: 1,
                          py: 0.75,
                          cursor: 'pointer',
                          '&:hover': { bgcolor: 'action.hover' },
                          bgcolor: checked ? 'action.selected' : undefined,
                        }}
                      >
                        <Checkbox
                          size="small"
                          checked={checked}
                          onClick={(e) => e.stopPropagation()}
                          onChange={() => toggle(d.id)}
                        />
                        <Box sx={{ flex: 1, minWidth: 0 }}>
                          <Typography variant="body2" sx={{ fontWeight: 500 }} noWrap>
                            {d.title}
                          </Typography>
                          <Stack direction="row" spacing={0.75} alignItems="center" sx={{ mt: 0.25 }}>
                            <Typography
                              variant="caption"
                              color="text.secondary"
                              sx={{ fontFamily: 'JetBrains Mono, monospace' }}
                            >
                              {d.sigma_id.slice(0, 12)}…
                            </Typography>
                            <Chip size="small" variant="outlined" label={d.detection_status} />
                            <Chip size="small" variant="outlined" label={d.source} />
                            {d.techniques.length > 0 && (
                              <Typography variant="caption" color="text.secondary">
                                {d.techniques.length} technique{d.techniques.length === 1 ? '' : 's'}
                              </Typography>
                            )}
                          </Stack>
                        </Box>
                      </Stack>
                    );
                  })}
                </Stack>
              )}
            </Paper>

            <Stack direction="row" alignItems="center" spacing={1} sx={{ mt: 1 }}>
              <Typography variant="caption" color="text.secondary" sx={{ flex: 1 }}>
                {resultsTotal === 0
                  ? 'no results'
                  : `${resultsTotal.toLocaleString()} result${resultsTotal === 1 ? '' : 's'} · page ${page} / ${pageCount}`}
              </Typography>
              <Button
                size="small"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1 || searchLoading}
              >
                Prev
              </Button>
              <Button
                size="small"
                onClick={() => setPage((p) => Math.min(pageCount, p + 1))}
                disabled={page >= pageCount || searchLoading}
              >
                Next
              </Button>
            </Stack>
          </Box>

          {/* ---- right: selected pile ---- */}
          <Box sx={{ width: { xs: '100%', md: 320 }, display: 'flex', flexDirection: 'column' }}>
            <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
              Selected ({selected.length})
            </Typography>
            {initialLoading ? (
              <Box sx={{ py: 2, display: 'flex', justifyContent: 'center' }}>
                <CircularProgress size={20} />
              </Box>
            ) : selected.length === 0 ? (
              <Paper variant="outlined" sx={{ p: 2, textAlign: 'center' }}>
                <Typography variant="caption" color="text.secondary">
                  Pick rules from the list to link them here.
                </Typography>
              </Paper>
            ) : (
              <Paper
                variant="outlined"
                sx={{ flex: 1, overflow: 'auto', maxHeight: 420 }}
              >
                <Stack divider={<Divider />}>
                  {selected.map((id) => {
                    const meta = metaCache[id];
                    return (
                      <Stack
                        key={id}
                        direction="row"
                        alignItems="center"
                        sx={{ px: 1, py: 0.5 }}
                      >
                        <Box sx={{ flex: 1, minWidth: 0 }}>
                          <Typography variant="body2" noWrap sx={{ fontWeight: 500 }}>
                            {meta?.title ?? id}
                          </Typography>
                          <Typography
                            variant="caption"
                            color="text.secondary"
                            sx={{ fontFamily: 'JetBrains Mono, monospace' }}
                          >
                            {meta?.sigma_id?.slice(0, 12) ?? id.slice(0, 12)}…
                            {meta && ` · ${meta.detection_status}`}
                          </Typography>
                        </Box>
                        <IconButton
                          size="small"
                          color="error"
                          onClick={() => toggle(id)}
                        >
                          <DeleteOutlineRoundedIcon fontSize="small" />
                        </IconButton>
                      </Stack>
                    );
                  })}
                </Stack>
              </Paper>
            )}
          </Box>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={saving}>Cancel</Button>
        <Button variant="contained" onClick={commit} disabled={saving || initialLoading}>
          {saving ? <CircularProgress size={16} /> : 'Save links'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

// ---- Collection sources dialog (CMF) -------------------------------------

const QUALITY_DIMS: { key: keyof AssetDataSourceOut; label: string }[] = [
  { key: 'device_completeness_q', label: 'Device completeness' },
  { key: 'data_field_completeness_q', label: 'Data field completeness' },
  { key: 'timeliness_q', label: 'Timeliness' },
  { key: 'consistency_q', label: 'Consistency' },
  { key: 'retention_q', label: 'Retention' },
];

function QualitySelect({
  label,
  value,
  onChange,
}: {
  label: string;
  value: number | null;
  onChange: (v: number | null) => void;
}) {
  return (
    <TextField
      select
      size="small"
      label={label}
      value={value === null ? '' : String(value)}
      onChange={(e) => onChange(e.target.value === '' ? null : Number(e.target.value))}
      sx={{ flex: 1, minWidth: 130 }}
    >
      <MenuItem value=""><em>—</em></MenuItem>
      {[0, 1, 2, 3, 4, 5].map((n) => (
        <MenuItem key={n} value={String(n)}>{n}</MenuItem>
      ))}
    </TextField>
  );
}

function DataSourcesDialog({
  codename,
  asset,
  archived,
  onClose,
}: {
  codename: string;
  asset: AssetOut | null;
  archived: boolean;
  onClose: () => void;
}) {
  const open = asset !== null;
  const [items, setItems] = useState<AssetDataSourceOut[]>([]);
  const [vocab, setVocab] = useState<DataSourceVocabItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<AssetDataSourceOut | 'new' | null>(null);

  const reload = useCallback(async () => {
    if (!asset) return;
    setLoading(true);
    setError(null);
    try {
      setItems(await listAssetDataSources(asset.id, codename));
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'failed to load data sources');
    } finally {
      setLoading(false);
    }
  }, [asset?.id, codename]);

  useEffect(() => {
    if (open) reload();
  }, [open, reload]);

  // Vocab is global to the catalog — fetch once on first open and cache.
  useEffect(() => {
    if (!open || vocab.length) return;
    listAttackDataSourceVocab()
      .then(setVocab)
      .catch(() => {/* picker degrades to free text */});
  }, [open, vocab.length]);

  const remove = async (d: AssetDataSourceOut) => {
    if (!asset) return;
    if (!confirm(`Delete data source "${d.name}"?`)) return;
    try {
      await deleteAssetDataSource(asset.id, d.id, codename);
      await reload();
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'delete failed');
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="lg" fullWidth>
      <DialogTitle>Collection sources — {asset?.name ?? ''}</DialogTitle>
      <DialogContent dividers>
        <Stack direction="row" alignItems="center" spacing={1} mb={1.5}>
          <Typography variant="caption" color="text.secondary" sx={{ flex: 1 }}>
            The data this asset collects: what it is, where it's stored, how
            long, and the DeTT&amp;CT quality scores (0–5) that drive
            visibility coverage. Tag sources with ATT&amp;CK data-source names
            so they join back to the techniques they illuminate.
          </Typography>
          <Button
            size="small"
            variant="contained"
            startIcon={<AddRoundedIcon />}
            onClick={() => setEditing('new')}
            disabled={archived}
          >
            Add source
          </Button>
        </Stack>

        {error && <Alert severity="error" sx={{ mb: 1.5 }}>{error}</Alert>}

        {loading ? (
          <Box sx={{ py: 4, display: 'flex', justifyContent: 'center' }}>
            <CircularProgress />
          </Box>
        ) : items.length === 0 ? (
          <Paper variant="outlined" sx={{ p: 3, textAlign: 'center' }}>
            <Typography variant="body2" color="text.secondary">
              No collection sources yet. Add the logs and telemetry this asset
              produces.
            </Typography>
          </Paper>
        ) : (
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Name</TableCell>
                  <TableCell>ATT&amp;CK data source</TableCell>
                  <TableCell>Storage</TableCell>
                  <TableCell sx={{ width: 90 }} align="right">Retention</TableCell>
                  <TableCell sx={{ width: 80 }} align="center">Quality</TableCell>
                  <TableCell sx={{ width: 80 }} align="center">Enabled</TableCell>
                  <TableCell sx={{ width: 90 }} align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {items.map((d) => {
                  const scores = QUALITY_DIMS
                    .map((q) => d[q.key] as number | null)
                    .filter((v): v is number => v !== null);
                  const avg = scores.length
                    ? (scores.reduce((a, b) => a + b, 0) / scores.length).toFixed(1)
                    : '—';
                  const attack = d.attack_data_source
                    ? d.attack_data_component
                      ? `${d.attack_data_source}: ${d.attack_data_component}`
                      : d.attack_data_source
                    : '—';
                  return (
                    <TableRow key={d.id} hover>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontWeight: 500 }}>{d.name}</Typography>
                        {d.log_source && (
                          <Typography
                            variant="caption"
                            color="text.secondary"
                            sx={{ fontFamily: 'JetBrains Mono, monospace' }}
                          >
                            {d.log_source}
                          </Typography>
                        )}
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption">{attack}</Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption">{d.storage_location ?? '—'}</Typography>
                      </TableCell>
                      <TableCell align="right">
                        <Typography variant="caption">
                          {d.retention_days === null ? '—' : `${d.retention_days}d`}
                        </Typography>
                      </TableCell>
                      <TableCell align="center">
                        <Tooltip title="Mean DeTT&CT quality score">
                          <Typography variant="caption">{avg}</Typography>
                        </Tooltip>
                      </TableCell>
                      <TableCell align="center">
                        <Chip
                          size="small"
                          label={d.enabled ? 'on' : 'off'}
                          color={d.enabled ? 'success' : 'default'}
                          variant="outlined"
                          sx={{ height: 20 }}
                        />
                      </TableCell>
                      <TableCell align="right">
                        <IconButton size="small" onClick={() => setEditing(d)} disabled={archived}>
                          <EditRoundedIcon fontSize="small" />
                        </IconButton>
                        <IconButton size="small" color="error" onClick={() => remove(d)} disabled={archived}>
                          <DeleteOutlineRoundedIcon fontSize="small" />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
        )}

        {asset && (
          <DataSourceEditor
            codename={codename}
            assetId={asset.id}
            vocab={vocab}
            target={editing}
            onClose={() => setEditing(null)}
            onSaved={() => {
              setEditing(null);
              reload();
            }}
          />
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
}

function DataSourceEditor({
  codename,
  assetId,
  vocab,
  target,
  onClose,
  onSaved,
}: {
  codename: string;
  assetId: string;
  vocab: DataSourceVocabItem[];
  target: AssetDataSourceOut | 'new' | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const open = target !== null;
  const existing = target && target !== 'new' ? target : null;

  const [name, setName] = useState('');
  const [attackRaw, setAttackRaw] = useState('');
  const [logSource, setLogSource] = useState('');
  const [description, setDescription] = useState('');
  const [storageLocation, setStorageLocation] = useState('');
  const [killChainPhase, setKillChainPhase] = useState('');
  const [followOnCollection, setFollowOnCollection] = useState('');
  const [retentionDays, setRetentionDays] = useState('');
  const [quality, setQuality] = useState<Record<string, number | null>>({});
  const [enabled, setEnabled] = useState(true);
  const [notes, setNotes] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    if (existing) {
      setName(existing.name);
      setAttackRaw(formatAttackDataSource(existing.attack_data_source, existing.attack_data_component));
      setLogSource(existing.log_source ?? '');
      setDescription(existing.description ?? '');
      setStorageLocation(existing.storage_location ?? '');
      setKillChainPhase(existing.kill_chain_phase ?? '');
      setFollowOnCollection(existing.follow_on_collection ?? '');
      setRetentionDays(existing.retention_days === null ? '' : String(existing.retention_days));
      setQuality(
        Object.fromEntries(QUALITY_DIMS.map((q) => [q.key, existing[q.key] as number | null])),
      );
      setEnabled(existing.enabled);
      setNotes(existing.notes ?? '');
    } else {
      setName('');
      setAttackRaw('');
      setLogSource('');
      setDescription('');
      setStorageLocation('');
      setKillChainPhase('');
      setFollowOnCollection('');
      setRetentionDays('');
      setQuality({});
      setEnabled(true);
      setNotes('');
    }
    setError(null);
  }, [open, existing?.id]);

  async function save() {
    setSaving(true);
    setError(null);
    if (!validRetention(retentionDays === '' ? null : Number(retentionDays))) {
      setError('Retention must be a whole number of days, zero or greater.');
      setSaving(false);
      return;
    }
    const mapping = splitAttackDataSource(attackRaw);
    const payload: AssetDataSourceInput = {
      name: name.trim(),
      ...mapping,
      log_source: logSource || null,
      description: description || null,
      storage_location: storageLocation || null,
      kill_chain_phase: killChainPhase || null,
      follow_on_collection: followOnCollection || null,
      retention_days: retentionDays === '' ? null : Number(retentionDays),
      device_completeness_q: quality.device_completeness_q ?? null,
      data_field_completeness_q: quality.data_field_completeness_q ?? null,
      timeliness_q: quality.timeliness_q ?? null,
      consistency_q: quality.consistency_q ?? null,
      retention_q: quality.retention_q ?? null,
      enabled,
      notes: notes || null,
    };
    try {
      if (existing) {
        await updateAssetDataSource(assetId, existing.id, payload, codename);
      } else {
        await createAssetDataSource(assetId, payload, codename);
      }
      onSaved();
    } catch (e: any) {
      setError(apiErrorMessage(e, 'Save failed.'));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{existing ? `Edit ${existing.name}` : 'Add collection source'}</DialogTitle>
      <DialogContent dividers>
        <Stack spacing={2} sx={{ pt: 1 }}>
          {error && <Alert severity="error">{error}</Alert>}
          <TextField
            size="small"
            label="Name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            placeholder="Windows Security event logs"
          />
          <Autocomplete
            freeSolo
            options={vocab.map((v) => v.raw)}
            inputValue={attackRaw}
            onInputChange={(_, v) => setAttackRaw(v)}
            renderInput={(params) => (
              <TextField
                {...params}
                size="small"
                label="ATT&CK data source"
                helperText="Pick a canonical name (Source: Component) so it joins to coverage, or type your own."
              />
            )}
          />
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5}>
            <TextField
              size="small"
              label="Log source"
              value={logSource}
              onChange={(e) => setLogSource(e.target.value)}
              sx={{ flex: 1 }}
              placeholder="windows/security"
            />
            <TextField
              size="small"
              label="Storage location"
              value={storageLocation}
              onChange={(e) => setStorageLocation(e.target.value)}
              sx={{ flex: 1 }}
              placeholder="index=wineventlog"
            />
            <TextField
              size="small"
              label="Retention (days)"
              type="number"
              value={retentionDays}
              onChange={(e) => setRetentionDays(e.target.value)}
              sx={{ width: 140 }}
              inputProps={{ min: 0, step: 1 }}
            />
          </Stack>
          <TextField size="small" label="Kill chain phase" value={killChainPhase}
            onChange={(e) => setKillChainPhase(e.target.value)} />
          <TextField size="small" label="Follow-on collection" multiline minRows={2}
            value={followOnCollection} onChange={(e) => setFollowOnCollection(e.target.value)} />
          <Typography variant="overline" sx={{ color: 'text.secondary', fontWeight: 700 }}>
            DeTT&amp;CT data quality (0–5)
          </Typography>
          <Stack direction="row" spacing={1.5} flexWrap="wrap" useFlexGap>
            {QUALITY_DIMS.map((q) => (
              <QualitySelect
                key={q.key}
                label={q.label}
                value={quality[q.key] ?? null}
                onChange={(v) => setQuality((prev) => ({ ...prev, [q.key]: v }))}
              />
            ))}
          </Stack>
          <TextField
            size="small"
            label="Description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            multiline
            minRows={2}
          />
          <FormControlLabel
            control={<Switch checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />}
            label="Enabled (counts toward visibility coverage)"
          />
          <TextField
            size="small"
            label="Notes"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            multiline
            minRows={2}
          />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={saving}>Cancel</Button>
        <Button variant="contained" onClick={save} disabled={saving || name.trim().length < 1}>
          {saving ? <CircularProgress size={16} /> : existing ? 'Save' : 'Create'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

// ---- Import dialog (CMF bulk import) -------------------------------------

const IMPORT_EXAMPLE = `[
  {
    "name": "DC-01",
    "kind": "server",
    "criticality": "critical",
    "cmf_category": "identity",
    "external_id": "cmdb-1024",
    "data_sources": [
      {
        "name": "Windows Security event logs",
        "attack_data_source": "Logon Session",
        "attack_data_component": "Logon Session Creation",
        "log_source": "windows/security",
        "storage_location": "index=wineventlog",
        "retention_days": 90,
        "device_completeness_q": 4
      }
    ]
  }
]`;

function ImportDialog({
  codename,
  onClose,
  onDone,
}: {
  codename: string;
  onClose: () => void;
  onDone: () => void;
}) {
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AssetImportResult | null>(null);

  const onFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = () => setText(String(reader.result ?? ''));
    reader.readAsText(f);
  };

  const run = async () => {
    setBusy(true);
    setError(null);
    setResult(null);
    let rows: any;
    try {
      rows = JSON.parse(text);
    } catch {
      setError('Not valid JSON. Paste a JSON array of assets.');
      setBusy(false);
      return;
    }
    if (!Array.isArray(rows)) {
      setError('Top-level JSON must be an array of asset objects.');
      setBusy(false);
      return;
    }
    try {
      const res = await importAssets(rows, codename);
      setResult(res);
    } catch (e: any) {
      const detail = e?.response?.data?.detail;
      setError(typeof detail === 'string' ? detail : 'import failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>Import Collection Management Framework</DialogTitle>
      <DialogContent dividers>
        <Stack spacing={2}>
          <Typography variant="caption" color="text.secondary">
            Paste a JSON array of assets (each may carry a{' '}
            <code>data_sources</code> array). Rows are matched on{' '}
            <code>external_id</code>: a match updates the asset to the imported
            values; rows without one always create. Data sources are appended
            by name — existing ones are left untouched.
          </Typography>
          <Button component="label" variant="outlined" size="small" sx={{ alignSelf: 'flex-start' }}>
            Load .json file
            <input type="file" hidden accept="application/json,.json" onChange={onFile} />
          </Button>
          <TextField
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={IMPORT_EXAMPLE}
            multiline
            minRows={10}
            maxRows={20}
            sx={{ '& textarea': { fontFamily: 'JetBrains Mono, monospace', fontSize: 12 } }}
          />
          {error && <Alert severity="error">{error}</Alert>}
          {result && (
            <Alert severity={result.errors.length ? 'warning' : 'success'}>
              Imported: {result.created} created, {result.updated} updated,{' '}
              {result.data_sources_added} data source(s) added.
              {result.errors.length > 0 && (
                <Box component="ul" sx={{ mt: 1, mb: 0, pl: 2 }}>
                  {result.errors.slice(0, 10).map((er, i) => (
                    <li key={i}>
                      <Typography variant="caption">
                        row {er.row}{er.name ? ` (${er.name})` : ''}:{' '}
                        {typeof er.error === 'string' ? er.error : JSON.stringify(er.error)}
                      </Typography>
                    </li>
                  ))}
                  {result.errors.length > 10 && (
                    <li><Typography variant="caption">…and {result.errors.length - 10} more</Typography></li>
                  )}
                </Box>
              )}
            </Alert>
          )}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={result ? onDone : onClose} disabled={busy}>
          {result ? 'Done' : 'Cancel'}
        </Button>
        <Button variant="contained" onClick={run} disabled={busy || !text.trim()}>
          {busy ? <CircularProgress size={16} /> : 'Import'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

// ---- Contacts ------------------------------------------------------------

function ContactsSection({ codename, archived }: { codename: string; archived: boolean }) {
  const [items, setItems] = useState<ContactOut[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<ContactOut | 'new' | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const rows = await listContacts(codename);
      setItems(rows);
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'failed to load contacts');
    } finally {
      setLoading(false);
    }
  }, [codename]);

  useEffect(() => {
    reload();
  }, [reload]);

  return (
    <Box>
      <Stack direction="row" alignItems="center" spacing={1} mb={1.5}>
        <Box sx={{ flex: 1 }}>
          <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
            Emergency contacts ({items.length})
          </Typography>
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>
            People at the customer to reach during an incident. Mark one
            primary — that's the first call.
          </Typography>
        </Box>
        <Button
          size="small"
          variant="contained"
          startIcon={<AddRoundedIcon />}
          onClick={() => setEditing('new')}
          disabled={archived}
        >
          Add contact
        </Button>
      </Stack>

      {error && <Alert severity="error" sx={{ mb: 1 }}>{error}</Alert>}

      {loading ? (
        <Box sx={{ py: 4, display: 'flex', justifyContent: 'center' }}>
          <CircularProgress />
        </Box>
      ) : items.length === 0 ? (
        <Typography variant="body2" color="text.secondary" sx={{ py: 2 }}>
          No contacts yet.
        </Typography>
      ) : (
        <Stack spacing={1}>
          {items.map((c) => (
            <Card key={c.id} variant="outlined">
              <CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}>
                <Stack direction="row" alignItems="flex-start" spacing={1.5}>
                  <Box sx={{ flex: 1 }}>
                    <Stack direction="row" alignItems="center" spacing={1}>
                      {c.is_primary ? (
                        <StarRoundedIcon fontSize="small" color="warning" />
                      ) : (
                        <StarBorderRoundedIcon fontSize="small" color="action" />
                      )}
                      <Typography variant="body2" sx={{ fontWeight: 600 }}>
                        {c.name}
                      </Typography>
                      {c.role && (
                        <Typography variant="caption" color="text.secondary">
                          · {c.role}
                        </Typography>
                      )}
                    </Stack>
                    <Stack direction="row" spacing={2} sx={{ mt: 0.5 }} flexWrap="wrap" useFlexGap>
                      {c.email && (
                        <Typography variant="caption">
                          ✉ {c.email}
                        </Typography>
                      )}
                      {c.phone && (
                        <Typography variant="caption">
                          ☎ {c.phone}
                        </Typography>
                      )}
                      {c.office_address && (
                        <Typography variant="caption" color="text.secondary">
                          🏢 {c.office_address}
                        </Typography>
                      )}
                    </Stack>
                  </Box>
                  <IconButton size="small" onClick={() => setEditing(c)} disabled={archived}>
                    <EditRoundedIcon fontSize="small" />
                  </IconButton>
                  <IconButton
                    size="small"
                    color="error"
                    disabled={archived}
                    onClick={async () => {
                      if (!confirm(`Delete contact "${c.name}"?`)) return;
                      await deleteContact(c.id, codename);
                      reload();
                    }}
                  >
                    <DeleteOutlineRoundedIcon fontSize="small" />
                  </IconButton>
                </Stack>
              </CardContent>
            </Card>
          ))}
        </Stack>
      )}

      <ContactEditor
        codename={codename}
        target={editing}
        onClose={() => setEditing(null)}
        onSaved={() => {
          setEditing(null);
          reload();
        }}
      />
    </Box>
  );
}

function ContactEditor({
  codename,
  target,
  onClose,
  onSaved,
}: {
  codename: string;
  target: ContactOut | 'new' | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const open = target !== null;
  const existing = target && target !== 'new' ? target : null;

  const [name, setName] = useState('');
  const [role, setRole] = useState('');
  const [email, setEmail] = useState('');
  const [phone, setPhone] = useState('');
  const [office, setOffice] = useState('');
  const [isPrimary, setIsPrimary] = useState(false);
  const [notes, setNotes] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (existing) {
      setName(existing.name);
      setRole(existing.role ?? '');
      setEmail(existing.email ?? '');
      setPhone(existing.phone ?? '');
      setOffice(existing.office_address ?? '');
      setIsPrimary(existing.is_primary);
      setNotes(existing.notes ?? '');
    } else if (open) {
      setName('');
      setRole('');
      setEmail('');
      setPhone('');
      setOffice('');
      setIsPrimary(false);
      setNotes('');
    }
    setError(null);
  }, [open, existing?.id]);

  async function save() {
    setSaving(true);
    setError(null);
    const payload = {
      name: name.trim(),
      role: role || undefined,
      email: email || undefined,
      phone: phone || undefined,
      office_address: office || undefined,
      is_primary: isPrimary,
      notes: notes || undefined,
    };
    try {
      if (existing) {
        await updateContact(existing.id, payload, codename);
      } else {
        await createContact(payload, codename);
      }
      onSaved();
    } catch (e: any) {
      const detail = e?.response?.data?.detail;
      setError(typeof detail === 'string' ? detail : 'save failed');
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{existing ? `Edit ${existing.name}` : 'Add contact'}</DialogTitle>
      <DialogContent dividers>
        <Stack spacing={2} sx={{ pt: 1 }}>
          {error && <Alert severity="error">{error}</Alert>}
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5}>
            <TextField
              size="small"
              label="Name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              sx={{ flex: 2 }}
            />
            <TextField
              size="small"
              label="Role"
              value={role}
              onChange={(e) => setRole(e.target.value)}
              sx={{ flex: 1 }}
              placeholder="SOC lead"
            />
          </Stack>
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5}>
            <TextField
              size="small"
              label="Email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              sx={{ flex: 1 }}
            />
            <TextField
              size="small"
              label="Phone"
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
              sx={{ flex: 1 }}
            />
          </Stack>
          <TextField
            size="small"
            label="Office address"
            value={office}
            onChange={(e) => setOffice(e.target.value)}
            multiline
            minRows={2}
          />
          <FormControlLabel
            control={
              <Switch
                checked={isPrimary}
                onChange={(e) => setIsPrimary(e.target.checked)}
              />
            }
            label="Primary contact"
          />
          <TextField
            label="Notes"
            size="small"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            multiline
            minRows={2}
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
          {saving ? <CircularProgress size={16} /> : existing ? 'Save' : 'Create'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

// ---- Diagrams ------------------------------------------------------------

const MAX_DIAGRAM_BYTES = 50 * 1024 * 1024; // mirrors backend settings cap.

function bytesHuman(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function DiagramsSection({ codename, archived }: { codename: string; archived: boolean }) {
  const [items, setItems] = useState<DiagramOut[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [uploaderOpen, setUploaderOpen] = useState(false);
  const [renaming, setRenaming] = useState<DiagramOut | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setItems(await listDiagrams(codename));
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'failed to load diagrams');
    } finally {
      setLoading(false);
    }
  }, [codename]);

  useEffect(() => {
    reload();
  }, [reload]);

  const togglePrimary = async (d: DiagramOut) => {
    try {
      await updateDiagram(d.id, { is_primary: !d.is_primary }, codename);
      await reload();
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'failed to update diagram');
    }
  };

  const remove = async (d: DiagramOut) => {
    if (!confirm(`Delete diagram "${d.title}"?`)) return;
    try {
      await deleteDiagram(d.id, codename);
      await reload();
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'failed to delete diagram');
    }
  };

  return (
    <Box>
      <Stack direction="row" alignItems="center" spacing={1} mb={1.5}>
        <Box sx={{ flex: 1 }}>
          <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
            Network diagrams ({items.length})
          </Typography>
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>
            Topology, dataflow, or operational diagrams. Images and PDFs
            render inline; other formats (Visio, Packet Tracer, etc.) are
            available for download.
          </Typography>
        </Box>
        <Button
          size="small"
          variant="contained"
          startIcon={<CloudUploadRoundedIcon />}
          onClick={() => setUploaderOpen(true)}
          disabled={archived}
        >
          Upload diagram
        </Button>
      </Stack>

      {error && <Alert severity="error" sx={{ mb: 1.5 }}>{error}</Alert>}

      {loading ? (
        <Stack alignItems="center" p={4}><CircularProgress size={24} /></Stack>
      ) : items.length === 0 ? (
        <Paper variant="outlined" sx={{ p: 3, textAlign: 'center' }}>
          <Typography variant="body2" color="text.secondary">
            No diagrams yet. Upload a network or dataflow diagram to
            surface it on this profile.
          </Typography>
        </Paper>
      ) : (
        <Stack
          direction="row"
          flexWrap="wrap"
          useFlexGap
          spacing={2}
        >
          {items.map((d) => (
            <DiagramCard
              key={d.id}
              diagram={d}
              codename={codename}
              archived={archived}
              onTogglePrimary={() => togglePrimary(d)}
              onRename={() => setRenaming(d)}
              onDelete={() => remove(d)}
            />
          ))}
        </Stack>
      )}

      {uploaderOpen && (
        <DiagramUploader
          codename={codename}
          onClose={() => setUploaderOpen(false)}
          onSaved={async () => {
            setUploaderOpen(false);
            await reload();
          }}
        />
      )}

      {renaming && (
        <DiagramRenamer
          diagram={renaming}
          codename={codename}
          onClose={() => setRenaming(null)}
          onSaved={async () => {
            setRenaming(null);
            await reload();
          }}
        />
      )}
    </Box>
  );
}

function DiagramCard({
  diagram,
  codename,
  archived,
  onTogglePrimary,
  onRename,
  onDelete,
}: {
  diagram: DiagramOut;
  codename: string;
  archived: boolean;
  onTogglePrimary: () => void;
  onRename: () => void;
  onDelete: () => void;
}) {
  // Image / PDF preview is fetched as a blob URL because <img src> can't
  // carry the bearer token. Revoke on unmount so we don't leak memory
  // when the parent reloads the list (each remount creates a new URL).
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [previewError, setPreviewError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    let url: string | null = null;
    if (diagram.kind === 'image' || diagram.kind === 'pdf') {
      fetchDiagramBlobUrl(diagram.id, codename)
        .then((u) => {
          if (cancelled) {
            URL.revokeObjectURL(u);
            return;
          }
          url = u;
          setPreviewUrl(u);
        })
        .catch(() => {
          if (!cancelled) setPreviewError(true);
        });
    }
    return () => {
      cancelled = true;
      if (url) URL.revokeObjectURL(url);
    };
  }, [diagram.id, diagram.kind, codename]);

  const icon =
    diagram.kind === 'image' ? <ImageRoundedIcon fontSize="small" />
    : diagram.kind === 'pdf' ? <PictureAsPdfRoundedIcon fontSize="small" />
    : <InsertDriveFileRoundedIcon fontSize="small" />;

  return (
    <Card variant="outlined" sx={{ width: 280, display: 'flex', flexDirection: 'column' }}>
      <Box
        sx={{
          height: 160,
          bgcolor: 'action.hover',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          overflow: 'hidden',
        }}
      >
        {diagram.kind === 'image' && previewUrl && !previewError ? (
          // eslint-disable-next-line @next/next/no-img-element
          <img
            src={previewUrl}
            alt={diagram.title}
            style={{ maxWidth: '100%', maxHeight: '100%', objectFit: 'contain' }}
          />
        ) : diagram.kind === 'pdf' && previewUrl && !previewError ? (
          <embed
            src={previewUrl}
            type="application/pdf"
            style={{ width: '100%', height: '100%' }}
          />
        ) : diagram.kind === 'image' || diagram.kind === 'pdf' ? (
          <CircularProgress size={20} />
        ) : (
          <Stack alignItems="center" spacing={0.5}>
            <InsertDriveFileRoundedIcon sx={{ fontSize: 40, color: 'text.disabled' }} />
            <Typography variant="caption" color="text.secondary">
              {diagram.mime_type || 'binary'}
            </Typography>
          </Stack>
        )}
      </Box>
      <CardContent sx={{ p: 1.5, flex: 1, display: 'flex', flexDirection: 'column' }}>
        <Stack direction="row" alignItems="flex-start" spacing={1}>
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Typography
              variant="subtitle2"
              noWrap
              title={diagram.title}
              sx={{ fontWeight: 600 }}
            >
              {diagram.title}
            </Typography>
            <Stack direction="row" alignItems="center" spacing={0.5} mt={0.25}>
              {icon}
              <Typography variant="caption" color="text.secondary" noWrap>
                {diagram.filename} · {bytesHuman(diagram.size_bytes)}
              </Typography>
            </Stack>
          </Box>
          <Tooltip title={diagram.is_primary ? 'Primary diagram' : 'Set as primary'}>
            <IconButton size="small" onClick={onTogglePrimary} disabled={archived}>
              {diagram.is_primary ? (
                <StarRoundedIcon fontSize="small" sx={{ color: 'warning.main' }} />
              ) : (
                <StarBorderRoundedIcon fontSize="small" />
              )}
            </IconButton>
          </Tooltip>
        </Stack>
        {diagram.description && (
          <Typography
            variant="caption"
            color="text.secondary"
            sx={{
              mt: 0.5,
              display: '-webkit-box',
              WebkitLineClamp: 2,
              WebkitBoxOrient: 'vertical',
              overflow: 'hidden',
            }}
          >
            {diagram.description}
          </Typography>
        )}
        <Stack direction="row" spacing={0.5} mt="auto" pt={1} justifyContent="flex-end">
          <Tooltip title="Download">
            <IconButton
              size="small"
              onClick={() => downloadDiagramFile(diagram, codename)}
            >
              <DownloadRoundedIcon fontSize="small" />
            </IconButton>
          </Tooltip>
          <Tooltip title="Rename / edit">
            <IconButton size="small" onClick={onRename} disabled={archived}>
              <EditRoundedIcon fontSize="small" />
            </IconButton>
          </Tooltip>
          <Tooltip title="Delete">
            <IconButton size="small" onClick={onDelete} disabled={archived}>
              <DeleteOutlineRoundedIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Stack>
      </CardContent>
    </Card>
  );
}

function DiagramUploader({
  codename,
  onClose,
  onSaved,
}: {
  codename: string;
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [isPrimary, setIsPrimary] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0] ?? null;
    if (f && f.size > MAX_DIAGRAM_BYTES) {
      setError(`File too large (${bytesHuman(f.size)}; max ${bytesHuman(MAX_DIAGRAM_BYTES)})`);
      setFile(null);
      return;
    }
    setError(null);
    setFile(f);
    // Pre-fill the title from the filename so the user can hit Save fast.
    if (f && !title) setTitle(f.name.replace(/\.[^.]+$/, ''));
  };

  const save = async () => {
    if (!file || !title.trim()) return;
    setSaving(true);
    setError(null);
    try {
      await uploadDiagram(
        {
          file,
          title: title.trim(),
          description: description.trim() || undefined,
          is_primary: isPrimary,
        },
        codename,
      );
      await onSaved();
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'upload failed');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Upload diagram</DialogTitle>
      <DialogContent>
        <Stack spacing={2} mt={0.5}>
          {error && <Alert severity="error">{error}</Alert>}
          <Button
            variant="outlined"
            component="label"
            startIcon={<CloudUploadRoundedIcon />}
            sx={{ alignSelf: 'flex-start' }}
          >
            {file ? 'Choose a different file' : 'Choose file'}
            <input type="file" hidden onChange={onFileChange} />
          </Button>
          {file && (
            <Typography variant="caption" color="text.secondary">
              {file.name} · {bytesHuman(file.size)} · {file.type || 'binary'}
            </Typography>
          )}
          <TextField
            label="Title"
            size="small"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            required
          />
          <TextField
            label="Description"
            size="small"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            multiline
            minRows={2}
          />
          <FormControlLabel
            control={
              <Switch
                checked={isPrimary}
                onChange={(e) => setIsPrimary(e.target.checked)}
              />
            }
            label="Primary diagram (cover for this profile)"
          />
          <Typography variant="caption" color="text.secondary">
            Images and PDFs render inline. Other formats — Visio, Cisco
            Packet Tracer, draw.io, zip — upload fine and surface as
            download links. Max {bytesHuman(MAX_DIAGRAM_BYTES)}.
          </Typography>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={saving}>Cancel</Button>
        <Button
          variant="contained"
          onClick={save}
          disabled={saving || !file || !title.trim()}
        >
          {saving ? <CircularProgress size={16} /> : 'Upload'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function DiagramRenamer({
  diagram,
  codename,
  onClose,
  onSaved,
}: {
  diagram: DiagramOut;
  codename: string;
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const [title, setTitle] = useState(diagram.title);
  const [description, setDescription] = useState(diagram.description ?? '');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const save = async () => {
    if (!title.trim()) return;
    setSaving(true);
    setError(null);
    try {
      await updateDiagram(
        diagram.id,
        {
          title: title.trim(),
          description: description.trim() || null,
        },
        codename,
      );
      await onSaved();
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'save failed');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Edit diagram</DialogTitle>
      <DialogContent>
        <Stack spacing={2} mt={0.5}>
          {error && <Alert severity="error">{error}</Alert>}
          <Typography variant="caption" color="text.secondary">
            {diagram.filename} · {bytesHuman(diagram.size_bytes)} · {diagram.mime_type}
          </Typography>
          <TextField
            label="Title"
            size="small"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            required
          />
          <TextField
            label="Description"
            size="small"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            multiline
            minRows={2}
          />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={saving}>Cancel</Button>
        <Button
          variant="contained"
          onClick={save}
          disabled={saving || !title.trim()}
        >
          {saving ? <CircularProgress size={16} /> : 'Save'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
