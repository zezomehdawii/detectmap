'use client';

import { Fragment, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Checkbox,
  Chip,
  CircularProgress,
  Divider,
  Drawer,
  IconButton,
  MenuItem,
  Pagination,
  Paper,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from '@mui/material';
import CloseRoundedIcon from '@mui/icons-material/CloseRounded';
import FilterAltOffRoundedIcon from '@mui/icons-material/FilterAltOffRounded';
import {
  DetectionDetail,
  DetectionListItem,
  bulkDeleteDetections,
  bulkDetectionStatus,
  getDetection,
  listDetections,
  patchDetection,
} from '@/lib/api';
import { FeatureGate, useFeatures } from '@/lib/features';
import { useDeployment } from '@/lib/deployment';
import { useUserPrefs } from '@/lib/preferences';

const STATUS_OPTIONS = [
  'idea',
  'in_development',
  'tuning',
  'deployed',
  'gap',
  'not_applicable',
];
import { DetectionDrawerExtras, SuggestionsStrip } from './DetectionExtras';
import { DetectionReviewPanel } from './ReviewPanel';

const SOURCE_LABELS: Record<string, { label: string; color: 'default' | 'primary' | 'success' | 'warning' }> = {
  global: { label: 'global', color: 'default' },
  customized: { label: 'customized', color: 'warning' },
  custom: { label: 'custom', color: 'primary' },
};

const STATUS_LABELS: Record<string, { color: 'default' | 'primary' | 'success' | 'warning' | 'error' }> = {
  idea: { color: 'default' },
  in_development: { color: 'primary' },
  tuning: { color: 'warning' },
  deployed: { color: 'success' },
  gap: { color: 'error' },
  not_applicable: { color: 'default' },
};

const REVIEW_LABELS: Record<
  string,
  { label: string; color: 'default' | 'primary' | 'success' | 'warning' }
> = {
  draft: { label: 'Draft', color: 'default' },
  in_review: { label: 'In review', color: 'primary' },
  approved: { label: 'Approved', color: 'success' },
  changes_requested: { label: 'Changes requested', color: 'warning' },
};

// ---- Sigma YAML syntax highlighting ----------------------------------------
// Dependency-free, line-based highlighter for the rule preview. Each token
// gets a class; the actual colors come from CSS custom properties set on the
// container, with light + dark variants applied via theme.applyStyles so the
// palette tracks the active color mode (theme.palette.mode is frozen under
// MUI cssVariables, so per-token JS branching would not switch).

type YamlToken = { text: string; cls?: keyof typeof YAML_CLS };

const YAML_CLS = {
  key: 'yk',
  string: 'ys',
  number: 'yn',
  bool: 'yb',
  comment: 'yc',
  punct: 'yp',
  value: 'yv',
} as const;

function classifyScalar(v: string): YamlToken['cls'] {
  if (/^(['"]).*\1$/.test(v)) return 'string';
  if (/^(true|false|null|~|yes|no|on|off)$/i.test(v)) return 'bool';
  if (/^[+-]?\d+(\.\d+)?([eE][+-]?\d+)?$/.test(v)) return 'number';
  return 'value';
}

function tokenizeYamlValue(value: string): YamlToken[] {
  if (value === '') return [];
  // Split a trailing inline comment ( foo  # note ) off first.
  const ci = value.search(/\s#/);
  if (ci >= 0) {
    return [
      ...tokenizeYamlValue(value.slice(0, ci)),
      { text: value.slice(ci), cls: 'comment' },
    ];
  }
  const v = value.trim();
  if (v === '') return [{ text: value }];
  const start = value.indexOf(v);
  const out: YamlToken[] = [];
  if (start > 0) out.push({ text: value.slice(0, start) });
  out.push({ text: v, cls: classifyScalar(v) });
  const tail = value.slice(start + v.length);
  if (tail) out.push({ text: tail });
  return out;
}

function tokenizeYamlLine(line: string): YamlToken[] {
  if (line.trimStart().startsWith('#')) return [{ text: line, cls: 'comment' }];

  const tokens: YamlToken[] = [];
  // Leading indent + a single "- " list marker.
  const lead = line.match(/^(\s*)(-\s+)?(.*)$/);
  let body = line;
  if (lead) {
    const [, indent, dash, rest] = lead;
    if (indent) tokens.push({ text: indent });
    if (dash) tokens.push({ text: dash, cls: 'punct' });
    body = rest;
  }

  // key: value  — the colon must be followed by whitespace or end-of-line to
  // be a real YAML mapping key (so "https://..." is not split as a key).
  const kv = body.match(/^([^\s#][^:]*?)(:)(\s+|$)(.*)$/);
  if (kv) {
    const [, key, colon, ws, value] = kv;
    tokens.push({ text: key, cls: 'key' });
    tokens.push({ text: colon, cls: 'punct' });
    if (ws) tokens.push({ text: ws });
    tokens.push(...tokenizeYamlValue(value));
    return tokens;
  }

  tokens.push(...tokenizeYamlValue(body));
  return tokens;
}

function SigmaYamlBlock({ yaml }: { yaml: string }) {
  const lines = yaml.split('\n');
  return (
    <Paper
      variant="outlined"
      sx={(t) => ({
        p: 1.5,
        mt: 0.5,
        fontFamily: 'JetBrains Mono, monospace',
        fontSize: '0.75rem',
        lineHeight: 1.65,
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-word',
        maxHeight: 360,
        overflowY: 'auto',
        // Light (default) syntax palette.
        bgcolor: '#f6f8fc',
        color: '#3b4252',
        '--yaml-key': '#0a7ea4',
        '--yaml-string': '#1a7f37',
        '--yaml-number': '#b06f00',
        '--yaml-bool': '#7a4fe0',
        '--yaml-comment': '#8a93a6',
        '--yaml-punct': '#5a6478',
        '--yaml-value': '#3b4252',
        ...t.applyStyles('dark', {
          bgcolor: '#0d1426',
          color: '#c9d3e6',
          '--yaml-key': '#26d4ee',
          '--yaml-string': '#3ed598',
          '--yaml-number': '#f5b54a',
          '--yaml-bool': '#c4a8ff',
          '--yaml-comment': '#6b7591',
          '--yaml-punct': '#8a93a6',
          '--yaml-value': '#c9d3e6',
        }),
        '& .yk': { color: 'var(--yaml-key)' },
        '& .ys': { color: 'var(--yaml-string)' },
        '& .yn': { color: 'var(--yaml-number)' },
        '& .yb': { color: 'var(--yaml-bool)' },
        '& .yc': { color: 'var(--yaml-comment)', fontStyle: 'italic' },
        '& .yp': { color: 'var(--yaml-punct)' },
        '& .yv': { color: 'var(--yaml-value)' },
      })}
    >
      {lines.map((line, i) => (
        <Fragment key={i}>
          {tokenizeYamlLine(line).map((tok, j) => (
            <span key={j} className={tok.cls ? YAML_CLS[tok.cls] : undefined}>
              {tok.text}
            </span>
          ))}
          {i < lines.length - 1 ? '\n' : null}
        </Fragment>
      ))}
    </Paper>
  );
}

const LEVEL_COLORS: Record<string, string> = {
  informational: '#9ca3af',
  low: '#10b981',
  medium: '#f59e0b',
  high: '#ef4444',
  critical: '#7c3aed',
};

export default function DetectionsPage() {
  const singleEnvironment = useDeployment()?.mode === 'single';
  const searchParams = useSearchParams();
  const { isEnabled } = useFeatures();
  const canEdit = isEnabled('detection_editing');
  const { get: getPref } = useUserPrefs();
  const tableSize: 'small' | 'medium' =
    getPref<string>('density', 'comfortable') === 'compact' ? 'small' : 'medium';
  const [items, setItems] = useState<DetectionListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const pageSize = 25;
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters — technique_id can be deep-linked from gaps/APT pages.
  const [q, setQ] = useState('');
  const [status, setStatus] = useState('');
  const [source, setSource] = useState('');
  const [level, setLevel] = useState('');
  const [reviewStatus, setReviewStatus] = useState('');
  const [techniqueId, setTechniqueId] = useState(searchParams.get('technique_id') ?? '');

  const [openId, setOpenId] = useState<string | null>(null);
  const [detail, setDetail] = useState<DetectionDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // Selection + bulk actions
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkStatus, setBulkStatus] = useState('deployed');
  const [bulkBusy, setBulkBusy] = useState(false);
  const [bulkMsg, setBulkMsg] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [rowBusy, setRowBusy] = useState<string | null>(null);

  const pages = useMemo(
    () => Math.max(1, Math.ceil(total / pageSize)),
    [total],
  );

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    listDetections({
      page,
      page_size: pageSize,
      q: q || undefined,
      status: status || undefined,
      source: source || undefined,
      level: level || undefined,
      review_status: reviewStatus || undefined,
      technique_id: techniqueId || undefined,
    })
      .then((res) => {
        if (cancelled) return;
        setItems(res.items);
        setTotal(res.total);
      })
      .catch((e) => {
        if (cancelled) return;
        setError(
          e?.response?.data?.detail ??
            'failed to load — pick a customer in the topbar if you are an MSSP user.',
        );
      })
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [page, q, status, source, level, reviewStatus, techniqueId, reloadKey]);

  function toggleSelect(id: string) {
    setSelected((s) => {
      const next = new Set(s);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleSelectAll() {
    setSelected((s) =>
      s.size === items.length ? new Set() : new Set(items.map((i) => i.id)),
    );
  }

  async function applyBulkStatus() {
    setBulkBusy(true);
    setBulkMsg(null);
    try {
      const r = await bulkDetectionStatus([...selected], bulkStatus);
      const parts = [`Updated ${r.updated}`];
      if (r.skipped) parts.push(`skipped ${r.skipped} global`);
      if (r.blocked) parts.push(`${r.blocked} blocked pending approval`);
      setBulkMsg(`${parts.join(', ')}.`);
      setSelected(new Set());
      setReloadKey((k) => k + 1);
    } catch (e: any) {
      setBulkMsg(e?.response?.data?.detail ?? 'bulk update failed');
    } finally {
      setBulkBusy(false);
    }
  }

  async function applyBulkDelete() {
    if (!confirm(`Delete ${selected.size} detection(s)? Global rules are skipped.`)) return;
    setBulkBusy(true);
    setBulkMsg(null);
    try {
      const r = await bulkDeleteDetections([...selected]);
      setBulkMsg(`Deleted ${r.updated}${r.skipped ? `, skipped ${r.skipped} global` : ''}.`);
      setSelected(new Set());
      setReloadKey((k) => k + 1);
    } catch (e: any) {
      setBulkMsg(e?.response?.data?.detail ?? 'bulk delete failed');
    } finally {
      setBulkBusy(false);
    }
  }

  async function inlineStatus(id: string, newStatus: string) {
    setRowBusy(id);
    setBulkMsg(null);
    try {
      await patchDetection(id, { detection_status: newStatus });
      setReloadKey((k) => k + 1);
    } catch (e: any) {
      setBulkMsg(e?.response?.data?.detail ?? 'status update failed');
    } finally {
      setRowBusy(null);
    }
  }

  function openDetail(id: string) {
    setOpenId(id);
    setDetail(null);
    setDetailLoading(true);
    getDetection(id)
      .then((d) => setDetail(d))
      .finally(() => setDetailLoading(false));
  }

  function resetFilters() {
    setQ('');
    setStatus('');
    setSource('');
    setLevel('');
    setReviewStatus('');
    setTechniqueId('');
    setPage(1);
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      <Box>
        <Typography variant="h4" sx={{ fontWeight: 700, letterSpacing: '-0.02em' }}>
          Detection Library
        </Typography>
        <Typography variant="body2" color="text.secondary">
          SigmaHQ-synced detections, plus your customer-scoped overrides and custom rules.
        </Typography>
      </Box>

      {!singleEnvironment && (
        <FeatureGate feature="detection_promotion">
          <SuggestionsStrip />
        </FeatureGate>
      )}

      <Card>
        <CardContent>
          <Stack direction={{ xs: 'column', md: 'row' }} spacing={1.5} alignItems="center">
            <TextField
              size="small"
              placeholder="Search by title..."
              value={q}
              onChange={(e) => {
                setPage(1);
                setQ(e.target.value);
              }}
              sx={{ minWidth: 240 }}
            />
            <TextField
              size="small"
              select
              label="Source"
              value={source}
              onChange={(e) => {
                setPage(1);
                setSource(e.target.value);
              }}
              sx={{ minWidth: 140 }}
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="global">Global</MenuItem>
              <MenuItem value="customized">Customized</MenuItem>
              <MenuItem value="custom">Custom</MenuItem>
            </TextField>
            <TextField
              size="small"
              select
              label="Status"
              value={status}
              onChange={(e) => {
                setPage(1);
                setStatus(e.target.value);
              }}
              sx={{ minWidth: 160 }}
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="idea">Idea</MenuItem>
              <MenuItem value="in_development">In development</MenuItem>
              <MenuItem value="tuning">Tuning</MenuItem>
              <MenuItem value="deployed">Deployed</MenuItem>
              <MenuItem value="gap">Gap</MenuItem>
              <MenuItem value="not_applicable">N/A</MenuItem>
            </TextField>
            <TextField
              size="small"
              select
              label="Level"
              value={level}
              onChange={(e) => {
                setPage(1);
                setLevel(e.target.value);
              }}
              sx={{ minWidth: 130 }}
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="informational">Informational</MenuItem>
              <MenuItem value="low">Low</MenuItem>
              <MenuItem value="medium">Medium</MenuItem>
              <MenuItem value="high">High</MenuItem>
              <MenuItem value="critical">Critical</MenuItem>
            </TextField>
            <TextField
              size="small"
              select
              label="Review"
              value={reviewStatus}
              onChange={(e) => {
                setPage(1);
                setReviewStatus(e.target.value);
              }}
              sx={{ minWidth: 160 }}
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="draft">Draft</MenuItem>
              <MenuItem value="in_review">In review</MenuItem>
              <MenuItem value="approved">Approved</MenuItem>
              <MenuItem value="changes_requested">Changes requested</MenuItem>
            </TextField>
            <TextField
              size="small"
              label="Technique"
              placeholder="e.g. T1059.001"
              value={techniqueId}
              onChange={(e) => {
                setPage(1);
                setTechniqueId(e.target.value);
              }}
              sx={{ minWidth: 160 }}
            />
            <IconButton onClick={resetFilters} title="Clear filters" size="small">
              <FilterAltOffRoundedIcon />
            </IconButton>
            <Box sx={{ flex: 1 }} />
            <Typography variant="body2" color="text.secondary">
              {loading ? 'loading…' : `${total.toLocaleString()} detections`}
            </Typography>
          </Stack>
        </CardContent>
      </Card>

      {(selected.size > 0 || bulkMsg) && (
        <Paper variant="outlined" sx={{ p: 1.5 }}>
          <Stack direction="row" spacing={1.5} alignItems="center" flexWrap="wrap" useFlexGap>
            <Typography variant="body2" sx={{ fontWeight: 600 }}>
              {selected.size} selected
            </Typography>
            <TextField
              select
              size="small"
              label="Set status"
              value={bulkStatus}
              onChange={(e) => setBulkStatus(e.target.value)}
              sx={{ minWidth: 170 }}
              disabled={selected.size === 0 || !canEdit}
            >
              {STATUS_OPTIONS.map((s) => (
                <MenuItem key={s} value={s}>{s.replace('_', ' ')}</MenuItem>
              ))}
            </TextField>
            <Button
              variant="contained"
              size="small"
              onClick={applyBulkStatus}
              disabled={bulkBusy || selected.size === 0 || !canEdit}
            >
              Apply
            </Button>
            {bulkStatus === 'deployed' && (
              <Typography variant="caption" color="text.secondary">
                Unapproved rules are skipped.
              </Typography>
            )}
            <Button
              variant="outlined"
              size="small"
              color="error"
              onClick={applyBulkDelete}
              disabled={bulkBusy || selected.size === 0 || !canEdit}
            >
              Delete
            </Button>
            <Button size="small" onClick={() => setSelected(new Set())} disabled={selected.size === 0}>
              Clear
            </Button>
            {bulkMsg && (
              <Typography variant="caption" color="text.secondary">{bulkMsg}</Typography>
            )}
          </Stack>
        </Paper>
      )}

      <Paper variant="outlined" sx={{ overflow: 'hidden' }}>
        {error && (
          <Box sx={{ p: 3 }}>
            <Typography color="error">{error}</Typography>
          </Box>
        )}
        {!error && (
          <Table size={tableSize}>
            <TableHead>
              <TableRow>
                <TableCell padding="checkbox">
                  <Checkbox
                    size="small"
                    checked={items.length > 0 && selected.size === items.length}
                    indeterminate={selected.size > 0 && selected.size < items.length}
                    onChange={toggleSelectAll}
                  />
                </TableCell>
                <TableCell>Title</TableCell>
                <TableCell sx={{ width: 110 }}>Source</TableCell>
                <TableCell sx={{ width: 150 }}>Status</TableCell>
                <TableCell sx={{ width: 150 }}>Review</TableCell>
                <TableCell sx={{ width: 90 }}>Level</TableCell>
                <TableCell>Techniques</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {loading && items.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} align="center" sx={{ py: 4 }}>
                    <CircularProgress size={20} />
                  </TableCell>
                </TableRow>
              ) : items.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} align="center" sx={{ py: 6, color: 'text.secondary' }}>
                    No detections match these filters.
                  </TableCell>
                </TableRow>
              ) : (
                items.map((d) => {
                  const src = SOURCE_LABELS[d.source] ?? { label: d.source, color: 'default' as const };
                  const st = STATUS_LABELS[d.detection_status] ?? { color: 'default' as const };
                  return (
                    <TableRow
                      key={d.id}
                      hover
                      selected={selected.has(d.id)}
                      onClick={() => openDetail(d.id)}
                      sx={{ cursor: 'pointer' }}
                    >
                      <TableCell padding="checkbox" onClick={(e) => e.stopPropagation()}>
                        <Checkbox
                          size="small"
                          checked={selected.has(d.id)}
                          onChange={() => toggleSelect(d.id)}
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontWeight: 500 }}>
                          {d.title}
                        </Typography>
                        <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
                          {d.sigma_id.slice(0, 8)}…
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip label={src.label} size="small" color={src.color} />
                      </TableCell>
                      <TableCell onClick={(e) => e.stopPropagation()}>
                        {d.source === 'global' ? (
                          <Chip
                            label={d.detection_status.replace('_', ' ')}
                            size="small"
                            color={st.color}
                            variant="outlined"
                          />
                        ) : (
                          <TextField
                            select
                            size="small"
                            variant="standard"
                            value={d.detection_status}
                            disabled={rowBusy === d.id || !canEdit}
                            onChange={(e) => inlineStatus(d.id, e.target.value)}
                            sx={{ minWidth: 130 }}
                          >
                            {STATUS_OPTIONS.map((s) => {
                              const needsApproval =
                                s === 'deployed' &&
                                d.review_status !== 'approved' &&
                                d.detection_status !== 'deployed';
                              return (
                                <MenuItem key={s} value={s} disabled={needsApproval}>
                                  {s.replace('_', ' ')}
                                  {needsApproval ? ' (approval required)' : ''}
                                </MenuItem>
                              );
                            })}
                          </TextField>
                        )}
                      </TableCell>
                      <TableCell>
                        {(() => {
                          const status = d.review_status ?? 'draft';
                          const review = REVIEW_LABELS[status] ?? {
                            label: status.replace('_', ' '),
                            color: 'default' as const,
                          };
                          const needsReview =
                            d.detection_status === 'deployed' && status !== 'approved';
                          return (
                            <Chip
                              size="small"
                              variant={needsReview ? 'filled' : 'outlined'}
                              label={needsReview ? 'Re-review needed' : review.label}
                              color={needsReview ? 'warning' : review.color}
                            />
                          );
                        })()}
                      </TableCell>
                      <TableCell>
                        {d.level && (
                          <Box
                            sx={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: 0.75,
                              fontSize: '0.75rem',
                              fontWeight: 600,
                              textTransform: 'capitalize',
                            }}
                          >
                            <Box
                              sx={{
                                width: 8,
                                height: 8,
                                borderRadius: '50%',
                                bgcolor: LEVEL_COLORS[d.level] ?? 'grey.500',
                              }}
                            />
                            {d.level}
                          </Box>
                        )}
                      </TableCell>
                      <TableCell>
                        <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                          {d.techniques.slice(0, 4).map((t) => (
                            <Chip
                              key={t}
                              label={t}
                              size="small"
                              variant="outlined"
                              sx={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.7rem' }}
                            />
                          ))}
                          {d.techniques.length > 4 && (
                            <Chip label={`+${d.techniques.length - 4}`} size="small" />
                          )}
                        </Stack>
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        )}
      </Paper>

      {pages > 1 && (
        <Stack direction="row" justifyContent="center" sx={{ mt: 1 }}>
          <Pagination
            page={page}
            count={pages}
            onChange={(_, p) => setPage(p)}
            color="primary"
          />
        </Stack>
      )}

      <Drawer
        anchor="right"
        open={openId !== null}
        onClose={() => {
          setOpenId(null);
          setDetail(null);
        }}
        PaperProps={{ sx: { width: { xs: '100%', md: 640 } } }}
      >
        <Box sx={{ p: 3, display: 'flex', flexDirection: 'column', gap: 2 }}>
          <Stack direction="row" alignItems="center" spacing={1}>
            <Typography variant="h6" sx={{ flex: 1, fontWeight: 700 }}>
              {detail?.title ?? 'Loading…'}
            </Typography>
            <IconButton onClick={() => setOpenId(null)} size="small">
              <CloseRoundedIcon />
            </IconButton>
          </Stack>
          {detailLoading && <CircularProgress size={20} />}
          {detail && (
            <>
              <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                <Chip label={detail.source} size="small" color={SOURCE_LABELS[detail.source]?.color ?? 'default'} />
                <Chip
                  label={detail.detection_status.replace('_', ' ')}
                  size="small"
                  variant="outlined"
                />
                {detail.level && <Chip label={detail.level} size="small" />}
                {detail.sigma_status && <Chip label={detail.sigma_status} size="small" variant="outlined" />}
              </Stack>
              <DetectionReviewPanel
                detail={detail}
                canEdit={canEdit}
                onChanged={(next) => {
                  setDetail(next);
                  setReloadKey((k) => k + 1);
                }}
              />
              <Typography variant="body2" color="text.secondary">
                {detail.description ?? '(no description)'}
              </Typography>
              <Divider />
              <Box>
                <Typography variant="caption" color="text.secondary">
                  Techniques
                </Typography>
                <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap sx={{ mt: 0.5 }}>
                  {detail.techniques.length === 0 && (
                    <Typography variant="caption" color="text.secondary">
                      —
                    </Typography>
                  )}
                  {detail.techniques.map((t) => (
                    <Chip
                      key={t}
                      label={t}
                      size="small"
                      sx={{ fontFamily: 'JetBrains Mono, monospace' }}
                    />
                  ))}
                </Stack>
              </Box>
              <Box>
                <Typography variant="caption" color="text.secondary">
                  Tags
                </Typography>
                <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap sx={{ mt: 0.5 }}>
                  {detail.tags.map((t) => (
                    <Chip key={t} label={t} size="small" variant="outlined" />
                  ))}
                </Stack>
              </Box>
              <Box>
                <Typography variant="caption" color="text.secondary">
                  Sigma YAML
                </Typography>
                <SigmaYamlBlock yaml={detail.raw_yaml ?? '(no YAML)'} />
              </Box>
              <Box>
                <Button
                  size="small"
                  variant="outlined"
                  href={`${process.env.NEXT_PUBLIC_API_BASE ?? 'http://localhost:8000'}/detections/${detail.id}/export`}
                >
                  Download YAML
                </Button>
              </Box>
              <Divider />
              <DetectionDrawerExtras detectionId={detail.id} />
            </>
          )}
        </Box>
      </Drawer>
    </Box>
  );
}
