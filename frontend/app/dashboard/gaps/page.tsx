'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import {
  Alert,
  Autocomplete,
  Badge,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Divider,
  Drawer,
  FormControlLabel,
  IconButton,
  MenuItem,
  Paper,
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
import OpenInNewRoundedIcon from '@mui/icons-material/OpenInNewRounded';
import CloseRoundedIcon from '@mui/icons-material/CloseRounded';
import ChatBubbleOutlineRoundedIcon from '@mui/icons-material/ChatBubbleOutlineRounded';
import VisibilityOffRoundedIcon from '@mui/icons-material/VisibilityOffRounded';
import VisibilityRoundedIcon from '@mui/icons-material/VisibilityRounded';
import AccessTimeRoundedIcon from '@mui/icons-material/AccessTimeRounded';
import DeleteOutlineRoundedIcon from '@mui/icons-material/DeleteOutlineRounded';
import SendRoundedIcon from '@mui/icons-material/SendRounded';
import {
  APTListItem,
  GapDetail,
  GapEntry,
  SectorProfileSummary,
  addGapComment,
  deleteGapComment,
  getGapDetail,
  getTopGaps,
  ignoreGap,
  listAPTPaginated,
  listSectorProfiles,
  unignoreGap,
} from '@/lib/api';

type Kind = 'full' | 'sector' | 'apt';

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
};

export default function GapsPage() {
  const [kind, setKind] = useState<Kind>('full');
  const [ref, setRef] = useState<string>('');
  const [limit, setLimit] = useState(25);
  const [includeIgnored, setIncludeIgnored] = useState(false);
  const [sectors, setSectors] = useState<SectorProfileSummary[]>([]);
  const [groups, setGroups] = useState<APTListItem[]>([]);
  const [groupQuery, setGroupQuery] = useState('');
  const [items, setItems] = useState<GapEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Drawer state — opened by clicking a gap row's "Work on it" button.
  const [openTid, setOpenTid] = useState<string | null>(null);

  useEffect(() => {
    listSectorProfiles().then(setSectors).catch(() => {});
  }, []);

  useEffect(() => {
    if (kind !== 'apt') return;
    const handle = setTimeout(() => {
      listAPTPaginated(groupQuery || undefined, 1, 30)
        .then((r) => setGroups(r.items))
        .catch(() => {});
    }, 200);
    return () => clearTimeout(handle);
  }, [kind, groupQuery]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await getTopGaps(
        kind,
        kind === 'full' ? undefined : ref,
        limit,
        includeIgnored,
      );
      setItems(r.items);
    } catch (e: any) {
      setError(
        e?.response?.data?.detail ??
          'failed to load — pick a customer in the topbar if you are an MSSP user.',
      );
    } finally {
      setLoading(false);
    }
  }, [kind, ref, limit, includeIgnored]);

  useEffect(() => {
    if (kind !== 'full' && !ref) {
      setItems([]);
      setLoading(false);
      return;
    }
    load();
  }, [load, kind, ref]);

  // Refresh the gap row when the drawer reports a workflow change (e.g.
  // user ignored / un-ignored / added a comment) so the list stays in sync.
  const refreshRow = useCallback(async (tid: string) => {
    try {
      const d = await getGapDetail(tid);
      setItems((prev) =>
        prev
          .map((g) =>
            g.technique_id === tid
              ? {
                  ...g,
                  comment_count: d.comments.length,
                  is_ignored: d.ignore != null,
                }
              : g,
          )
          // Drop rows that became ignored while includeIgnored is off.
          .filter((g) => includeIgnored || !g.is_ignored),
      );
    } catch {
      // Non-fatal; the next manual refresh will reconcile.
    }
  }, [includeIgnored]);

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      <Box>
        <Typography variant="h4" sx={{ fontWeight: 700, letterSpacing: '-0.02em' }}>
          Gap analysis
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Uncovered techniques ranked by how many APT groups are known to use
          them. Click <strong>Work on it</strong> to pivot into a gap: add
          comments, link rules, or document a decision to ignore it.
        </Typography>
      </Box>

      <Card>
        <CardContent>
          <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} alignItems={{ md: 'center' }}>
            <TextField
              select
              size="small"
              label="Denominator"
              value={kind}
              onChange={(e) => {
                setKind(e.target.value as Kind);
                setRef('');
              }}
              sx={{ minWidth: 200 }}
            >
              <MenuItem value="full">Full ATT&amp;CK (Enterprise)</MenuItem>
              <MenuItem value="sector">By sector profile</MenuItem>
              <MenuItem value="apt">By APT group</MenuItem>
            </TextField>
            {kind === 'sector' && (
              <TextField
                select
                size="small"
                label="Sector"
                value={ref}
                onChange={(e) => setRef(e.target.value)}
                sx={{ minWidth: 240 }}
              >
                <MenuItem value="">— pick —</MenuItem>
                {sectors.map((s) => (
                  <MenuItem key={s.sector} value={s.sector}>
                    {s.label}
                  </MenuItem>
                ))}
              </TextField>
            )}
            {kind === 'apt' && (
              <Autocomplete
                size="small"
                options={groups}
                getOptionLabel={(g) => `${g.group_id} · ${g.name}`}
                onInputChange={(_, v) => setGroupQuery(v)}
                onChange={(_, v) => setRef(v ? v.group_id : '')}
                sx={{ minWidth: 300 }}
                renderInput={(params) => (
                  <TextField {...params} label="APT group" placeholder="e.g. APT28" />
                )}
              />
            )}
            <TextField
              select
              size="small"
              label="Limit"
              value={limit}
              onChange={(e) => setLimit(Number(e.target.value))}
              sx={{ minWidth: 100 }}
            >
              {[10, 25, 50, 100].map((n) => (
                <MenuItem key={n} value={n}>
                  Top {n}
                </MenuItem>
              ))}
            </TextField>
            <FormControlLabel
              control={
                <Switch
                  checked={includeIgnored}
                  onChange={(e) => setIncludeIgnored(e.target.checked)}
                  size="small"
                />
              }
              label="Show ignored"
            />
            <Box sx={{ flex: 1 }} />
            <Typography variant="body2" color="text.secondary">
              {loading ? 'loading…' : `${items.length} gaps`}
            </Typography>
          </Stack>
        </CardContent>
      </Card>

      {error && (
        <Card>
          <CardContent>
            <Typography color="error">{error}</Typography>
          </CardContent>
        </Card>
      )}

      {loading && (
        <Box sx={{ py: 6, display: 'flex', justifyContent: 'center' }}>
          <CircularProgress />
        </Box>
      )}

      {!loading && !items.length && !error && (
        <Card>
          <CardContent>
            <Typography color="text.secondary">
              {kind !== 'full' && !ref
                ? `Pick a ${kind === 'sector' ? 'sector' : 'group'} to compute gaps.`
                : 'No gaps to show — every in-scope technique has at least one detection (or all gaps are ignored).'}
            </Typography>
          </CardContent>
        </Card>
      )}

      {!loading && items.length > 0 && (
        <Paper variant="outlined" sx={{ overflow: 'hidden' }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell sx={{ width: 60 }}>Rank</TableCell>
                <TableCell sx={{ width: 120 }}>ID</TableCell>
                <TableCell>Technique</TableCell>
                <TableCell sx={{ width: 180 }}>Tactic</TableCell>
                <TableCell align="right" sx={{ width: 110 }}>
                  APTs
                </TableCell>
                <TableCell sx={{ minWidth: 220 }}>Sample groups</TableCell>
                <TableCell sx={{ width: 200 }} align="right">
                  Actions
                </TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {items.map((g, idx) => (
                <TableRow
                  key={g.technique_id}
                  hover
                  sx={
                    g.is_ignored
                      ? {
                          bgcolor: (t) => alpha(t.palette.text.disabled, 0.04),
                          opacity: 0.7,
                        }
                      : undefined
                  }
                >
                  <TableCell sx={{ color: 'text.secondary' }}>{idx + 1}</TableCell>
                  <TableCell sx={{ fontFamily: 'JetBrains Mono, monospace' }}>
                    {g.technique_id}
                    {g.is_subtechnique && (
                      <Box
                        component="span"
                        sx={{
                          display: 'inline-block',
                          width: 4,
                          height: 12,
                          bgcolor: 'primary.main',
                          ml: 0.5,
                          borderRadius: '2px',
                          verticalAlign: 'middle',
                        }}
                      />
                    )}
                  </TableCell>
                  <TableCell>
                    <Stack direction="row" alignItems="center" spacing={1}>
                      <Typography variant="body2" sx={{ fontWeight: 500 }}>
                        {g.name}
                      </Typography>
                      {g.is_ignored && (
                        <Chip
                          size="small"
                          icon={<VisibilityOffRoundedIcon fontSize="small" />}
                          label="ignored"
                          variant="outlined"
                          color="default"
                          sx={{ height: 20 }}
                        />
                      )}
                      {g.comment_count > 0 && (
                        <Tooltip
                          title={`${g.comment_count} comment${g.comment_count === 1 ? '' : 's'}`}
                          arrow
                        >
                          <Chip
                            size="small"
                            icon={<ChatBubbleOutlineRoundedIcon fontSize="small" />}
                            label={g.comment_count}
                            variant="outlined"
                            sx={{ height: 20 }}
                          />
                        </Tooltip>
                      )}
                    </Stack>
                  </TableCell>
                  <TableCell>
                    <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                      {g.tactics.map((t) => (
                        <Chip
                          key={t}
                          label={TACTIC_LABELS[t] ?? t}
                          size="small"
                          variant="outlined"
                        />
                      ))}
                    </Stack>
                  </TableCell>
                  <TableCell align="right">
                    <Tooltip
                      title={`${g.direct_group_count} direct · ${g.software_group_count} via software`}
                      arrow
                    >
                      <Chip
                        label={g.apt_count}
                        size="small"
                        color="error"
                        sx={{ fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}
                      />
                    </Tooltip>
                  </TableCell>
                  <TableCell>
                    <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                      {g.sample_groups.map((s) => (
                        <Tooltip key={s.group_id} title={s.name} arrow>
                          <Chip
                            label={s.group_id}
                            size="small"
                            variant="outlined"
                            sx={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.7rem' }}
                          />
                        </Tooltip>
                      ))}
                    </Stack>
                  </TableCell>
                  <TableCell align="right">
                    <Stack direction="row" spacing={0.5} justifyContent="flex-end">
                      <Button
                        size="small"
                        variant="outlined"
                        onClick={() => setOpenTid(g.technique_id)}
                      >
                        Work on it
                      </Button>
                      <Button
                        size="small"
                        variant="text"
                        endIcon={<OpenInNewRoundedIcon fontSize="small" />}
                        component={Link}
                        href={`/dashboard/detections?technique_id=${g.technique_id}`}
                      >
                        Rules
                      </Button>
                    </Stack>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Paper>
      )}

      <GapDrawer
        technique_id={openTid}
        onClose={() => setOpenTid(null)}
        onChanged={(tid) => refreshRow(tid)}
      />
    </Box>
  );
}

// ============================================================================
// Gap detail drawer
// ============================================================================

function GapDrawer({
  technique_id,
  onClose,
  onChanged,
}: {
  technique_id: string | null;
  onClose: () => void;
  onChanged: (tid: string) => void;
}) {
  const [detail, setDetail] = useState<GapDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Comment composer state
  const [newComment, setNewComment] = useState('');

  // Ignore composer state
  const [ignoreReason, setIgnoreReason] = useState('');
  const [ignoreUntil, setIgnoreUntil] = useState<string>('');

  const open = technique_id != null;

  const reload = useCallback(async () => {
    if (!technique_id) return;
    setLoading(true);
    setError(null);
    try {
      const d = await getGapDetail(technique_id);
      setDetail(d);
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'failed to load gap details');
    } finally {
      setLoading(false);
    }
  }, [technique_id]);

  useEffect(() => {
    if (open) {
      setDetail(null);
      setNewComment('');
      setIgnoreReason('');
      setIgnoreUntil('');
      reload();
    }
  }, [open, reload]);

  async function submitComment() {
    if (!technique_id || !newComment.trim()) return;
    setBusy(true);
    try {
      await addGapComment(technique_id, newComment.trim());
      setNewComment('');
      await reload();
      onChanged(technique_id);
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'failed to add comment');
    } finally {
      setBusy(false);
    }
  }

  async function removeComment(id: string) {
    if (!technique_id) return;
    if (!confirm('Delete this comment?')) return;
    setBusy(true);
    try {
      await deleteGapComment(id);
      await reload();
      onChanged(technique_id);
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'failed to delete comment');
    } finally {
      setBusy(false);
    }
  }

  async function submitIgnore() {
    if (!technique_id || ignoreReason.trim().length < 3) return;
    setBusy(true);
    try {
      await ignoreGap(technique_id, ignoreReason.trim(), {
        ignored_until: ignoreUntil || null,
      });
      await reload();
      onChanged(technique_id);
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'failed to ignore gap');
    } finally {
      setBusy(false);
    }
  }

  async function clearIgnore() {
    if (!technique_id) return;
    if (!confirm('Un-ignore this gap? It will reappear in the ranking.')) return;
    setBusy(true);
    try {
      await unignoreGap(technique_id);
      setIgnoreReason('');
      setIgnoreUntil('');
      await reload();
      onChanged(technique_id);
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'failed to un-ignore gap');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Drawer
      anchor="right"
      open={open}
      onClose={onClose}
      PaperProps={{ sx: { width: { xs: '100%', md: 560 }, p: 3 } }}
    >
      <Stack direction="row" alignItems="center" spacing={1} mb={2}>
        <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary', flex: 1 }}>
          Gap workspace
        </Typography>
        <IconButton size="small" onClick={onClose}>
          <CloseRoundedIcon fontSize="small" />
        </IconButton>
      </Stack>

      {loading && (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 6 }}>
          <CircularProgress />
        </Box>
      )}
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      {!loading && detail && (
        <Stack spacing={3}>
          {/* ---- Technique header ---- */}
          <Box>
            <Stack direction="row" alignItems="center" spacing={1}>
              <Typography
                variant="caption"
                sx={{ fontFamily: 'JetBrains Mono, monospace', color: 'primary.main' }}
              >
                {detail.technique_id}
              </Typography>
              {detail.is_subtechnique && detail.parent_technique_id && (
                <Chip
                  size="small"
                  label={`sub-of ${detail.parent_technique_id}`}
                  variant="outlined"
                  sx={{ height: 18, fontSize: '0.65rem' }}
                />
              )}
              {detail.deprecated && (
                <Chip size="small" label="deprecated" color="warning" sx={{ height: 18 }} />
              )}
              {detail.ignore && (
                <Chip
                  size="small"
                  icon={<VisibilityOffRoundedIcon fontSize="small" />}
                  label="ignored"
                  variant="outlined"
                  sx={{ height: 18 }}
                />
              )}
            </Stack>
            <Typography variant="h5" sx={{ fontWeight: 700, mt: 0.5 }}>
              {detail.name}
            </Typography>
            <Stack direction="row" spacing={0.5} mt={1} flexWrap="wrap" useFlexGap>
              {detail.tactics.map((t) => (
                <Chip
                  key={t}
                  label={TACTIC_LABELS[t] ?? t}
                  size="small"
                  variant="outlined"
                  sx={{ height: 20 }}
                />
              ))}
            </Stack>
            {detail.platforms.length > 0 && (
              <Typography
                variant="caption"
                color="text.secondary"
                sx={{ display: 'block', mt: 0.5 }}
              >
                Platforms: {detail.platforms.join(', ')}
              </Typography>
            )}
            {detail.description && (
              <Typography
                variant="body2"
                color="text.secondary"
                sx={{
                  mt: 1.5,
                  maxHeight: 140,
                  overflow: 'auto',
                  whiteSpace: 'pre-wrap',
                }}
              >
                {detail.description}
              </Typography>
            )}
          </Box>

          {/* ---- Quick pivots ---- */}
          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
            <Button
              size="small"
              variant="contained"
              component={Link}
              href={`/dashboard/detections?technique_id=${detail.technique_id}`}
              endIcon={<OpenInNewRoundedIcon fontSize="small" />}
            >
              View detections ({detail.detection_count})
            </Button>
            <Button
              size="small"
              variant="outlined"
              component={Link}
              href={`/dashboard/coverage?focus=${detail.technique_id}`}
              endIcon={<OpenInNewRoundedIcon fontSize="small" />}
            >
              Open in matrix
            </Button>
            {detail.url && (
              <Button
                size="small"
                variant="text"
                href={detail.url}
                target="_blank"
                rel="noreferrer"
                endIcon={<OpenInNewRoundedIcon fontSize="small" />}
              >
                ATT&amp;CK page
              </Button>
            )}
          </Stack>

          {/* ---- APT groups ---- */}
          {detail.apt_groups.length > 0 && (
            <Box>
              <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
                Used by {detail.apt_groups.length} APT group
                {detail.apt_groups.length === 1 ? '' : 's'}
              </Typography>
              <Stack direction="row" spacing={0.5} mt={1} flexWrap="wrap" useFlexGap>
                {detail.apt_groups.slice(0, 20).map((g) => (
                  <Tooltip
                    key={g.group_id}
                    title={`${g.name} · via ${g.via}`}
                    arrow
                  >
                    <Chip
                      size="small"
                      label={g.group_id}
                      variant="outlined"
                      sx={{
                        fontFamily: 'JetBrains Mono, monospace',
                        fontSize: '0.7rem',
                        borderColor: g.via === 'software' ? 'divider' : 'error.main',
                      }}
                    />
                  </Tooltip>
                ))}
                {detail.apt_groups.length > 20 && (
                  <Chip
                    size="small"
                    label={`+${detail.apt_groups.length - 20} more`}
                    variant="outlined"
                  />
                )}
              </Stack>
            </Box>
          )}

          <Divider />

          {/* ---- Comments ---- */}
          <Box>
            <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
              Comments ({detail.comments.length})
            </Typography>
            <Stack spacing={1.5} sx={{ mt: 1 }}>
              {detail.comments.length === 0 && (
                <Typography variant="body2" color="text.secondary">
                  No comments yet. Use the box below to leave a note for your team.
                </Typography>
              )}
              {detail.comments.map((c) => (
                <Paper
                  key={c.id}
                  variant="outlined"
                  sx={{ p: 1.5, borderRadius: 2 }}
                >
                  <Stack direction="row" alignItems="center" spacing={1} mb={0.5}>
                    <Typography variant="caption" sx={{ fontWeight: 600 }}>
                      {c.author_email ?? 'unknown'}
                    </Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ flex: 1 }}>
                      {new Date(c.created_at).toLocaleString()}
                    </Typography>
                    <IconButton
                      size="small"
                      onClick={() => removeComment(c.id)}
                      disabled={busy}
                      aria-label="delete comment"
                    >
                      <DeleteOutlineRoundedIcon fontSize="small" />
                    </IconButton>
                  </Stack>
                  <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
                    {c.body}
                  </Typography>
                </Paper>
              ))}
            </Stack>
            <Stack direction="row" spacing={1} sx={{ mt: 1.5 }}>
              <TextField
                size="small"
                multiline
                minRows={2}
                maxRows={6}
                placeholder="Add a comment — what did you find? what's next?"
                value={newComment}
                onChange={(e) => setNewComment(e.target.value)}
                sx={{ flex: 1 }}
              />
              <Button
                variant="contained"
                disabled={busy || !newComment.trim()}
                onClick={submitComment}
                endIcon={busy ? <CircularProgress size={14} /> : <SendRoundedIcon />}
              >
                Post
              </Button>
            </Stack>
          </Box>

          <Divider />

          {/* ---- Ignore panel ---- */}
          <Box>
            <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
              Ignore this gap
            </Typography>
            {detail.ignore ? (
              <Alert
                severity="info"
                icon={<VisibilityOffRoundedIcon />}
                sx={{ mt: 1 }}
                action={
                  <Button
                    color="inherit"
                    size="small"
                    startIcon={<VisibilityRoundedIcon fontSize="small" />}
                    onClick={clearIgnore}
                    disabled={busy}
                  >
                    Un-ignore
                  </Button>
                }
              >
                <Typography variant="body2" sx={{ fontWeight: 600, mb: 0.5 }}>
                  Currently ignored
                </Typography>
                <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
                  {detail.ignore.reason}
                </Typography>
                <Stack direction="row" spacing={1} mt={0.5}>
                  <Typography variant="caption" color="text.secondary">
                    by {detail.ignore.author_email ?? 'unknown'} ·{' '}
                    {new Date(detail.ignore.created_at).toLocaleDateString()}
                  </Typography>
                  {detail.ignore.ignored_until && (
                    <Chip
                      size="small"
                      icon={<AccessTimeRoundedIcon fontSize="small" />}
                      label={`re-surfaces ${detail.ignore.ignored_until}`}
                      variant="outlined"
                      sx={{ height: 18, fontSize: '0.65rem' }}
                    />
                  )}
                </Stack>
              </Alert>
            ) : (
              <Stack spacing={1.5} sx={{ mt: 1 }}>
                <Typography variant="caption" color="text.secondary">
                  Mark this gap as accepted so it drops out of the ranking. A
                  reason is required; optionally set a date when the gap should
                  re-surface for review.
                </Typography>
                <TextField
                  size="small"
                  multiline
                  minRows={2}
                  maxRows={4}
                  label="Reason (required)"
                  placeholder="e.g. Out of scope for this customer — no Linux workloads in production."
                  value={ignoreReason}
                  onChange={(e) => setIgnoreReason(e.target.value)}
                  required
                />
                <Stack direction="row" spacing={1}>
                  <TextField
                    size="small"
                    type="date"
                    label="Re-surface on (optional)"
                    value={ignoreUntil}
                    onChange={(e) => setIgnoreUntil(e.target.value)}
                    InputLabelProps={{ shrink: true }}
                    sx={{ flex: 1 }}
                  />
                  <Button
                    variant="outlined"
                    color="warning"
                    startIcon={<VisibilityOffRoundedIcon />}
                    disabled={busy || ignoreReason.trim().length < 3}
                    onClick={submitIgnore}
                  >
                    Ignore gap
                  </Button>
                </Stack>
              </Stack>
            )}
          </Box>
        </Stack>
      )}
    </Drawer>
  );
}
