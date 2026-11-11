'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { usePathname } from 'next/navigation';
import {
  Alert,
  Autocomplete,
  Box,
  Button,
  ButtonBase,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Collapse,
  Divider,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Drawer,
  IconButton,
  InputAdornment,
  LinearProgress,
  Link as MuiLink,
  ListSubheader,
  Menu,
  MenuItem,
  Paper,
  Skeleton,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Tooltip,
  Typography,
  alpha,
} from '@mui/material';
import CloseRoundedIcon from '@mui/icons-material/CloseRounded';
import SaveAltRoundedIcon from '@mui/icons-material/SaveAltRounded';
import SearchRoundedIcon from '@mui/icons-material/SearchRounded';
import FilterAltOffRoundedIcon from '@mui/icons-material/FilterAltOffRounded';
import BookmarkBorderRoundedIcon from '@mui/icons-material/BookmarkBorderRounded';
import ExpandMoreRoundedIcon from '@mui/icons-material/ExpandMoreRounded';
import ChevronRightRoundedIcon from '@mui/icons-material/ChevronRightRounded';
import OpenInNewRoundedIcon from '@mui/icons-material/OpenInNewRounded';
import AddCircleOutlineRoundedIcon from '@mui/icons-material/AddCircleOutlineRounded';
import ShieldRoundedIcon from '@mui/icons-material/ShieldRounded';
import GroupsRoundedIcon from '@mui/icons-material/GroupsRounded';
import RuleRoundedIcon from '@mui/icons-material/RuleRounded';
import NotesRoundedIcon from '@mui/icons-material/NotesRounded';
import TrendingUpRoundedIcon from '@mui/icons-material/TrendingUpRounded';
import TrendingDownRoundedIcon from '@mui/icons-material/TrendingDownRounded';
import FiberNewRoundedIcon from '@mui/icons-material/FiberNewRounded';
import HistoryRoundedIcon from '@mui/icons-material/HistoryRounded';
import StorageRoundedIcon from '@mui/icons-material/StorageRounded';
import {
  AIDraftResult,
  APTGroup,
  CoverageCell,
  CoverageMatrix,
  CoverageScore,
  CoverageSnapshot,
  CustomDenominatorSpec,
  DeltaChange,
  DetectionRef,
  GRCFrameworkSummary,
  MatrixDelta,
  MatrixDeltaCell,
  SavedView,
  SectorProfileSummary,
  SiemOverlay,
  SiemUseCaseRef,
  TechniqueDetail,
  aiDraftDetection,
  createCoverageSnapshot,
  createDetection,
  deleteSavedView,
  deleteTechniqueNote,
  getCoverageMatrix,
  getCoverageScore,
  getCustomCoverageMatrix,
  getCustomCoverageScore,
  getGRCFrameworkTechniques,
  getMatrixDelta,
  getSiemOverlay,
  getTechniqueDetail,
  listAPTGroups,
  listCoverageSnapshots,
  listGRCFrameworks,
  listSavedViews,
  listSectorProfiles,
  patchDetection,
  saveView,
  upsertTechniqueNote,
} from '@/lib/api';
import Link from 'next/link';
import AutoAwesomeRoundedIcon from '@mui/icons-material/AutoAwesomeRounded';
import { coverage } from '../../theme';
import { ChangePurposeAction, ChangePurposeDialog, useCanEditDetections } from '../detections/UseCaseChange';

type DenominatorKind = 'full' | 'sector' | 'apt' | 'custom';
type SubTechScope = 'all' | 'parents' | 'subs';
type ColorMode = 'state' | 'heatmap';
type ColumnSort = 'tactic' | 'state' | 'detections';
type CellState =
  | 'deployed'
  | 'in_progress'
  | 'idea'
  | 'gap'
  | 'not_applicable'
  | 'out_of_scope';

const ALL_STATES: CellState[] = [
  'deployed',
  'in_progress',
  'idea',
  'gap',
  'not_applicable',
  'out_of_scope',
];

// Lower number = appears first when sorting "gaps first". Matches analyst
// triage priority: open work before completed work, scope-relevant first.
const STATE_PRIORITY: Record<string, number> = {
  gap: 0,
  in_progress: 1,
  idea: 2,
  deployed: 3,
  not_applicable: 4,
  out_of_scope: 5,
};

const DELTA_COLOR: Record<DeltaChange, string> = {
  improved: coverage.green,
  regressed: coverage.red,
  unchanged: 'transparent',
  new: '#26d4ee',
  removed: coverage.grey,
};

// Heatmap ramp by depth 0..5. 0 = uncovered (red), 5 = mature (deep green).
const HEATMAP_RAMP = [
  '#3a1320', // 0 — deep gap red
  '#7d2a3f',
  '#b85f4a',
  '#c8a04a',
  '#5a9d6a',
  coverage.green, // 5 — deployed deep
];

const STATE_COLOR: Record<string, string> = {
  deployed: coverage.green,
  in_progress: coverage.amber,
  idea: coverage.idea,
  gap: coverage.red,
  not_applicable: coverage.blue,
  out_of_scope: coverage.grey,
};

const STATE_LABEL: Record<string, string> = {
  deployed: 'Deployed',
  in_progress: 'In progress',
  idea: 'Idea',
  gap: 'Gap',
  not_applicable: 'N/A',
  out_of_scope: 'Out of scope',
};

const TACTIC_LABELS: Record<string, string> = {
  reconnaissance: 'Reconnaissance',
  'resource-development': 'Resource development',
  'initial-access': 'Initial access',
  execution: 'Execution',
  persistence: 'Persistence',
  'privilege-escalation': 'Privilege escalation',
  'defense-evasion': 'Defense evasion',
  'defense-impairment': 'Defense impairment',
  stealth: 'Stealth',
  'credential-access': 'Credential access',
  discovery: 'Discovery',
  'lateral-movement': 'Lateral movement',
  collection: 'Collection',
  'command-and-control': 'Command & control',
  exfiltration: 'Exfiltration',
  impact: 'Impact',
};

function tacticLabel(t: string): string {
  return (
    TACTIC_LABELS[t] ??
    t.split('-').map((w) => w[0]?.toUpperCase() + w.slice(1)).join(' ')
  );
}

export default function CoveragePage() {
  const [kind, setKind] = useState<DenominatorKind>('full');
  const [ref, setRef] = useState<string>('');
  const [matrix, setMatrix] = useState<CoverageMatrix | null>(null);
  const [score, setScore] = useState<CoverageScore | null>(null);
  const [sectors, setSectors] = useState<SectorProfileSummary[]>([]);
  const [groups, setGroups] = useState<APTGroup[]>([]);
  const [groupQuery, setGroupQuery] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [openCell, setOpenCell] = useState<CoverageCell | null>(null);
  const [savingSnapshot, setSavingSnapshot] = useState(false);
  const [snapshotMsg, setSnapshotMsg] = useState<string | null>(null);
  // Deployed SIEM use-cases overlay (from connectors). Read-only drift signal:
  // which techniques have a rule actually running in the customer's SIEM.
  const [siem, setSiem] = useState<SiemOverlay | null>(null);

  // ---- filter bar state ----
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch] = useState('');
  const [stateFilter, setStateFilter] = useState<Set<CellState>>(new Set());
  const [tacticFilter, setTacticFilter] = useState<string[]>([]);
  const [subScope, setSubScope] = useState<SubTechScope>('all');
  // Compliance-framework filter: when a framework is selected, the matrix
  // hides every technique that no control in that framework maps to. Lets
  // analysts answer "what does my ATT&CK coverage look like through the
  // NCA ECC lens?" without leaving the matrix.
  const [grcFrameworks, setGrcFrameworks] = useState<GRCFrameworkSummary[]>([]);
  const [frameworkFilter, setFrameworkFilter] = useState<string>('');
  const [frameworkTechSet, setFrameworkTechSet] = useState<Set<string> | null>(null);

  // ---- display options ----
  const [colorMode, setColorMode] = useState<ColorMode>('state');
  const [columnSort, setColumnSort] = useState<ColumnSort>('state');
  const [collapseSubs, setCollapseSubs] = useState(true);
  const [expandedParents, setExpandedParents] = useState<Set<string>>(new Set());
  // When set, the matrix collapses to a single tactic column and the
  // remaining tactic's technique cells render in a roomier "focused" mode
  // showing extra metadata (state, deployed count, other tactic chips).
  const [focusedTactic, setFocusedTactic] = useState<string | null>(null);

  // ---- snapshot delta overlay ----
  const [snapshots, setSnapshots] = useState<CoverageSnapshot[]>([]);
  const [compareSnapshotId, setCompareSnapshotId] = useState<string>('');
  const [delta, setDelta] = useState<MatrixDelta | null>(null);
  const [deltaError, setDeltaError] = useState<string | null>(null);

  // Re-fetch snapshots whenever the denominator changes — the snapshot list
  // is global per tenant but the delta endpoint must be invoked with the
  // matching denominator to compare apples-to-apples.
  useEffect(() => {
    listCoverageSnapshots().then(setSnapshots).catch(() => setSnapshots([]));
  }, []);

  // GRC frameworks list — populates the compliance-framework filter dropdown.
  // Filtered to frameworks that actually have technique mappings (an empty
  // framework would just blank the matrix, which isn't useful).
  useEffect(() => {
    listGRCFrameworks()
      .then((rows) =>
        setGrcFrameworks(rows.filter((r) => r.technique_mapping_count > 0)),
      )
      .catch(() => setGrcFrameworks([]));
  }, []);

  // Fetch the technique-ID set whenever the framework filter changes. Empty
  // selection => no filter (matrix shows the full denominator).
  useEffect(() => {
    if (!frameworkFilter) {
      setFrameworkTechSet(null);
      return;
    }
    let cancelled = false;
    getGRCFrameworkTechniques(frameworkFilter)
      .then((res) => {
        if (!cancelled) setFrameworkTechSet(new Set(res.technique_ids));
      })
      .catch(() => {
        if (!cancelled) setFrameworkTechSet(new Set());
      });
    return () => {
      cancelled = true;
    };
  }, [frameworkFilter]);

  function toggleParent(tid: string) {
    setExpandedParents((prev) => {
      const next = new Set(prev);
      if (next.has(tid)) next.delete(tid);
      else next.add(tid);
      return next;
    });
  }

  // debounce the search box so we don't recompute on every keystroke
  useEffect(() => {
    const handle = setTimeout(() => setSearch(searchInput.trim()), 150);
    return () => clearTimeout(handle);
  }, [searchInput]);

  // reset filters when the underlying denominator changes (different universe)
  useEffect(() => {
    setSearchInput('');
    setSearch('');
    setStateFilter(new Set());
    setTacticFilter([]);
    setSubScope('all');
    setCompareSnapshotId('');
    setDelta(null);
    setDeltaError(null);
  }, [kind, ref]);

  // fetch matrix-delta when the user picks a snapshot to compare against
  useEffect(() => {
    if (!compareSnapshotId) {
      setDelta(null);
      setDeltaError(null);
      return;
    }
    // The matrix-delta endpoint only knows the catalog denominators; the
    // custom-set denominator is computed via a different pipeline and has
    // no delta support, so bail cleanly. (This narrows `kind` for TS too.)
    if (kind === 'custom') {
      setDelta(null);
      setDeltaError('snapshot delta is not available for the custom denominator.');
      return;
    }
    let cancelled = false;
    setDeltaError(null);
    getMatrixDelta(compareSnapshotId, {
      denominator: kind,
      ref: kind === 'full' ? undefined : ref || undefined,
    })
      .then((d) => {
        if (!cancelled) setDelta(d);
      })
      .catch((e) => {
        if (cancelled) return;
        setDelta(null);
        setDeltaError(
          e?.response?.data?.detail ??
            'snapshot cannot be compared — it predates per-technique state capture.',
        );
      });
    return () => {
      cancelled = true;
    };
  }, [compareSnapshotId, kind, ref]);

  // index delta cells by technique_id for fast lookup during render
  const deltaByTechnique = useMemo(() => {
    if (!delta) return new Map<string, MatrixDeltaCell>();
    const m = new Map<string, MatrixDeltaCell>();
    for (const c of delta.cells) m.set(c.technique_id, c);
    return m;
  }, [delta]);

  useEffect(() => {
    listSectorProfiles().then(setSectors).catch(() => {});
    getSiemOverlay().then(setSiem).catch(() => setSiem(null));
  }, []);

  const siemTechs = useMemo(
    () => new Set(siem?.technique_ids ?? []),
    [siem],
  );

  // Debounced groups search.
  useEffect(() => {
    if (kind !== 'apt') return;
    const handle = setTimeout(() => {
      listAPTGroups(groupQuery || undefined).then(setGroups).catch(() => {});
    }, 200);
    return () => clearTimeout(handle);
  }, [kind, groupQuery]);

  // Custom-denominator state. When `customSpec` is set and kind === 'custom',
  // the matrix is computed by POSTing to /coverage/matrix-custom.
  const [customSpec, setCustomSpec] = useState<CustomDenominatorSpec | null>(null);
  const [customDialogOpen, setCustomDialogOpen] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      if (kind === 'custom') {
        if (!customSpec) {
          setMatrix(null);
          setScore(null);
          return;
        }
        const [m, s] = await Promise.all([
          getCustomCoverageMatrix(customSpec),
          getCustomCoverageScore(customSpec),
        ]);
        setMatrix(m);
        setScore(s);
      } else {
        // In this branch `kind` is narrowed to exclude 'custom'.
        const params: { denominator: 'full' | 'sector' | 'apt'; ref?: string } = {
          denominator: kind,
        };
        if (kind !== 'full' && ref) params.ref = ref;
        const [m, s] = await Promise.all([
          getCoverageMatrix(params),
          getCoverageScore(params),
        ]);
        setMatrix(m);
        setScore(s);
      }
    } catch (e: any) {
      setError(
        e?.response?.data?.detail ??
          'failed to load — pick a customer in the topbar if you are an MSSP user.',
      );
    } finally {
      setLoading(false);
    }
  }, [kind, ref, customSpec]);

  useEffect(() => {
    if (kind === 'custom') {
      if (!customSpec) {
        setMatrix(null);
        setScore(null);
        setLoading(false);
        return;
      }
      load();
      return;
    }
    if (kind !== 'full' && !ref) {
      // Don't fetch until a ref is chosen for sector/apt.
      setMatrix(null);
      setScore(null);
      setLoading(false);
      return;
    }
    load();
  }, [load, kind, ref, customSpec]);

  // Saved views state — Save/Load presets for this page.
  const [views, setViews] = useState<SavedView[]>([]);
  const [viewsMenuAnchor, setViewsMenuAnchor] = useState<HTMLElement | null>(null);
  const [saveDialogOpen, setSaveDialogOpen] = useState(false);
  const [newViewName, setNewViewName] = useState('');

  useEffect(() => {
    listSavedViews('coverage_matrix').then(setViews).catch(() => setViews([]));
  }, []);

  async function handleSaveView() {
    const name = newViewName.trim();
    if (!name) return;
    const payload: Record<string, unknown> = {
      kind,
      ref,
      stateFilter: Array.from(stateFilter),
      tacticFilter,
      subScope,
      colorMode,
      columnSort,
      customSpec,
      frameworkFilter,
    };
    try {
      const v = await saveView({ name, kind: 'coverage_matrix', payload });
      setViews((prev) => [v, ...prev.filter((p) => p.id !== v.id)]);
      setSaveDialogOpen(false);
      setNewViewName('');
    } catch (e) {
      // surfaced via the page error if needed
    }
  }

  function handleLoadView(v: SavedView) {
    const p = v.payload as any;
    if (p.kind === 'custom' && p.customSpec) {
      setKind('custom');
      setCustomSpec(p.customSpec as CustomDenominatorSpec);
    } else {
      setKind(p.kind ?? 'full');
      setRef(p.ref ?? '');
      setCustomSpec(null);
    }
    setStateFilter(new Set(p.stateFilter ?? []));
    setTacticFilter(p.tacticFilter ?? []);
    setSubScope(p.subScope ?? 'all');
    setFrameworkFilter(p.frameworkFilter ?? '');
    if (p.colorMode) setColorMode(p.colorMode);
    if (p.columnSort) setColumnSort(p.columnSort);
    setViewsMenuAnchor(null);
  }

  async function handleDeleteView(id: string) {
    await deleteSavedView(id);
    setViews((prev) => prev.filter((v) => v.id !== id));
  }

  const totalTechniques = useMemo(() => {
    if (!matrix) return 0;
    // each technique appears under one tactic column at most once per tactic;
    // count unique technique IDs across all columns
    const seen = new Set<string>();
    for (const t of matrix.tactics) {
      for (const c of matrix.by_tactic[t] ?? []) seen.add(c.technique_id);
    }
    return seen.size;
  }, [matrix]);

  const filteredByTactic = useMemo(() => {
    if (!matrix) return null as Record<string, CoverageCell[]> | null;
    const lowered = search.toLowerCase();
    const states = stateFilter;
    const tactics = new Set(tacticFilter);
    const sortFn = (a: CoverageCell, b: CoverageCell) => {
      if (columnSort === 'state') {
        const sd = STATE_PRIORITY[a.state] - STATE_PRIORITY[b.state];
        if (sd !== 0) return sd;
      } else if (columnSort === 'detections') {
        const dd = b.detection_count - a.detection_count;
        if (dd !== 0) return dd;
      }
      // tie-breaker / 'tactic' mode: keep stable ATT&CK order by id
      return a.technique_id.localeCompare(b.technique_id);
    };
    const out: Record<string, CoverageCell[]> = {};
    for (const t of matrix.tactics) {
      if (tactics.size > 0 && !tactics.has(t)) {
        out[t] = [];
        continue;
      }
      const filtered = (matrix.by_tactic[t] ?? []).filter((c) => {
        if (states.size > 0 && !states.has(c.state as CellState)) return false;
        if (subScope === 'parents' && c.is_subtechnique) return false;
        if (subScope === 'subs' && !c.is_subtechnique) return false;
        if (lowered) {
          const hay = `${c.technique_id} ${c.name}`.toLowerCase();
          if (!hay.includes(lowered)) return false;
        }
        if (frameworkTechSet) {
          // A cell passes the framework filter if it (or its parent, for
          // sub-techniques) is in the mapped-techniques set. Mapping a
          // control to T1059 implicitly covers T1059.001, T1059.003, etc.
          const inSet =
            frameworkTechSet.has(c.technique_id) ||
            (c.is_subtechnique &&
              c.parent_technique_id != null &&
              frameworkTechSet.has(c.parent_technique_id));
          if (!inSet) return false;
        }
        return true;
      });
      out[t] = [...filtered].sort(sortFn);
    }
    return out;
  }, [matrix, search, stateFilter, tacticFilter, subScope, columnSort, frameworkTechSet]);

  // For a single tactic column, group sub-techniques under their parents
  // when `collapseSubs` is on. Subs that survive a filter but whose parent
  // does NOT survive are still surfaced under a synthetic "(orphan)" group
  // so a search like "T1059.001" doesn't hide them.
  const groupCells = useCallback(
    (
      cells: CoverageCell[],
    ): { parent: CoverageCell | null; subs: CoverageCell[] }[] => {
      if (!collapseSubs) {
        return cells.map((c) => ({ parent: c, subs: [] }));
      }
      const parents = cells.filter((c) => !c.is_subtechnique);
      const subsByParent = new Map<string, CoverageCell[]>();
      const orphans: CoverageCell[] = [];
      for (const c of cells) {
        if (!c.is_subtechnique) continue;
        const pid = c.parent_technique_id;
        if (!pid || !parents.some((p) => p.technique_id === pid)) {
          orphans.push(c);
          continue;
        }
        subsByParent.set(pid, [...(subsByParent.get(pid) ?? []), c]);
      }
      const groups: { parent: CoverageCell | null; subs: CoverageCell[] }[] =
        parents.map((p) => ({
          parent: p,
          subs: subsByParent.get(p.technique_id) ?? [],
        }));
      if (orphans.length) {
        groups.push(
          ...orphans.map((o) => ({ parent: null, subs: [o] })),
        );
      }
      return groups;
    },
    [collapseSubs],
  );

  // Per-tactic posture: % of techniques with deployed OR in_progress detections.
  const tacticPosture = useMemo(() => {
    if (!filteredByTactic) return {} as Record<string, { covered: number; total: number; pct: number }>;
    const out: Record<string, { covered: number; total: number; pct: number }> = {};
    for (const [t, cells] of Object.entries(filteredByTactic)) {
      const covered = cells.filter(
        (c) => c.state === 'deployed' || c.state === 'in_progress',
      ).length;
      const total = cells.length;
      out[t] = { covered, total, pct: total === 0 ? 0 : covered / total };
    }
    return out;
  }, [filteredByTactic]);

  const filteredCount = useMemo(() => {
    if (!filteredByTactic) return 0;
    const seen = new Set<string>();
    for (const t of Object.keys(filteredByTactic)) {
      for (const c of filteredByTactic[t]) seen.add(c.technique_id);
    }
    return seen.size;
  }, [filteredByTactic]);

  const maxColumnHeight = useMemo(() => {
    if (!filteredByTactic) return 0;
    return Math.max(
      0,
      ...Object.values(filteredByTactic).map((arr) => arr.length),
    );
  }, [filteredByTactic]);

  const hasFilter =
    search.length > 0 ||
    stateFilter.size > 0 ||
    tacticFilter.length > 0 ||
    subScope !== 'all';

  function toggleState(s: CellState) {
    setStateFilter((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  }

  function resetFilters() {
    setSearchInput('');
    setSearch('');
    setStateFilter(new Set());
    setTacticFilter([]);
    setSubScope('all');
  }

  async function snapshot() {
    setSavingSnapshot(true);
    setSnapshotMsg(null);
    try {
      const snap = await createCoverageSnapshot({
        domain: 'enterprise',
        // Snapshots persist a catalog denominator; the ad-hoc custom set
        // isn't reproducible, so fall back to 'full' for the record.
        denominator_kind: kind === 'custom' ? 'full' : kind,
        denominator_ref: kind === 'full' || kind === 'custom' ? null : ref || null,
        notes: null as any,
      });
      setSnapshotMsg(
        `Snapshot ${snap.id.slice(0, 8)} captured (${snap.posture_grade}).`,
      );
    } catch (e: any) {
      setSnapshotMsg(e?.response?.data?.detail ?? 'snapshot failed');
    } finally {
      setSavingSnapshot(false);
    }
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      <Box>
        <Typography variant="h4" sx={{ fontWeight: 700, letterSpacing: '-0.02em' }}>
          Coverage matrix
        </Typography>
        <Typography variant="body2" color="text.secondary">
          MITRE ATT&amp;CK technique cells coloured by detection state, scored
          DeTT&amp;CT-style across the chosen denominator.
        </Typography>
      </Box>

      <Card>
        <CardContent>
          <Stack
            direction={{ xs: 'column', md: 'row' }}
            spacing={2}
            alignItems={{ md: 'center' }}
          >
            <TextField
              select
              size="small"
              label="Denominator"
              value={kind}
              onChange={(e) => {
                const k = e.target.value as DenominatorKind;
                setKind(k);
                setRef('');
                if (k === 'custom') {
                  setCustomDialogOpen(true);
                } else {
                  setCustomSpec(null);
                }
              }}
              sx={{ minWidth: 200 }}
            >
              <MenuItem value="full">Full ATT&amp;CK (Enterprise)</MenuItem>
              <MenuItem value="sector">By sector profile</MenuItem>
              <MenuItem value="apt">By APT group</MenuItem>
              <MenuItem value="custom">Custom (build…)</MenuItem>
            </TextField>

            {kind === 'custom' && customSpec && (
              <Tooltip title="Edit the custom denominator spec">
                <Button
                  size="small"
                  variant="outlined"
                  onClick={() => setCustomDialogOpen(true)}
                >
                  {`${customSpec.sectors?.length ?? 0} sector · ${
                    customSpec.apt_groups?.length ?? 0
                  } APT · ${
                    customSpec.platforms?.length ?? 0
                  } platform · ${customSpec.operator}`}
                </Button>
              </Tooltip>
            )}

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
                    {s.label} ({s.technique_count})
                  </MenuItem>
                ))}
              </TextField>
            )}

            {kind === 'apt' && (
              <Autocomplete
                size="small"
                options={groups}
                getOptionLabel={(g) =>
                  typeof g === 'string' ? g : `${g.group_id} · ${g.name}`
                }
                onInputChange={(_, v) => setGroupQuery(v)}
                onChange={(_, v) => setRef(v ? v.group_id : '')}
                sx={{ minWidth: 300 }}
                renderInput={(params) => (
                  <TextField {...params} label="APT group" placeholder="e.g. APT28" />
                )}
              />
            )}

            <Box sx={{ flex: 1 }} />

            {score && (
              <Stack direction="row" spacing={2} alignItems="center">
                <PostureBadge grade={score.posture_grade} />
                <Stack spacing={0}>
                  <Typography variant="caption" color="text.secondary">
                    Breadth {Math.round(score.breadth_pct * 100)}% ·{' '}
                    {score.breadth_grade} &nbsp;|&nbsp; Depth{' '}
                    {score.depth_avg.toFixed(1)} · {score.depth_grade}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {score.covered_count}/{score.denominator_size} covered ·{' '}
                    {score.deployed_count} deployed
                  </Typography>
                </Stack>
                <Tooltip title="Save snapshot to history">
                  <span>
                    <IconButton
                      onClick={snapshot}
                      disabled={savingSnapshot}
                      color="primary"
                    >
                      <SaveAltRoundedIcon />
                    </IconButton>
                  </span>
                </Tooltip>
              </Stack>
            )}
          </Stack>
          {snapshotMsg && (
            <Typography
              variant="caption"
              color="text.secondary"
              sx={{ display: 'block', mt: 1 }}
            >
              {snapshotMsg}
            </Typography>
          )}
        </CardContent>
      </Card>

      {matrix && (
        <Card>
          <CardContent sx={{ p: { xs: 2, md: 2.5 }, '&:last-child': { pb: { xs: 2, md: 2.5 } } }}>
            <Stack spacing={1.5}>
              <Stack
                direction={{ xs: 'column', md: 'row' }}
                spacing={1.5}
                alignItems={{ md: 'center' }}
              >
                <TextField
                  size="small"
                  placeholder="Search by technique ID or name (e.g. T1059, PowerShell)"
                  value={searchInput}
                  onChange={(e) => setSearchInput(e.target.value)}
                  sx={{ flex: 1, minWidth: { md: 320 } }}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start">
                        <SearchRoundedIcon fontSize="small" />
                      </InputAdornment>
                    ),
                    endAdornment: searchInput ? (
                      <InputAdornment position="end">
                        <IconButton
                          size="small"
                          onClick={() => setSearchInput('')}
                          aria-label="clear search"
                        >
                          <CloseRoundedIcon fontSize="small" />
                        </IconButton>
                      </InputAdornment>
                    ) : null,
                  }}
                />

                <TextField
                  select
                  size="small"
                  label="Scope"
                  value={subScope}
                  onChange={(e) => setSubScope(e.target.value as SubTechScope)}
                  sx={{ minWidth: 160 }}
                >
                  <MenuItem value="all">All techniques</MenuItem>
                  <MenuItem value="parents">Top-level only</MenuItem>
                  <MenuItem value="subs">Sub-techniques only</MenuItem>
                </TextField>

                <Autocomplete
                  multiple
                  size="small"
                  options={matrix.tactics}
                  value={tacticFilter}
                  onChange={(_, v) => setTacticFilter(v)}
                  getOptionLabel={tacticLabel}
                  sx={{ minWidth: 240, flex: { md: 1 } }}
                  renderTags={(value, getTagProps) =>
                    value.map((option, index) => (
                      <Chip
                        size="small"
                        label={tacticLabel(option)}
                        {...getTagProps({ index })}
                        key={option}
                      />
                    ))
                  }
                  renderInput={(params) => (
                    <TextField {...params} label="Tactic" placeholder="Any tactic" />
                  )}
                />

                <TextField
                  select
                  size="small"
                  label="Compliance framework"
                  value={frameworkFilter}
                  onChange={(e) => setFrameworkFilter(e.target.value)}
                  sx={{ minWidth: 220 }}
                  helperText={
                    frameworkFilter && frameworkTechSet
                      ? `${frameworkTechSet.size} techniques mapped`
                      : ' '
                  }
                >
                  <MenuItem value="">No framework filter</MenuItem>
                  {(() => {
                    // Group like the GRC picker: international standards first,
                    // then the Saudi NCA family. Inside the NCA group the
                    // "NCA " prefix is dropped — the group header implies it.
                    const intl = grcFrameworks.filter(
                      (f) => !f.key.startsWith('nca_'),
                    );
                    const nca = grcFrameworks.filter((f) =>
                      f.key.startsWith('nca_'),
                    );
                    const items: React.ReactNode[] = [];
                    if (intl.length > 0) {
                      items.push(
                        <ListSubheader
                          key="hdr-intl"
                          disableSticky
                          sx={{ bgcolor: 'transparent' }}
                        >
                          International standards
                        </ListSubheader>,
                      );
                      for (const f of intl) {
                        items.push(
                          <MenuItem key={f.key} value={f.key}>
                            {f.label}
                            {f.version ? ` · ${f.version}` : ''}
                          </MenuItem>,
                        );
                      }
                    }
                    if (nca.length > 0) {
                      items.push(
                        <ListSubheader
                          key="hdr-nca"
                          disableSticky
                          sx={{ bgcolor: 'transparent' }}
                        >
                          Saudi NCA
                        </ListSubheader>,
                      );
                      for (const f of nca) {
                        const short = f.label.replace(/^NCA\s+/i, '');
                        items.push(
                          <MenuItem key={f.key} value={f.key}>
                            {short}
                            {f.version ? ` · ${f.version}` : ''}
                          </MenuItem>,
                        );
                      }
                    }
                    return items;
                  })()}
                </TextField>

                <Button
                  size="small"
                  variant="outlined"
                  onClick={(e) => setViewsMenuAnchor(e.currentTarget)}
                  startIcon={<BookmarkBorderRoundedIcon fontSize="small" />}
                >
                  Views ({views.length})
                </Button>
                <Menu
                  anchorEl={viewsMenuAnchor}
                  open={Boolean(viewsMenuAnchor)}
                  onClose={() => setViewsMenuAnchor(null)}
                >
                  <MenuItem
                    onClick={() => {
                      setSaveDialogOpen(true);
                      setViewsMenuAnchor(null);
                    }}
                  >
                    <Stack direction="row" spacing={1} alignItems="center">
                      <SaveAltRoundedIcon fontSize="small" />
                      <Typography variant="body2">Save current filters…</Typography>
                    </Stack>
                  </MenuItem>
                  {views.length > 0 && <Divider />}
                  {views.map((v) => (
                    <MenuItem
                      key={v.id}
                      onClick={() => handleLoadView(v)}
                      sx={{ pr: 1 }}
                    >
                      <Stack
                        direction="row"
                        spacing={1}
                        alignItems="center"
                        sx={{ flex: 1 }}
                      >
                        <Box sx={{ flex: 1, minWidth: 0 }}>
                          <Typography variant="body2" sx={{ fontWeight: 600 }}>
                            {v.name}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {(v.payload as any)?.kind ?? '?'} ·{' '}
                            {(v.payload as any)?.ref || '—'}
                          </Typography>
                        </Box>
                        <IconButton
                          size="small"
                          onClick={(ev) => {
                            ev.stopPropagation();
                            handleDeleteView(v.id);
                          }}
                          aria-label="delete view"
                        >
                          <CloseRoundedIcon fontSize="small" />
                        </IconButton>
                      </Stack>
                    </MenuItem>
                  ))}
                </Menu>

                {hasFilter && (
                  <Tooltip title="Clear all filters">
                    <Button
                      size="small"
                      onClick={resetFilters}
                      startIcon={<FilterAltOffRoundedIcon fontSize="small" />}
                    >
                      Reset
                    </Button>
                  </Tooltip>
                )}
              </Stack>

              <Stack
                direction="row"
                spacing={1}
                alignItems="center"
                flexWrap="wrap"
                useFlexGap
              >
                <Typography
                  variant="caption"
                  color="text.secondary"
                  sx={{ fontWeight: 600, mr: 0.5 }}
                >
                  State:
                </Typography>
                {ALL_STATES.map((s) => {
                  const active = stateFilter.has(s);
                  const color = STATE_COLOR[s];
                  return (
                    <Chip
                      key={s}
                      label={STATE_LABEL[s]}
                      size="small"
                      onClick={() => toggleState(s)}
                      sx={(t) => ({
                        cursor: 'pointer',
                        fontWeight: 600,
                        bgcolor: active ? color : alpha(color, 0.16),
                        color: active ? '#ffffff' : color,
                        border: `1px solid ${active ? color : alpha(color, 0.45)}`,
                        '&:hover': {
                          bgcolor: active ? color : alpha(color, 0.28),
                        },
                      })}
                    />
                  );
                })}
                {siem && siem.use_case_count > 0 && (
                  <Stack direction="row" alignItems="center" spacing={0.5} sx={{ ml: 1 }}>
                    <Box
                      sx={{
                        width: 8,
                        height: 8,
                        borderRadius: '50%',
                        bgcolor: 'text.primary',
                        border: '2px solid',
                        borderColor: 'background.paper',
                        boxShadow: '0 0 0 1px rgba(0,0,0,0.3)',
                      }}
                    />
                    <Typography variant="caption" color="text.secondary">
                      deployed in SIEM ({siemTechs.size})
                    </Typography>
                  </Stack>
                )}
                <Box sx={{ flex: 1 }} />
                <Typography variant="caption" color="text.secondary">
                  Showing <strong>{filteredCount}</strong> of {totalTechniques}{' '}
                  techniques
                </Typography>
              </Stack>

              <Divider sx={{ my: 0.5 }} />

              <Stack
                direction={{ xs: 'column', md: 'row' }}
                spacing={1.5}
                alignItems={{ md: 'center' }}
                flexWrap="wrap"
                useFlexGap
              >
                <Stack direction="row" alignItems="center" spacing={1}>
                  <Typography
                    variant="caption"
                    color="text.secondary"
                    sx={{ fontWeight: 600 }}
                  >
                    Color:
                  </Typography>
                  <ToggleButtonGroup
                    size="small"
                    exclusive
                    value={colorMode}
                    onChange={(_, v) => v && setColorMode(v as ColorMode)}
                    sx={{
                      '& .MuiToggleButton-root': {
                        textTransform: 'none',
                        py: 0.25,
                        px: 1.25,
                        fontSize: '0.72rem',
                        fontWeight: 600,
                      },
                    }}
                  >
                    <ToggleButton value="state">State</ToggleButton>
                    <ToggleButton value="heatmap">Heatmap (depth)</ToggleButton>
                  </ToggleButtonGroup>
                </Stack>

                <Stack direction="row" alignItems="center" spacing={1}>
                  <Typography
                    variant="caption"
                    color="text.secondary"
                    sx={{ fontWeight: 600 }}
                  >
                    Sort in column:
                  </Typography>
                  <ToggleButtonGroup
                    size="small"
                    exclusive
                    value={columnSort}
                    onChange={(_, v) => v && setColumnSort(v as ColumnSort)}
                    sx={{
                      '& .MuiToggleButton-root': {
                        textTransform: 'none',
                        py: 0.25,
                        px: 1.25,
                        fontSize: '0.72rem',
                        fontWeight: 600,
                      },
                    }}
                  >
                    <ToggleButton value="state">Gaps first</ToggleButton>
                    <ToggleButton value="detections">Most rules</ToggleButton>
                    <ToggleButton value="tactic">A→Z</ToggleButton>
                  </ToggleButtonGroup>
                </Stack>

                <Stack direction="row" alignItems="center" spacing={1}>
                  <Chip
                    size="small"
                    label={collapseSubs ? 'Sub-techniques grouped' : 'Flat list'}
                    onClick={() => setCollapseSubs((v) => !v)}
                    sx={{ cursor: 'pointer', fontWeight: 600 }}
                  />
                </Stack>

                <Box sx={{ flex: 1 }} />

                <Stack direction="row" alignItems="center" spacing={1}>
                  <HistoryRoundedIcon fontSize="small" color="action" />
                  <TextField
                    select
                    size="small"
                    label="Compare to snapshot"
                    value={compareSnapshotId}
                    onChange={(e) => setCompareSnapshotId(e.target.value)}
                    sx={{ minWidth: 260 }}
                  >
                    <MenuItem value="">— none —</MenuItem>
                    {snapshots
                      .filter(
                        (s) =>
                          s.denominator_kind === kind &&
                          (s.denominator_ref ?? null) ===
                            (kind === 'full' ? null : ref || null),
                      )
                      .map((s) => (
                        <MenuItem key={s.id} value={s.id}>
                          {new Date(s.taken_at).toLocaleString()} ·{' '}
                          {s.posture_grade}
                        </MenuItem>
                      ))}
                  </TextField>
                </Stack>
              </Stack>

              {delta && (
                <Stack
                  direction="row"
                  spacing={1.5}
                  alignItems="center"
                  flexWrap="wrap"
                  useFlexGap
                  sx={{
                    p: 1,
                    borderRadius: 2,
                    bgcolor: (t) => alpha(t.palette.primary.main, 0.06),
                  }}
                >
                  <Typography variant="caption" sx={{ fontWeight: 700 }}>
                    Delta since{' '}
                    {new Date(delta.snapshot_taken_at).toLocaleString()}:
                  </Typography>
                  <DeltaPill
                    icon={<TrendingUpRoundedIcon sx={{ fontSize: 14 }} />}
                    label={`${delta.summary.improved} improved`}
                    color={coverage.green}
                  />
                  <DeltaPill
                    icon={<TrendingDownRoundedIcon sx={{ fontSize: 14 }} />}
                    label={`${delta.summary.regressed} regressed`}
                    color={coverage.red}
                  />
                  <DeltaPill
                    icon={<FiberNewRoundedIcon sx={{ fontSize: 14 }} />}
                    label={`${delta.summary.new} new`}
                    color="#26d4ee"
                  />
                  <DeltaPill
                    label={`${delta.summary.unchanged} unchanged`}
                    color={coverage.grey}
                  />
                  <Box sx={{ flex: 1 }} />
                  <Button
                    size="small"
                    onClick={() => setCompareSnapshotId('')}
                    startIcon={<CloseRoundedIcon fontSize="small" />}
                  >
                    Hide delta
                  </Button>
                </Stack>
              )}
              {deltaError && (
                <Typography variant="caption" color="error">
                  {deltaError}
                </Typography>
              )}
            </Stack>
          </CardContent>
        </Card>
      )}

      {error && (
        <Card>
          <CardContent>
            <Typography color="error">{error}</Typography>
          </CardContent>
        </Card>
      )}

      {!error && loading && (
        <Box sx={{ py: 6, display: 'flex', justifyContent: 'center' }}>
          <CircularProgress />
        </Box>
      )}

      {!loading && !matrix && !error && (
        <Card>
          <CardContent>
            <Typography color="text.secondary">
              Pick a {kind === 'sector' ? 'sector' : 'group'} to compute the
              coverage matrix.
            </Typography>
          </CardContent>
        </Card>
      )}

      {matrix && !loading && filteredCount === 0 && hasFilter && (
        <Card>
          <CardContent>
            <Stack
              direction="row"
              spacing={1.5}
              alignItems="center"
              justifyContent="space-between"
            >
              <Typography color="text.secondary">
                No techniques match the current filters.
              </Typography>
              <Button
                size="small"
                onClick={resetFilters}
                startIcon={<FilterAltOffRoundedIcon fontSize="small" />}
              >
                Reset filters
              </Button>
            </Stack>
          </CardContent>
        </Card>
      )}

      {matrix && !loading && filteredCount > 0 && filteredByTactic && (
        <Paper variant="outlined" sx={{ overflow: 'auto' }}>
          {focusedTactic && (
            <Stack
              direction="row"
              alignItems="center"
              spacing={1}
              sx={(t) => ({
                px: 1.5,
                py: 1,
                bgcolor: alpha(t.palette.primary.main, 0.06),
                borderBottom: 1,
                borderColor: 'divider',
              })}
            >
              <Typography variant="caption" sx={{ fontWeight: 700, letterSpacing: '0.04em' }}>
                FOCUSED TACTIC
              </Typography>
              <Chip
                size="small"
                label={tacticLabel(focusedTactic)}
                color="primary"
                sx={{ fontWeight: 700 }}
              />
              <Box sx={{ flex: 1 }} />
              <Button size="small" onClick={() => setFocusedTactic(null)}>
                Show all tactics
              </Button>
            </Stack>
          )}
          {focusedTactic ? (
            <TacticTable
              groups={groupCells(filteredByTactic[focusedTactic] ?? [])}
              tactic={focusedTactic}
              deltaByTechnique={deltaByTechnique}
              siemTechs={siemTechs}
              openTechniqueId={openCell?.technique_id ?? null}
              onRowClick={(c) => setOpenCell(c)}
            />
          ) : (
          <Box
            sx={{
              display: 'grid',
              gridAutoFlow: 'column',
              gridAutoColumns: 'minmax(180px, 1fr)',
              gap: 0,
              minWidth: matrix.tactics.length * 190,
            }}
          >
            {matrix.tactics.map((tac) => {
              const cells = filteredByTactic[tac] ?? [];
              const original = matrix.by_tactic[tac]?.length ?? 0;
              const posture = tacticPosture[tac] ?? { covered: 0, total: 0, pct: 0 };
              const groups = groupCells(cells);
              return (
                <Box
                  key={tac}
                  sx={{
                    borderRight: 1,
                    borderColor: 'divider',
                    '&:last-of-type': { borderRight: 0 },
                  }}
                >
                  <Box
                    onClick={() =>
                      setFocusedTactic((current) =>
                        current === tac ? null : tac,
                      )
                    }
                    role="button"
                    aria-pressed={focusedTactic === tac}
                    title={
                      focusedTactic === tac
                        ? 'Click to show all tactics'
                        : `Focus on ${tacticLabel(tac)}`
                    }
                    sx={(t) => ({
                      px: 1,
                      py: 1,
                      borderBottom: 1,
                      borderColor: 'divider',
                      bgcolor:
                        focusedTactic === tac
                          ? alpha(t.palette.primary.main, 0.14)
                          : 'grey.50',
                      ...(focusedTactic === tac
                        ? {}
                        : t.applyStyles('dark', {
                            // dark.bgPaper (#161d33) at 0.6 — alpha() can't
                            // take a CSS var, so use the resolved rgba.
                            bgcolor: 'rgba(22,29,51,0.6)',
                          })),
                      position: 'sticky',
                      top: 0,
                      zIndex: 1,
                      cursor: 'pointer',
                      '&:hover': {
                        bgcolor: alpha(t.palette.primary.main, 0.08),
                      },
                    })}
                  >
                    <Stack
                      direction="row"
                      alignItems="center"
                      spacing={0.75}
                      mb={0.25}
                    >
                      <Typography
                        variant="caption"
                        sx={(t) => ({
                          fontWeight: 700,
                          letterSpacing: '0.02em',
                          flex: 1,
                          minWidth: 0,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                          color:
                            focusedTactic === tac
                              ? t.palette.primary.main
                              : undefined,
                        })}
                      >
                        {tacticLabel(tac)}
                      </Typography>
                      <Tooltip
                        title={`${posture.covered}/${posture.total} techniques covered (deployed + in progress)`}
                      >
                        <Chip
                          size="small"
                          label={`${Math.round(posture.pct * 100)}%`}
                          sx={{
                            height: 18,
                            fontSize: '0.65rem',
                            fontWeight: 800,
                            fontFamily: 'JetBrains Mono, monospace',
                            bgcolor: alpha(
                              postureBucketColor(posture.pct),
                              0.22,
                            ),
                            color: postureBucketColor(posture.pct),
                            '& .MuiChip-label': { px: 0.75 },
                          }}
                        />
                      </Tooltip>
                    </Stack>
                    <Typography
                      variant="caption"
                      color="text.secondary"
                      display="block"
                      sx={{ fontSize: '0.66rem' }}
                    >
                      {hasFilter && cells.length !== original
                        ? `${cells.length} / ${original} techniques`
                        : `${original} techniques`}
                    </Typography>
                    <Box sx={{ mt: 0.5 }}>
                      <LinearProgress
                        variant="determinate"
                        value={Math.round(posture.pct * 100)}
                        sx={(t) => ({
                          height: 3,
                          borderRadius: 4,
                          bgcolor: 'rgba(15,18,35,0.06)',
                          ...t.applyStyles('dark', {
                            bgcolor: 'rgba(255,255,255,0.06)',
                          }),
                          '& .MuiLinearProgress-bar': {
                            bgcolor: postureBucketColor(posture.pct),
                            borderRadius: 4,
                          },
                        })}
                      />
                    </Box>
                  </Box>
                  <Stack
                    spacing={0.5}
                    sx={{ p: 1, minHeight: maxColumnHeight * 38 }}
                  >
                    {cells.length === 0 ? (
                      <Typography
                        variant="caption"
                        color="text.secondary"
                        sx={{ textAlign: 'center', py: 1, opacity: 0.6 }}
                      >
                        —
                      </Typography>
                    ) : (
                      groups.map((g, gi) => {
                        const expanded = g.parent
                          ? expandedParents.has(g.parent.technique_id)
                          : true;
                        return (
                          <Box key={`${tac}-grp-${gi}`}>
                            {g.parent && (
                              <TechniqueCellChip
                                cell={g.parent}
                                onClick={() => setOpenCell(g.parent!)}
                                selected={
                                  openCell?.technique_id ===
                                  g.parent.technique_id
                                }
                                colorMode={colorMode}
                                siem={siemTechs.has(g.parent.technique_id)}
                                deltaCell={deltaByTechnique.get(
                                  g.parent.technique_id,
                                )}
                                subCount={g.subs.length}
                                expanded={
                                  g.subs.length > 0 ? expanded : undefined
                                }
                                onToggleExpand={
                                  g.subs.length > 0
                                    ? (e) => {
                                        e.stopPropagation();
                                        toggleParent(g.parent!.technique_id);
                                      }
                                    : undefined
                                }
                              />
                            )}
                            {g.subs.length > 0 && (
                              <Collapse in={expanded} timeout={120}>
                                <Stack spacing={0.5} sx={{ pl: 1.5, mt: 0.5 }}>
                                  {g.subs.map((sub) => (
                                    <TechniqueCellChip
                                      key={`${tac}-${sub.technique_id}`}
                                      cell={sub}
                                      onClick={() => setOpenCell(sub)}
                                      selected={
                                        openCell?.technique_id ===
                                        sub.technique_id
                                      }
                                      colorMode={colorMode}
                                      siem={siemTechs.has(sub.technique_id)}
                                      deltaCell={deltaByTechnique.get(
                                        sub.technique_id,
                                      )}
                                    />
                                  ))}
                                </Stack>
                              </Collapse>
                            )}
                          </Box>
                        );
                      })
                    )}
                  </Stack>
                </Box>
              );
            })}
          </Box>
          )}
        </Paper>
      )}

      <Drawer
        anchor="right"
        open={openCell !== null}
        onClose={() => setOpenCell(null)}
        PaperProps={{ sx: { width: { xs: '100%', md: 540 } } }}
      >
        {openCell && (
          <TechniqueDrawer
            cell={openCell}
            siemUseCases={siem?.by_technique?.[openCell.technique_id] ?? []}
            onClose={() => setOpenCell(null)}
            onCellRefresh={() => {
              // Re-fetch the matrix so state/count changes after edits
              // reflect in the grid behind the drawer.
              load();
            }}
          />
        )}
      </Drawer>

      <Dialog
        open={saveDialogOpen}
        onClose={() => setSaveDialogOpen(false)}
        maxWidth="xs"
        fullWidth
      >
        <DialogTitle>Save current filters as a view</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            fullWidth
            label="View name"
            value={newViewName}
            onChange={(e) => setNewViewName(e.target.value)}
            placeholder="e.g. APT29 gaps in Finance"
            size="small"
            sx={{ mt: 1 }}
          />
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1.5 }}>
            Captures denominator, search, state, tactic, scope, color mode, and column sort.
            Existing view with the same name is overwritten.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSaveDialogOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleSaveView}
            disabled={!newViewName.trim()}
          >
            Save
          </Button>
        </DialogActions>
      </Dialog>

      <CustomDenominatorDialog
        open={customDialogOpen}
        initial={customSpec}
        sectors={sectors}
        onClose={() => {
          // closing without saving while kind==='custom' but no spec → revert
          if (kind === 'custom' && !customSpec) setKind('full');
          setCustomDialogOpen(false);
        }}
        onApply={(spec) => {
          setCustomSpec(spec);
          setCustomDialogOpen(false);
        }}
      />
    </Box>
  );
}

function CustomDenominatorDialog({
  open,
  initial,
  sectors,
  onClose,
  onApply,
}: {
  open: boolean;
  initial: CustomDenominatorSpec | null;
  sectors: SectorProfileSummary[];
  onClose: () => void;
  onApply: (spec: CustomDenominatorSpec) => void;
}) {
  const [selSectors, setSelSectors] = useState<string[]>(initial?.sectors ?? []);
  const [aptInput, setAptInput] = useState('');
  const [apts, setApts] = useState<string[]>(initial?.apt_groups ?? []);
  const [platforms, setPlatforms] = useState<string[]>(initial?.platforms ?? []);
  const [op, setOp] = useState<'union' | 'intersection'>(
    initial?.operator ?? 'union',
  );

  useEffect(() => {
    if (!open) return;
    setSelSectors(initial?.sectors ?? []);
    setApts(initial?.apt_groups ?? []);
    setPlatforms(initial?.platforms ?? []);
    setOp(initial?.operator ?? 'union');
    setAptInput('');
  }, [open, initial]);

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Custom denominator</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <Autocomplete
            multiple
            size="small"
            options={sectors.map((s) => s.sector)}
            value={selSectors}
            onChange={(_, v) => setSelSectors(v)}
            getOptionLabel={(s) =>
              sectors.find((x) => x.sector === s)?.label ?? s
            }
            renderInput={(params) => (
              <TextField {...params} label="Sectors" placeholder="finance, energy…" />
            )}
          />

          <Autocomplete
            multiple
            freeSolo
            size="small"
            options={[]}
            value={apts}
            inputValue={aptInput}
            onInputChange={(_, v) => setAptInput(v)}
            onChange={(_, v) => setApts(v as string[])}
            renderInput={(params) => (
              <TextField
                {...params}
                label="APT groups"
                placeholder="G0007 (press Enter), G0016…"
              />
            )}
          />

          <Autocomplete
            multiple
            freeSolo
            size="small"
            options={[
              'Windows',
              'Linux',
              'macOS',
              'Containers',
              'IaaS',
              'SaaS',
              'Office Suite',
              'Network Devices',
              'Identity Provider',
              'ESXi',
            ]}
            value={platforms}
            onChange={(_, v) => setPlatforms(v as string[])}
            renderInput={(params) => (
              <TextField {...params} label="Platforms" placeholder="Windows, Linux…" />
            )}
          />

          <TextField
            select
            size="small"
            label="Combine sources by"
            value={op}
            onChange={(e) => setOp(e.target.value as 'union' | 'intersection')}
          >
            <MenuItem value="union">Union — anything in any source</MenuItem>
            <MenuItem value="intersection">Intersection — only techniques in all sources</MenuItem>
          </TextField>

          <Typography variant="caption" color="text.secondary">
            Platform list always acts as a filter applied after the combine
            step. Leave all sources empty to start with the full ATT&amp;CK
            universe and narrow by platform only.
          </Typography>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button
          variant="contained"
          onClick={() =>
            onApply({
              sectors: selSectors,
              apt_groups: apts,
              platforms,
              operator: op,
            })
          }
          disabled={
            selSectors.length === 0 &&
            apts.length === 0 &&
            platforms.length === 0
          }
        >
          Apply
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function PostureBadge({ grade }: { grade: string }) {
  const color =
    grade === 'A'
      ? coverage.green
      : grade === 'B'
        ? coverage.amber
        : grade === 'C'
          ? '#e8895d'
          : coverage.red;
  return (
    <Box
      sx={{
        width: 56,
        height: 56,
        borderRadius: '14px',
        bgcolor: alpha(color, 0.12),
        border: `2px solid ${color}`,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      <Typography
        sx={{
          fontWeight: 800,
          color,
          fontSize: '1.8rem',
          letterSpacing: '-0.04em',
        }}
      >
        {grade}
      </Typography>
    </Box>
  );
}

const DETECTION_STATUS_OPTIONS = [
  'idea',
  'in_development',
  'tuning',
  'deployed',
  'gap',
  'not_applicable',
] as const;

const DETECTION_STATUS_LABEL: Record<string, string> = {
  idea: 'Idea',
  in_development: 'In development',
  tuning: 'Tuning',
  deployed: 'Deployed',
  gap: 'Gap',
  not_applicable: 'N/A',
};

const SOURCE_LABEL: Record<string, string> = {
  global: 'Global',
  customized: 'Customized',
  custom: 'Custom',
};

function mitreTechniqueUrl(technique_id: string): string {
  // ATT&CK URLs use the parent + sub form, e.g. T1059.001 → /T1059/001/
  const [parent, sub] = technique_id.split('.');
  return sub
    ? `https://attack.mitre.org/techniques/${parent}/${sub}/`
    : `https://attack.mitre.org/techniques/${parent}/`;
}

function TechniqueDrawer({
  cell,
  siemUseCases = [],
  onClose,
  onCellRefresh,
}: {
  cell: CoverageCell;
  siemUseCases?: SiemUseCaseRef[];
  onClose: () => void;
  onCellRefresh: () => void;
}) {
  const canEdit = useCanEditDetections();
  const detectionsPath = usePathname().startsWith('/portal/') ? '/portal/detections' : '/dashboard/detections';
  const [detail, setDetail] = useState<TechniqueDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [noteInput, setNoteInput] = useState('');
  const [editingNote, setEditingNote] = useState(false);
  const [savingNote, setSavingNote] = useState(false);
  const [statusAction, setStatusAction] = useState<ChangePurposeAction | null>(null);
  const [aiOpen, setAiOpen] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setDetail(null);
    setEditingNote(false);
    setAiOpen(false);
    setStatusAction(null);
    getTechniqueDetail(cell.technique_id)
      .then((d) => {
        if (cancelled) return;
        setDetail(d);
        setNoteInput(d.note?.body ?? '');
      })
      .catch((e) => {
        if (cancelled) return;
        setError(e?.response?.data?.detail ?? 'failed to load technique detail');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [cell.technique_id]);

  async function saveNote() {
    setSavingNote(true);
    try {
      const note = await upsertTechniqueNote(cell.technique_id, noteInput);
      setDetail((d) => (d ? { ...d, note } : d));
      setEditingNote(false);
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'failed to save note');
    } finally {
      setSavingNote(false);
    }
  }

  async function removeNote() {
    setSavingNote(true);
    try {
      await deleteTechniqueNote(cell.technique_id);
      setDetail((d) => (d ? { ...d, note: null } : d));
      setNoteInput('');
      setEditingNote(false);
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'failed to delete note');
    } finally {
      setSavingNote(false);
    }
  }

  function confirmStatusChange(detection: DetectionRef, nextStatus: string) {
    if (detection.detection_status === nextStatus) return;
    const status = DETECTION_STATUS_LABEL[nextStatus];
    setStatusAction({
      title: 'Change status',
      description: detection.source === 'global'
        ? `Save a workspace copy of ${detection.title} with status ${status}.`
        : `Set ${detection.title} to ${status}.`,
      onSave: async (purpose) => {
        const updated = await patchDetection(detection.id, {
          detection_status: nextStatus,
          change_reason: purpose,
          expected_version: detection.version,
        });
        setDetail((current) => current ? {
          ...current,
          detections: current.detections.map((item) => item.id === detection.id ? updated : item),
        } : current);
        onCellRefresh();
      },
      onReload: async () => setDetail(await getTechniqueDetail(cell.technique_id)),
    });
  }

  const draftDetectionHref = `/dashboard/detections?draft_for=${encodeURIComponent(cell.technique_id)}`;

  return (
    <Box sx={{ p: 3, display: 'flex', flexDirection: 'column', gap: 2 }}>
      {/* header */}
      <Stack direction="row" alignItems="center" spacing={1}>
        <Typography
          sx={{
            flex: 1,
            fontFamily: 'JetBrains Mono, monospace',
            fontWeight: 700,
            fontSize: '0.95rem',
          }}
        >
          {cell.technique_id}
        </Typography>
        <Tooltip title="Open on attack.mitre.org">
          <IconButton
            size="small"
            component="a"
            href={mitreTechniqueUrl(cell.technique_id)}
            target="_blank"
            rel="noopener noreferrer"
          >
            <OpenInNewRoundedIcon fontSize="small" />
          </IconButton>
        </Tooltip>
        <Chip
          label={STATE_LABEL[cell.state]}
          size="small"
          sx={{
            bgcolor: STATE_COLOR[cell.state],
            color: '#ffffff',
            fontWeight: 700,
          }}
        />
        <IconButton onClick={onClose} size="small">
          <CloseRoundedIcon />
        </IconButton>
      </Stack>

      <Typography variant="h6" sx={{ fontWeight: 700 }}>
        {cell.name}
      </Typography>

      <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
        {cell.tactics.map((t) => (
          <Chip key={t} label={tacticLabel(t)} size="small" variant="outlined" />
        ))}
        {cell.is_subtechnique && (
          <Chip label="sub-technique" size="small" color="primary" />
        )}
        {cell.parent_technique_id && (
          <Chip
            label={`parent ${cell.parent_technique_id}`}
            size="small"
            variant="outlined"
            sx={{ fontFamily: 'JetBrains Mono, monospace' }}
          />
        )}
        {detail?.platforms?.length ? (
          <Chip
            label={`platforms: ${detail.platforms.join(', ')}`}
            size="small"
            variant="outlined"
          />
        ) : null}
      </Stack>

      {/* numeric strip */}
      <Stack direction="row" spacing={3}>
        <Box>
          <Typography variant="caption" color="text.secondary">
            Detections
          </Typography>
          <Typography variant="h5">{cell.detection_count}</Typography>
        </Box>
        <Box>
          <Typography variant="caption" color="text.secondary">
            Deployed
          </Typography>
          <Typography variant="h5">{cell.deployed_count}</Typography>
        </Box>
        <Box>
          <Typography variant="caption" color="text.secondary">
            Max depth
          </Typography>
          <Typography variant="h5">{cell.max_depth}/5</Typography>
        </Box>
      </Stack>

      {detail?.description && (
        <>
          <Divider />
          <Typography variant="body2" color="text.secondary" sx={{ whiteSpace: 'pre-line' }}>
            {detail.description.length > 600
              ? detail.description.slice(0, 600).trim() + '…'
              : detail.description}
          </Typography>
        </>
      )}

      {/* detections section */}
      <Divider />
      <Stack direction="row" alignItems="center" spacing={1} flexWrap="wrap" useFlexGap>
        <RuleRoundedIcon fontSize="small" color="action" />
        <Typography variant="subtitle2" sx={{ fontWeight: 700, flex: 1 }}>
          Detections
        </Typography>
        <Button
          size="small"
          variant="text"
          startIcon={<AutoAwesomeRoundedIcon fontSize="small" />}
          onClick={() => setAiOpen((v) => !v)}
        >
          {aiOpen ? 'Hide AI draft' : 'Draft with AI'}
        </Button>
        <Button
          size="small"
          variant="outlined"
          component={MuiLink}
          href={draftDetectionHref}
          startIcon={<AddCircleOutlineRoundedIcon fontSize="small" />}
        >
          Draft a detection
        </Button>
      </Stack>
      {aiOpen && (
        <TechniqueAiDraft
          techniqueId={cell.technique_id}
          techniqueName={cell.name}
          tactic={cell.tactics[0]}
          onSaved={() => {
            onCellRefresh();
          }}
        />
      )}
      {loading ? (
        <Stack spacing={1}>
          <Skeleton variant="rectangular" height={48} />
          <Skeleton variant="rectangular" height={48} />
        </Stack>
      ) : detail && detail.detections.length === 0 ? (
        <Typography variant="body2" color="text.secondary">
          No detections mapped to this technique yet. Use the draft button above
          to start one with the right ATT&amp;CK tag pre-filled.
        </Typography>
      ) : (
        <Stack spacing={1}>
          {detail!.detections.map((d) => (
            <Box
              key={d.id}
              sx={(t) => ({
                border: `1px solid ${t.palette.divider}`,
                borderRadius: 2,
                p: 1.25,
              })}
            >
              <Stack direction="row" alignItems="baseline" spacing={1} mb={0.5}>
                <Typography
                  variant="caption"
                  sx={{
                    fontFamily: 'JetBrains Mono, monospace',
                    color: 'text.secondary',
                  }}
                >
                  {d.sigma_id.slice(0, 8)}…
                </Typography>
                <Typography
                  variant="body2"
                  sx={{ flex: 1, fontWeight: 600, minWidth: 0 }}
                >
                  {d.title}
                </Typography>
                <Chip
                  label={SOURCE_LABEL[d.source] ?? d.source}
                  size="small"
                  variant="outlined"
                  sx={{ height: 20, fontSize: '0.65rem' }}
                />
              </Stack>
              <Stack direction="row" alignItems="center" spacing={1}>
                <TextField
                  select
                  size="small"
                  value={d.detection_status}
                  onChange={(e) => confirmStatusChange(d, e.target.value)}
                  disabled={!canEdit}
                  sx={{ minWidth: 160 }}
                >
                  {DETECTION_STATUS_OPTIONS.map((s) => {
                    const needsApproval =
                      s === 'deployed' &&
                      d.detection_status !== 'deployed' &&
                      (d.source === 'global' || d.review_status !== 'approved');
                    return (
                      <MenuItem key={s} value={s} disabled={needsApproval}>
                        {DETECTION_STATUS_LABEL[s]}
                        {needsApproval ? ' (approval required)' : ''}
                      </MenuItem>
                    );
                  })}
                </TextField>
                <Tooltip title="Depth score (DeTT&CT A-D, 0–5)">
                  <Chip
                    label={`depth ${d.score_depth}/5`}
                    size="small"
                    sx={{ height: 22, fontFamily: 'JetBrains Mono, monospace' }}
                  />
                </Tooltip>
                {d.level && (
                  <Chip
                    label={d.level}
                    size="small"
                    sx={{ height: 22, textTransform: 'capitalize' }}
                  />
                )}
                <Box sx={{ flex: 1 }} />
                <Tooltip title="Open in detection library">
                  <IconButton
                    size="small"
                    component={MuiLink}
                    href={`${detectionsPath}?id=${d.id}`}
                    aria-label="Open in detection library"
                  >
                    <OpenInNewRoundedIcon fontSize="small" />
                  </IconButton>
                </Tooltip>
              </Stack>
            </Box>
          ))}
        </Stack>
      )}
      {statusAction && canEdit && (
        <ChangePurposeDialog action={statusAction} onClose={() => setStatusAction(null)} />
      )}

      {/* APT groups */}
      <Divider />
      <Stack direction="row" alignItems="center" spacing={1}>
        <GroupsRoundedIcon fontSize="small" color="action" />
        <Typography variant="subtitle2" sx={{ fontWeight: 700, flex: 1 }}>
          APT groups using this technique
        </Typography>
        {detail && (
          <Typography variant="caption" color="text.secondary">
            {detail.apt_groups.length}
          </Typography>
        )}
      </Stack>
      {loading ? (
        <Skeleton variant="rectangular" height={36} />
      ) : detail && detail.apt_groups.length === 0 ? (
        <Typography variant="body2" color="text.secondary">
          No tracked APT group uses this technique directly or via known software.
        </Typography>
      ) : (
        <Stack direction="row" spacing={0.75} flexWrap="wrap" useFlexGap>
          {detail!.apt_groups.map((g) => {
            const direct = g.via.includes('direct');
            const softwareNames = g.via
              .filter((v) => v.startsWith('software:'))
              .map((v) => v.split(':').slice(2).join(':'));
            const tip = [
              direct ? 'used directly' : null,
              softwareNames.length
                ? `via ${softwareNames.join(', ')}`
                : null,
            ]
              .filter(Boolean)
              .join(' · ');
            return (
              <Tooltip key={g.group_id} title={tip || g.group_id}>
                <Chip
                  size="small"
                  label={`${g.group_id} · ${g.name}`}
                  component={MuiLink}
                  href={`/dashboard/apt?group=${g.group_id}`}
                  clickable
                  sx={{
                    fontFamily: 'JetBrains Mono, monospace',
                    fontSize: '0.72rem',
                    cursor: 'pointer',
                  }}
                />
              </Tooltip>
            );
          })}
        </Stack>
      )}

      {/* Deployed in SIEM (from connectors) */}
      <Divider />
      <Stack direction="row" alignItems="center" spacing={1}>
        <StorageRoundedIcon fontSize="small" color="action" />
        <Typography variant="subtitle2" sx={{ fontWeight: 700, flex: 1 }}>
          Deployed in SIEM
        </Typography>
        <Typography variant="caption" color="text.secondary">
          {siemUseCases.length}
        </Typography>
      </Stack>
      {siemUseCases.length === 0 ? (
        <Typography variant="body2" color="text.secondary">
          No deployed SIEM rule mapped to this technique. Import use-cases on
          the connectors page to see production coverage here.
        </Typography>
      ) : (
        <Stack spacing={1}>
          {siemUseCases.map((u) => (
            <Box
              key={u.id}
              sx={(t) => ({
                border: `1px solid ${t.palette.divider}`,
                borderRadius: 2,
                p: 1,
              })}
            >
              <Stack direction="row" alignItems="baseline" spacing={1}>
                <Typography variant="body2" sx={{ flex: 1, fontWeight: 600 }}>
                  {u.name}
                </Typography>
                {!u.enabled && (
                  <Chip label="disabled" size="small" color="warning" variant="outlined" sx={{ height: 18, fontSize: '0.62rem' }} />
                )}
                {u.severity && (
                  <Chip label={u.severity} size="small" variant="outlined" sx={{ height: 18, fontSize: '0.62rem' }} />
                )}
              </Stack>
              <Typography variant="caption" color="text.secondary">
                {u.connector_label} · {u.connector_kind}
              </Typography>
            </Box>
          ))}
        </Stack>
      )}

      {/* Mitigations */}
      <Divider />
      <Stack direction="row" alignItems="center" spacing={1}>
        <ShieldRoundedIcon fontSize="small" color="action" />
        <Typography variant="subtitle2" sx={{ fontWeight: 700, flex: 1 }}>
          Mitigations
        </Typography>
        {detail && (
          <Typography variant="caption" color="text.secondary">
            {detail.mitigations.length}
          </Typography>
        )}
      </Stack>
      {loading ? (
        <Skeleton variant="rectangular" height={36} />
      ) : detail && detail.mitigations.length === 0 ? (
        <Typography variant="body2" color="text.secondary">
          No ATT&amp;CK mitigations linked to this technique.
        </Typography>
      ) : (
        <Stack spacing={1}>
          {detail!.mitigations.map((m) => (
            <Box
              key={m.mitigation_id}
              sx={(t) => ({
                border: `1px solid ${t.palette.divider}`,
                borderRadius: 2,
                p: 1,
              })}
            >
              <Stack direction="row" alignItems="baseline" spacing={1}>
                <Typography
                  variant="caption"
                  sx={{
                    fontFamily: 'JetBrains Mono, monospace',
                    fontWeight: 700,
                  }}
                >
                  {m.mitigation_id}
                </Typography>
                <Typography variant="body2" sx={{ flex: 1, fontWeight: 600 }}>
                  {m.name}
                </Typography>
                {m.url && (
                  <IconButton
                    size="small"
                    component="a"
                    href={m.url}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    <OpenInNewRoundedIcon fontSize="small" />
                  </IconButton>
                )}
              </Stack>
              {m.description && (
                <Typography
                  variant="caption"
                  color="text.secondary"
                  sx={{ display: 'block', mt: 0.5 }}
                >
                  {m.description.length > 200
                    ? m.description.slice(0, 200).trim() + '…'
                    : m.description}
                </Typography>
              )}
            </Box>
          ))}
        </Stack>
      )}

      {/* D3FEND defensive techniques */}
      <Divider />
      <Stack direction="row" alignItems="center" spacing={1}>
        <ShieldRoundedIcon fontSize="small" color="action" />
        <Typography variant="subtitle2" sx={{ fontWeight: 700, flex: 1 }}>
          D3FEND defenses
        </Typography>
        {detail && (
          <Typography variant="caption" color="text.secondary">
            {detail.d3fend?.length ?? 0}
          </Typography>
        )}
      </Stack>
      {loading ? (
        <Skeleton variant="rectangular" height={36} />
      ) : !detail?.d3fend || detail.d3fend.length === 0 ? (
        <Typography variant="body2" color="text.secondary">
          No D3FEND mapping for this technique. Run the D3FEND catalog
          refresh from Settings → Schedule to populate.
        </Typography>
      ) : (
        <Stack spacing={1}>
          {detail.d3fend.map((d) => (
            <Box
              key={`${d.d3fend_id}-${d.relation ?? ''}`}
              sx={(t) => ({
                border: `1px solid ${t.palette.divider}`,
                borderRadius: 2,
                p: 1,
              })}
            >
              <Stack direction="row" alignItems="baseline" spacing={1}>
                <Typography
                  variant="caption"
                  sx={{
                    fontFamily: 'JetBrains Mono, monospace',
                    fontWeight: 700,
                  }}
                >
                  {d.d3fend_id}
                </Typography>
                <Typography variant="body2" sx={{ flex: 1, fontWeight: 600 }}>
                  {d.name}
                </Typography>
                {d.relation && (
                  <Chip
                    size="small"
                    label={d.relation}
                    variant="outlined"
                    sx={{ height: 18, fontSize: '0.6rem' }}
                  />
                )}
                {d.url && (
                  <IconButton
                    size="small"
                    component="a"
                    href={d.url}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    <OpenInNewRoundedIcon fontSize="small" />
                  </IconButton>
                )}
              </Stack>
            </Box>
          ))}
        </Stack>
      )}

      {/* Notes */}
      <Divider />
      <Stack direction="row" alignItems="center" spacing={1}>
        <NotesRoundedIcon fontSize="small" color="action" />
        <Typography variant="subtitle2" sx={{ fontWeight: 700, flex: 1 }}>
          Analyst note
        </Typography>
        {detail?.note && !editingNote && (
          <Button size="small" onClick={() => setEditingNote(true)}>
            Edit
          </Button>
        )}
      </Stack>
      {loading ? (
        <Skeleton variant="rectangular" height={48} />
      ) : editingNote || !detail?.note ? (
        <Stack spacing={1}>
          <TextField
            multiline
            minRows={3}
            placeholder="Rationale, references, compensating controls…"
            value={noteInput}
            onChange={(e) => setNoteInput(e.target.value)}
            size="small"
            fullWidth
          />
          <Stack direction="row" spacing={1} justifyContent="flex-end">
            {detail?.note && (
              <Button
                size="small"
                color="error"
                onClick={removeNote}
                disabled={savingNote}
              >
                Delete
              </Button>
            )}
            {editingNote && (
              <Button
                size="small"
                onClick={() => {
                  setEditingNote(false);
                  setNoteInput(detail?.note?.body ?? '');
                }}
                disabled={savingNote}
              >
                Cancel
              </Button>
            )}
            <Button
              size="small"
              variant="contained"
              onClick={saveNote}
              disabled={savingNote || !noteInput.trim()}
            >
              {savingNote ? 'Saving…' : 'Save note'}
            </Button>
          </Stack>
        </Stack>
      ) : (
        <Box
          sx={(t) => ({
            border: `1px solid ${t.palette.divider}`,
            borderRadius: 2,
            p: 1.5,
            bgcolor: alpha(t.palette.primary.main, 0.04),
          })}
        >
          <Typography variant="body2" sx={{ whiteSpace: 'pre-line' }}>
            {detail.note.body}
          </Typography>
          <Typography
            variant="caption"
            color="text.secondary"
            sx={{ display: 'block', mt: 1 }}
          >
            {detail.note.author_email
              ? `${detail.note.author_email} · `
              : ''}
            {detail.note.updated_at
              ? new Date(detail.note.updated_at).toLocaleString()
              : ''}
          </Typography>
        </Box>
      )}

      {error && (
        <Typography variant="caption" color="error">
          {error}
        </Typography>
      )}
    </Box>
  );
}

function postureBucketColor(pct: number): string {
  if (pct >= 0.75) return coverage.green;
  if (pct >= 0.5) return coverage.amber;
  if (pct >= 0.25) return '#e8895d';
  return coverage.red;
}

function cellBackground(cell: CoverageCell, mode: ColorMode): string {
  if (mode === 'heatmap') {
    // Heatmap colors by depth (0..5). Out-of-scope keeps neutral grey.
    if (cell.state === 'out_of_scope') return coverage.grey;
    const d = Math.max(0, Math.min(5, cell.max_depth));
    return HEATMAP_RAMP[d];
  }
  return STATE_COLOR[cell.state] ?? coverage.grey;
}

function DeltaPill({
  icon,
  label,
  color,
}: {
  icon?: React.ReactNode;
  label: string;
  color: string;
}) {
  return (
    <Chip
      size="small"
      icon={icon as any}
      label={label}
      sx={(t) => ({
        bgcolor: alpha(color, 0.18),
        color,
        fontWeight: 700,
        '& .MuiChip-icon': { color },
      })}
    />
  );
}

function TechniqueAiDraft({
  techniqueId,
  techniqueName,
  tactic,
  onSaved,
}: {
  techniqueId: string;
  techniqueName: string;
  tactic?: string;
  onSaved: () => void;
}) {
  const [intent, setIntent] = useState(
    `Detect adversary use of ${techniqueId} (${techniqueName})`,
  );
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<AIDraftResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [errorDetails, setErrorDetails] = useState<string[]>([]);
  const [needsConfig, setNeedsConfig] = useState(false);
  const [savedId, setSavedId] = useState<string | null>(null);

  async function draft() {
    setBusy(true);
    setError(null);
    setErrorDetails([]);
    setNeedsConfig(false);
    setSavedId(null);
    try {
      const r = await aiDraftDetection({
        intent: intent.trim(),
        techniques: [techniqueId],
        log_source_product: 'windows',
        log_source_category: 'process_creation',
        severity: 'medium',
      });
      setResult(r);
    } catch (e: any) {
      const detail = e?.response?.data?.detail;
      if (typeof detail === 'string') {
        setError(detail);
        if (detail.toLowerCase().includes('not configured')) setNeedsConfig(true);
      } else if (detail && typeof detail === 'object') {
        setError(detail.detail ?? 'AI draft failed validation');
        setErrorDetails(Array.isArray(detail.errors) ? detail.errors : []);
      } else {
        setError(e?.message ?? 'AI draft failed');
      }
    } finally {
      setBusy(false);
    }
  }

  async function save() {
    if (!result) return;
    setBusy(true);
    try {
      const saved = await createDetection({
        raw_yaml: result.yaml,
        detection_status: 'idea',
      });
      setSavedId(saved.id);
      onSaved();
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'save failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Box
      sx={(t) => ({
        border: `1px solid ${alpha(t.palette.primary.main, 0.3)}`,
        bgcolor: alpha(t.palette.primary.main, 0.04),
        borderRadius: 2,
        p: 1.5,
      })}
    >
      <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1 }}>
        Drafts a Sigma rule for {techniqueId}
        {tactic ? ` · ${tacticLabel(tactic)}` : ''} and validates it with
        pySigma before showing. Configure the key under{' '}
        <MuiLink component={Link} href="/dashboard/settings?tab=ai" underline="hover">
          Settings → AI authoring
        </MuiLink>
        .
      </Typography>
      <TextField
        size="small"
        fullWidth
        multiline
        minRows={2}
        label="What should the rule catch?"
        value={intent}
        onChange={(e) => setIntent(e.target.value)}
        sx={{ mb: 1 }}
      />
      <Button
        size="small"
        variant="contained"
        startIcon={<AutoAwesomeRoundedIcon fontSize="small" />}
        onClick={draft}
        disabled={busy || !intent.trim()}
      >
        {busy ? 'Drafting…' : 'Draft with AI'}
      </Button>

      {error && (
        <Alert
          severity={needsConfig ? 'warning' : 'error'}
          sx={{ mt: 1.5 }}
          action={
            needsConfig ? (
              <Button component={Link} href="/dashboard/settings?tab=ai" size="small">
                Configure
              </Button>
            ) : undefined
          }
        >
          <Typography variant="body2">{error}</Typography>
          {errorDetails.length > 0 && (
            <Box component="ul" sx={{ pl: 2, mt: 0.5, mb: 0 }}>
              {errorDetails.map((e, i) => (
                <li key={i}>
                  <Typography variant="caption" sx={{ fontFamily: 'JetBrains Mono, monospace' }}>
                    {e}
                  </Typography>
                </li>
              ))}
            </Box>
          )}
        </Alert>
      )}

      {result && (
        <Box sx={{ mt: 1.5 }}>
          <Typography variant="caption" color="text.secondary">
            Generated in {result.attempts} attempt
            {result.attempts === 1 ? '' : 's'}
          </Typography>
          <Paper
            variant="outlined"
            sx={(t) => ({
              mt: 0.5,
              p: 1.25,
              bgcolor: alpha(t.palette.primary.main, 0.05),
              fontFamily: 'JetBrains Mono, monospace',
              fontSize: '0.7rem',
              whiteSpace: 'pre-wrap',
              maxHeight: 280,
              overflowY: 'auto',
            })}
          >
            {result.yaml}
          </Paper>
          <Stack direction="row" spacing={1} mt={1}>
            <Button
              size="small"
              variant="contained"
              onClick={save}
              disabled={busy || !!savedId}
            >
              {savedId ? 'Saved' : 'Save as new detection'}
            </Button>
            <Button
              size="small"
              variant="outlined"
              onClick={() => navigator.clipboard.writeText(result.yaml)}
            >
              Copy YAML
            </Button>
          </Stack>
        </Box>
      )}
    </Box>
  );
}

function TacticTable({
  groups,
  tactic,
  deltaByTechnique,
  siemTechs,
  openTechniqueId,
  onRowClick,
}: {
  groups: { parent: CoverageCell | null; subs: CoverageCell[] }[];
  tactic: string;
  deltaByTechnique: Map<string, MatrixDeltaCell>;
  siemTechs: Set<string>;
  openTechniqueId: string | null;
  onRowClick: (cell: CoverageCell) => void;
}) {
  // Flatten parent → its subs into ordered rows, tagging sub rows so we
  // can indent them.
  const rows: { cell: CoverageCell; isSub: boolean }[] = [];
  for (const g of groups) {
    if (g.parent) rows.push({ cell: g.parent, isSub: false });
    for (const s of g.subs) rows.push({ cell: s, isSub: g.parent !== null });
  }

  return (
    <Table size="small" stickyHeader sx={{ minWidth: 760 }}>
      <TableHead>
        <TableRow>
          <TableCell sx={{ fontWeight: 700 }}>Technique</TableCell>
          <TableCell sx={{ fontWeight: 700, width: 130 }}>State</TableCell>
          <TableCell sx={{ fontWeight: 700, width: 90 }} align="right">
            Detections
          </TableCell>
          <TableCell sx={{ fontWeight: 700, width: 80 }} align="right">
            Deployed
          </TableCell>
          <TableCell sx={{ fontWeight: 700, width: 70 }} align="center">
            SIEM
          </TableCell>
          <TableCell sx={{ fontWeight: 700, width: 130 }}>Depth</TableCell>
          <TableCell sx={{ fontWeight: 700, width: 110 }}>Change</TableCell>
          <TableCell sx={{ fontWeight: 700 }}>Also in tactics</TableCell>
        </TableRow>
      </TableHead>
      <TableBody>
        {rows.length === 0 && (
          <TableRow>
            <TableCell colSpan={8} align="center" sx={{ color: 'text.secondary', py: 3 }}>
              No techniques match the current filters.
            </TableCell>
          </TableRow>
        )}
        {rows.map(({ cell, isSub }) => {
          const stateColor = STATE_COLOR[cell.state] ?? coverage.grey;
          const delta = deltaByTechnique.get(cell.technique_id);
          const otherTactics = cell.tactics.filter((t) => t && t !== tactic);
          const selected = openTechniqueId === cell.technique_id;
          return (
            <TableRow
              key={cell.technique_id}
              hover
              selected={selected}
              onClick={() => onRowClick(cell)}
              sx={{ cursor: 'pointer' }}
            >
              <TableCell sx={{ pl: isSub ? 4 : 2 }}>
                <Stack direction="row" spacing={1} alignItems="baseline">
                  <Typography
                    variant="caption"
                    sx={{ fontFamily: 'JetBrains Mono, monospace', fontWeight: 700 }}
                  >
                    {cell.technique_id}
                  </Typography>
                  <Typography variant="body2" sx={{ fontWeight: isSub ? 400 : 600 }}>
                    {cell.name}
                  </Typography>
                  {isSub && (
                    <Chip
                      label="sub"
                      size="small"
                      variant="outlined"
                      sx={{ height: 16, fontSize: '0.55rem' }}
                    />
                  )}
                </Stack>
              </TableCell>
              <TableCell>
                <Chip
                  size="small"
                  label={STATE_LABEL[cell.state] ?? cell.state}
                  sx={{
                    bgcolor: alpha(stateColor, 0.18),
                    color: stateColor,
                    fontWeight: 700,
                    height: 20,
                  }}
                />
              </TableCell>
              <TableCell align="right">
                <Typography
                  variant="body2"
                  sx={{ fontFamily: 'JetBrains Mono, monospace' }}
                >
                  {cell.detection_count}
                </Typography>
              </TableCell>
              <TableCell align="right">
                <Typography
                  variant="body2"
                  sx={{ fontFamily: 'JetBrains Mono, monospace' }}
                >
                  {cell.deployed_count}
                </Typography>
              </TableCell>
              <TableCell align="center">
                {siemTechs.has(cell.technique_id) ? (
                  <Tooltip title="Deployed in SIEM (via connector)" arrow>
                    <Box
                      sx={{
                        display: 'inline-block',
                        width: 9,
                        height: 9,
                        borderRadius: '50%',
                        bgcolor: 'success.main',
                      }}
                    />
                  </Tooltip>
                ) : (
                  <Typography variant="caption" color="text.secondary">
                    —
                  </Typography>
                )}
              </TableCell>
              <TableCell>
                <Stack direction="row" spacing={0.25} alignItems="center">
                  {[1, 2, 3, 4, 5].map((i) => (
                    <Box
                      key={i}
                      sx={{
                        width: 12,
                        height: 5,
                        borderRadius: 1,
                        bgcolor:
                          i <= cell.max_depth
                            ? coverage.green
                            : (t) => alpha(t.palette.text.primary, 0.12),
                      }}
                    />
                  ))}
                  <Typography
                    variant="caption"
                    color="text.secondary"
                    sx={{ ml: 0.5, fontFamily: 'JetBrains Mono, monospace' }}
                  >
                    {cell.max_depth}/5
                  </Typography>
                </Stack>
              </TableCell>
              <TableCell>
                {delta && delta.change !== 'unchanged' ? (
                  <Chip
                    size="small"
                    label={delta.change}
                    sx={{
                      height: 18,
                      fontSize: '0.6rem',
                      bgcolor: alpha(DELTA_COLOR[delta.change] ?? coverage.grey, 0.18),
                      color: DELTA_COLOR[delta.change] ?? coverage.grey,
                      fontWeight: 700,
                    }}
                  />
                ) : (
                  <Typography variant="caption" color="text.secondary">
                    —
                  </Typography>
                )}
              </TableCell>
              <TableCell>
                {otherTactics.length === 0 ? (
                  <Typography variant="caption" color="text.secondary">
                    —
                  </Typography>
                ) : (
                  <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                    {otherTactics.map((t) => (
                      <Chip
                        key={t}
                        label={tacticLabel(t)}
                        size="small"
                        variant="outlined"
                        sx={{ height: 18, fontSize: '0.6rem' }}
                      />
                    ))}
                  </Stack>
                )}
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}

function TechniqueCellChip({
  cell,
  onClick,
  selected,
  colorMode = 'state',
  deltaCell,
  subCount,
  expanded,
  onToggleExpand,
  siem = false,
}: {
  cell: CoverageCell;
  onClick: () => void;
  selected: boolean;
  colorMode?: ColorMode;
  deltaCell?: MatrixDeltaCell;
  subCount?: number;
  expanded?: boolean;
  onToggleExpand?: (e: React.MouseEvent) => void;
  siem?: boolean;
}) {
  const bg = cellBackground(cell, colorMode);
  const fg = '#ffffff';
  const deltaColor =
    deltaCell && deltaCell.change !== 'unchanged'
      ? DELTA_COLOR[deltaCell.change]
      : null;

  const tooltipParts = [
    `${cell.technique_id} · ${cell.name}`,
    `${cell.detection_count} detection${cell.detection_count === 1 ? '' : 's'} · depth ${cell.max_depth}/5`,
  ];
  if (siem) {
    tooltipParts.push('Deployed in SIEM (via connector)');
  }
  if (deltaCell && deltaCell.change !== 'unchanged') {
    tooltipParts.push(
      deltaCell.previous_state
        ? `Delta: ${deltaCell.previous_state} → ${deltaCell.current_state} (${deltaCell.change})`
        : `Delta: new (${deltaCell.current_state})`,
    );
  }

  return (
    <Tooltip title={tooltipParts.join(' • ')} placement="right" arrow>
      <Box
        onClick={onClick}
        sx={(t) => ({
          position: 'relative',
          px: 0.75,
          py: 0.5,
          minHeight: 34,
          borderRadius: 1,
          bgcolor: bg,
          color: fg,
          cursor: 'pointer',
          outline: selected
            ? `2px solid ${t.palette.primary.main}`
            : deltaColor
              ? `2px solid ${deltaColor}`
              : 'none',
          outlineOffset: '1px',
          display: 'flex',
          flexDirection: 'column',
          gap: 0.25,
          overflow: 'hidden',
          '&:hover': { filter: 'brightness(1.08)' },
        })}
      >
        {siem && (
          // Deployed-in-SIEM marker — small ring in the top-right corner.
          <Box
            sx={{
              position: 'absolute',
              top: 3,
              right: 3,
              width: 8,
              height: 8,
              borderRadius: '50%',
              bgcolor: '#ffffff',
              border: '2px solid rgba(0,0,0,0.35)',
              zIndex: 1,
            }}
          />
        )}
        <Stack direction="row" alignItems="center" spacing={0.5} sx={{ width: '100%' }}>
          {onToggleExpand && (
            <IconButton
              size="small"
              onClick={onToggleExpand}
              sx={{
                color: '#ffffff',
                p: 0,
                width: 16,
                height: 16,
                flexShrink: 0,
                '& svg': { fontSize: 14 },
              }}
              aria-label={expanded ? 'collapse sub-techniques' : 'expand sub-techniques'}
            >
              {expanded ? <ExpandMoreRoundedIcon /> : <ChevronRightRoundedIcon />}
            </IconButton>
          )}
          {cell.is_subtechnique && !onToggleExpand && (
            <Box
              sx={{
                width: 4,
                height: 14,
                borderRadius: '2px',
                bgcolor: alpha('#ffffff', 0.7),
                flexShrink: 0,
              }}
            />
          )}
          <Typography
            variant="caption"
            sx={{
              fontFamily: 'JetBrains Mono, monospace',
              fontWeight: 600,
              lineHeight: 1.2,
              flexShrink: 0,
            }}
          >
            {cell.technique_id}
          </Typography>
          <Typography
            variant="caption"
            sx={{
              lineHeight: 1.2,
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
              flex: 1,
            }}
          >
            {cell.name}
          </Typography>
          {(cell.detection_count > 0 || (subCount ?? 0) > 0) && (
            <Stack
              direction="row"
              spacing={0.25}
              alignItems="center"
              sx={{ flexShrink: 0 }}
            >
              {cell.detection_count > 0 && (
                <Box
                  sx={{
                    fontSize: '0.6rem',
                    fontWeight: 800,
                    px: 0.5,
                    py: 0,
                    borderRadius: '8px',
                    bgcolor: alpha('#ffffff', 0.25),
                    fontFamily: 'JetBrains Mono, monospace',
                    lineHeight: 1.4,
                  }}
                >
                  ×{cell.detection_count}
                </Box>
              )}
              {(subCount ?? 0) > 0 && (
                <Box
                  sx={{
                    fontSize: '0.6rem',
                    fontWeight: 800,
                    px: 0.5,
                    py: 0,
                    borderRadius: '8px',
                    bgcolor: alpha('#000000', 0.25),
                    fontFamily: 'JetBrains Mono, monospace',
                    lineHeight: 1.4,
                  }}
                >
                  +{subCount}
                </Box>
              )}
            </Stack>
          )}
        </Stack>
        {/* depth indicator: 5 small segments, filled up to max_depth */}
        {cell.state !== 'out_of_scope' && cell.state !== 'gap' && (
          <Stack
            direction="row"
            spacing={0.25}
            sx={{ width: '100%', pl: onToggleExpand || cell.is_subtechnique ? 2.5 : 0 }}
          >
            {[1, 2, 3, 4, 5].map((i) => (
              <Box
                key={i}
                sx={{
                  flex: 1,
                  height: 3,
                  borderRadius: 1,
                  bgcolor:
                    i <= cell.max_depth
                      ? alpha('#ffffff', 0.85)
                      : alpha('#ffffff', 0.18),
                }}
              />
            ))}
          </Stack>
        )}
      </Box>
    </Tooltip>
  );
}
