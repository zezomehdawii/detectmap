'use client';

import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  MenuItem,
  Paper,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Typography,
  alpha,
} from '@mui/material';
import TrendingUpRoundedIcon from '@mui/icons-material/TrendingUpRounded';
import TrendingDownRoundedIcon from '@mui/icons-material/TrendingDownRounded';
import FiberNewRoundedIcon from '@mui/icons-material/FiberNewRounded';
import {
  CoverageSnapshot,
  DeltaChange,
  MatrixDelta,
  getMatrixDelta,
  listCoverageSnapshots,
} from '@/lib/api';
import { coverage } from '../../../theme';

const CHANGE_COLOR: Record<DeltaChange, string> = {
  improved: coverage.green,
  regressed: coverage.red,
  unchanged: coverage.grey,
  new: '#26d4ee',
  removed: coverage.amber,
};

const STATE_LABEL: Record<string, string> = {
  deployed: 'Deployed',
  in_progress: 'In progress',
  idea: 'Idea',
  gap: 'Gap',
  not_applicable: 'N/A',
  out_of_scope: 'Out of scope',
};

export default function SnapshotDiffPage() {
  const [snapshots, setSnapshots] = useState<CoverageSnapshot[]>([]);
  const [baselineId, setBaselineId] = useState('');
  const [delta, setDelta] = useState<MatrixDelta | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<DeltaChange | 'all'>('all');

  useEffect(() => {
    listCoverageSnapshots()
      .then((rows) => {
        setSnapshots(rows);
        if (rows.length) setBaselineId(rows[0].id);
      })
      .catch((e) => setError(e?.response?.data?.detail ?? 'failed to load snapshots'));
  }, []);

  useEffect(() => {
    if (!baselineId) {
      setDelta(null);
      return;
    }
    const snap = snapshots.find((s) => s.id === baselineId);
    if (!snap) return;
    setLoading(true);
    setError(null);
    getMatrixDelta(baselineId, {
      denominator: snap.denominator_kind as any,
      ref: snap.denominator_ref ?? undefined,
    })
      .then(setDelta)
      .catch((e) =>
        setError(
          e?.response?.data?.detail ?? 'failed to compute delta. This snapshot may pre-date per-technique state capture.',
        ),
      )
      .finally(() => setLoading(false));
  }, [baselineId, snapshots]);

  const visibleCells = useMemo(() => {
    if (!delta) return [];
    if (filter === 'all') return delta.cells.filter((c) => c.change !== 'unchanged');
    return delta.cells.filter((c) => c.change === filter);
  }, [delta, filter]);

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      <Box>
        <Typography variant="h4" sx={{ fontWeight: 700, letterSpacing: '-0.02em' }}>
          Snapshot diff
        </Typography>
        <Typography variant="body2" color="text.secondary">
          What changed in your coverage between a saved snapshot and the live matrix.
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
              label="Baseline snapshot"
              value={baselineId}
              onChange={(e) => setBaselineId(e.target.value)}
              sx={{ minWidth: 320 }}
            >
              <MenuItem value="">— pick —</MenuItem>
              {snapshots.map((s) => (
                <MenuItem key={s.id} value={s.id}>
                  {new Date(s.taken_at).toLocaleString()} · {s.denominator_kind}
                  {s.denominator_ref ? ` (${s.denominator_ref})` : ''} ·{' '}
                  {s.posture_grade}
                </MenuItem>
              ))}
            </TextField>
            <Box sx={{ flex: 1 }} />
            {delta && (
              <Stack direction="row" spacing={1}>
                <Chip
                  icon={<TrendingUpRoundedIcon sx={{ fontSize: 14 }} />}
                  label={`${delta.summary.improved} improved`}
                  sx={{
                    bgcolor: alpha(CHANGE_COLOR.improved, 0.18),
                    color: CHANGE_COLOR.improved,
                    fontWeight: 700,
                  }}
                  size="small"
                />
                <Chip
                  icon={<TrendingDownRoundedIcon sx={{ fontSize: 14 }} />}
                  label={`${delta.summary.regressed} regressed`}
                  sx={{
                    bgcolor: alpha(CHANGE_COLOR.regressed, 0.18),
                    color: CHANGE_COLOR.regressed,
                    fontWeight: 700,
                  }}
                  size="small"
                />
                <Chip
                  icon={<FiberNewRoundedIcon sx={{ fontSize: 14 }} />}
                  label={`${delta.summary.new} new`}
                  sx={{
                    bgcolor: alpha(CHANGE_COLOR.new, 0.18),
                    color: CHANGE_COLOR.new,
                    fontWeight: 700,
                  }}
                  size="small"
                />
                <Chip
                  label={`${delta.summary.unchanged} unchanged`}
                  size="small"
                />
              </Stack>
            )}
          </Stack>
        </CardContent>
      </Card>

      {error && (
        <Alert severity="info" variant="outlined" sx={{ borderRadius: 3 }}>
          {error}
        </Alert>
      )}

      {loading && (
        <Box sx={{ py: 6, display: 'flex', justifyContent: 'center' }}>
          <CircularProgress />
        </Box>
      )}

      {delta && !loading && (
        <>
          <Stack direction="row" spacing={1} alignItems="center">
            <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600 }}>
              Show:
            </Typography>
            <ToggleButtonGroup
              size="small"
              exclusive
              value={filter}
              onChange={(_, v) => v && setFilter(v as any)}
              sx={{ '& .MuiToggleButton-root': { textTransform: 'none', py: 0.25, px: 1.25 } }}
            >
              <ToggleButton value="all">All changes</ToggleButton>
              <ToggleButton value="improved">Improved</ToggleButton>
              <ToggleButton value="regressed">Regressed</ToggleButton>
              <ToggleButton value="new">New</ToggleButton>
              <ToggleButton value="removed">Removed</ToggleButton>
            </ToggleButtonGroup>
            <Box sx={{ flex: 1 }} />
            <Typography variant="caption" color="text.secondary">
              {visibleCells.length} cells
            </Typography>
          </Stack>

          {visibleCells.length === 0 ? (
            <Card>
              <CardContent>
                <Typography color="text.secondary">
                  Nothing matches that filter. Posture is stable on this dimension.
                </Typography>
              </CardContent>
            </Card>
          ) : (
            <Paper variant="outlined" sx={{ overflow: 'hidden' }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Technique</TableCell>
                    <TableCell>Was</TableCell>
                    <TableCell>Now</TableCell>
                    <TableCell align="right">Depth</TableCell>
                    <TableCell align="center">Change</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {visibleCells.slice(0, 500).map((c) => (
                    <TableRow key={c.technique_id} hover>
                      <TableCell>
                        <Typography
                          variant="body2"
                          sx={{ fontFamily: 'JetBrains Mono, monospace', fontWeight: 700 }}
                        >
                          {c.technique_id}
                        </Typography>
                      </TableCell>
                      <TableCell>{c.previous_state ? STATE_LABEL[c.previous_state] ?? c.previous_state : '—'}</TableCell>
                      <TableCell>{STATE_LABEL[c.current_state] ?? c.current_state}</TableCell>
                      <TableCell align="right">
                        {c.previous_depth ?? 0} → {c.current_depth}
                      </TableCell>
                      <TableCell align="center">
                        <Chip
                          size="small"
                          label={c.change}
                          sx={{
                            bgcolor: alpha(CHANGE_COLOR[c.change], 0.18),
                            color: CHANGE_COLOR[c.change],
                            fontWeight: 700,
                            textTransform: 'capitalize',
                          }}
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {visibleCells.length > 500 && (
                <Box sx={{ p: 1.5, textAlign: 'center' }}>
                  <Typography variant="caption" color="text.secondary">
                    Showing the first 500 — narrow the filter for more.
                  </Typography>
                </Box>
              )}
            </Paper>
          )}
        </>
      )}

      {!loading && !delta && !error && snapshots.length === 0 && (
        <Alert severity="info" variant="outlined" sx={{ borderRadius: 3 }}>
          No snapshots have been saved yet. Open the coverage matrix and click the save icon to
          record one — diffs become available against any subsequent snapshot.
        </Alert>
      )}
    </Box>
  );
}
