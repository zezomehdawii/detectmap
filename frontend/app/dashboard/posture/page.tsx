'use client';

import { useEffect, useMemo, useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  IconButton,
  MenuItem,
  Paper,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
  alpha,
} from '@mui/material';
import DeleteOutlineRoundedIcon from '@mui/icons-material/DeleteOutlineRounded';
import {
  PosturePoint,
  PostureTrend,
  deleteCoverageSnapshot,
  getPostureTrend,
} from '@/lib/api';
import { accent, coverage } from '../../theme';

type Filter = '' | 'full' | 'sector' | 'apt';

const GRADE_COLOR: Record<string, string> = {
  A: coverage.green,
  B: coverage.amber,
  C: '#e8895d',
  D: coverage.red,
};

export default function PosturePage() {
  const [kind, setKind] = useState<Filter>('');
  const [data, setData] = useState<PostureTrend | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    getPostureTrend(kind || undefined, undefined)
      .then(setData)
      .catch((e) =>
        setError(
          e?.response?.data?.detail ??
            'failed to load — pick a customer in the topbar if you are an MSSP user.',
        ),
      )
      .finally(() => setLoading(false));
  }, [kind, reloadKey]);

  async function removeSnapshot(id: string) {
    if (!confirm('Delete this snapshot? This cannot be undone.')) return;
    setDeletingId(id);
    try {
      await deleteCoverageSnapshot(id);
      setReloadKey((k) => k + 1);
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'delete failed');
    } finally {
      setDeletingId(null);
    }
  }

  const points = data?.points ?? [];

  const latest = points.length ? points[points.length - 1] : null;

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      <Box>
        <Typography variant="h4" sx={{ fontWeight: 700, letterSpacing: '-0.02em' }}>
          Posture trend
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Historical breadth × depth captured from every coverage snapshot.
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
              label="Filter denominator"
              value={kind}
              onChange={(e) => setKind(e.target.value as Filter)}
              sx={{ minWidth: 220 }}
            >
              <MenuItem value="">All denominators</MenuItem>
              <MenuItem value="full">Full ATT&amp;CK</MenuItem>
              <MenuItem value="sector">Sector profile</MenuItem>
              <MenuItem value="apt">APT group</MenuItem>
            </TextField>
            <Box sx={{ flex: 1 }} />
            {latest && (
              <Stack direction="row" spacing={2} alignItems="center">
                <PostureBadge grade={latest.posture_grade} />
                <Stack spacing={0}>
                  <Typography variant="caption" color="text.secondary">
                    Latest: {new Date(latest.taken_at).toLocaleString()}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Breadth {Math.round(latest.breadth_pct * 100)}% ·{' '}
                    {latest.breadth_grade} &nbsp;|&nbsp; Depth{' '}
                    {latest.depth_avg.toFixed(1)} · {latest.depth_grade}
                  </Typography>
                </Stack>
              </Stack>
            )}
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

      {!loading && !error && (
        <>
          {points.length === 0 ? (
            <Card>
              <CardContent>
                <Typography color="text.secondary">
                  No snapshots captured yet. Open the coverage matrix and click
                  the save icon to record one.
                </Typography>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent>
                <Typography
                  variant="overline"
                  sx={{ fontWeight: 700, color: 'text.secondary' }}
                >
                  Breadth over time ({points.length} snapshot
                  {points.length === 1 ? '' : 's'})
                </Typography>
                <TrendChart points={points} />
              </CardContent>
            </Card>
          )}

          {points.length > 0 && (
            <Paper variant="outlined" sx={{ overflow: 'hidden' }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Captured</TableCell>
                    <TableCell>Denominator</TableCell>
                    <TableCell align="right">Breadth</TableCell>
                    <TableCell align="right">Depth</TableCell>
                    <TableCell align="right">Covered</TableCell>
                    <TableCell align="right">Deployed</TableCell>
                    <TableCell align="center">Grade</TableCell>
                    <TableCell sx={{ width: 48 }} />
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[...points].reverse().map((p) => (
                    <TableRow key={p.id} hover>
                      <TableCell>
                        {new Date(p.taken_at).toLocaleString()}
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={
                            p.denominator_ref
                              ? `${p.denominator_kind} · ${p.denominator_ref}`
                              : p.denominator_kind
                          }
                          size="small"
                          variant="outlined"
                        />
                      </TableCell>
                      <TableCell align="right">
                        {Math.round(p.breadth_pct * 100)}% · {p.breadth_grade}
                      </TableCell>
                      <TableCell align="right">
                        {p.depth_avg.toFixed(1)} · {p.depth_grade}
                      </TableCell>
                      <TableCell align="right">
                        {p.covered_count}/{p.denominator_size}
                      </TableCell>
                      <TableCell align="right">{p.deployed_count}</TableCell>
                      <TableCell align="center">
                        <Chip
                          label={p.posture_grade}
                          size="small"
                          sx={{
                            bgcolor: alpha(GRADE_COLOR[p.posture_grade] ?? coverage.grey, 0.18),
                            color: GRADE_COLOR[p.posture_grade] ?? 'text.primary',
                            fontWeight: 800,
                            fontFamily: 'JetBrains Mono, monospace',
                          }}
                        />
                      </TableCell>
                      <TableCell align="center">
                        <IconButton
                          size="small"
                          color="error"
                          disabled={deletingId === p.id}
                          onClick={() => removeSnapshot(p.id)}
                        >
                          <DeleteOutlineRoundedIcon fontSize="small" />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Paper>
          )}
        </>
      )}
    </Box>
  );
}

function PostureBadge({ grade }: { grade: string }) {
  const color = GRADE_COLOR[grade] ?? coverage.grey;
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

function TrendChart({ points }: { points: PosturePoint[] }) {
  // Simple inline SVG: x = time index, y = breadth %.
  // No external chart library — we want one dependency-free render.
  const w = 760;
  const h = 200;
  const pad = { top: 12, right: 16, bottom: 24, left: 36 };
  const innerW = w - pad.left - pad.right;
  const innerH = h - pad.top - pad.bottom;

  const xs = useMemo(() => {
    if (points.length <= 1) return [pad.left];
    return points.map(
      (_, i) => pad.left + (i / (points.length - 1)) * innerW,
    );
  }, [points, innerW]);

  const yBreadth = (pct: number) =>
    pad.top + innerH - Math.max(0, Math.min(1, pct)) * innerH;

  const yDepth = (avg: number) =>
    pad.top + innerH - (Math.max(0, Math.min(5, avg)) / 5) * innerH;

  const breadthPath = points
    .map((p, i) => `${i === 0 ? 'M' : 'L'} ${xs[i]} ${yBreadth(p.breadth_pct)}`)
    .join(' ');
  const depthPath = points
    .map((p, i) => `${i === 0 ? 'M' : 'L'} ${xs[i]} ${yDepth(p.depth_avg)}`)
    .join(' ');

  return (
    <Box sx={{ width: '100%', overflowX: 'auto', mt: 1 }}>
      <svg
        viewBox={`0 0 ${w} ${h}`}
        preserveAspectRatio="xMinYMid meet"
        style={{ width: '100%', minWidth: 320 }}
      >
        {/* gridlines */}
        {[0, 0.25, 0.5, 0.75, 1].map((g) => {
          const y = pad.top + innerH - g * innerH;
          return (
            <g key={g}>
              <line
                x1={pad.left}
                x2={pad.left + innerW}
                y1={y}
                y2={y}
                stroke="currentColor"
                strokeOpacity={0.1}
                strokeWidth={1}
              />
              <text x={4} y={y + 4} fontSize={10} fill="currentColor" opacity={0.55}>
                {Math.round(g * 100)}%
              </text>
            </g>
          );
        })}

        {/* breadth */}
        <path d={breadthPath} stroke={accent.cyan} strokeWidth={2} fill="none" />
        {points.map((p, i) => (
          <circle
            key={`b-${p.id}`}
            cx={xs[i]}
            cy={yBreadth(p.breadth_pct)}
            r={3.5}
            fill={accent.cyan}
          />
        ))}

        {/* depth (lighter overlay, scaled 0-5) */}
        <path
          d={depthPath}
          stroke={coverage.amber}
          strokeWidth={2}
          fill="none"
          opacity={0.85}
          strokeDasharray="4 4"
        />
        {points.map((p, i) => (
          <circle
            key={`d-${p.id}`}
            cx={xs[i]}
            cy={yDepth(p.depth_avg)}
            r={3}
            fill={coverage.amber}
          />
        ))}

        {/* legend */}
        <g transform={`translate(${pad.left}, ${h - 4})`}>
          <circle cx={4} cy={-6} r={3} fill={accent.cyan} />
          <text x={12} y={-3} fontSize={11} fill="currentColor" opacity={0.7}>
            Breadth %
          </text>
          <circle cx={90} cy={-6} r={3} fill={coverage.amber} />
          <text x={98} y={-3} fontSize={11} fill="currentColor" opacity={0.7}>
            Depth (0–5)
          </text>
        </g>
      </svg>
    </Box>
  );
}
