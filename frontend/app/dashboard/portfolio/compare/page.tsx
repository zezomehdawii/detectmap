'use client';

import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Autocomplete,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Divider,
  LinearProgress,
  Paper,
  Stack,
  TextField,
  Typography,
  alpha,
} from '@mui/material';
import CompareArrowsRoundedIcon from '@mui/icons-material/CompareArrowsRounded';
import {
  CompareCustomer,
  CustomerOut,
  PortfolioCompare,
  comparePortfolio,
  listCustomers,
} from '@/lib/api';
import { coverage } from '../../../theme';

const STATE_LABELS: Record<string, string> = {
  deployed: 'Deployed',
  in_progress: 'In progress',
  idea: 'Idea',
  gap: 'Gap',
  not_applicable: 'N/A',
  out_of_scope: 'OoS',
};

const STATE_COLOR: Record<string, string> = {
  deployed: coverage.green,
  in_progress: coverage.amber,
  idea: coverage.idea,
  gap: coverage.red,
  not_applicable: coverage.blue,
  out_of_scope: coverage.grey,
};

const GRADE_COLOR: Record<string, string> = {
  A: coverage.green,
  B: coverage.amber,
  C: '#e8895d',
  D: coverage.red,
};

export default function CompareCustomersPage() {
  const [customers, setCustomers] = useState<CustomerOut[]>([]);
  const [picked, setPicked] = useState<CustomerOut[]>([]);
  const [data, setData] = useState<PortfolioCompare | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listCustomers().then(setCustomers).catch(() => {});
  }, []);

  async function run() {
    if (picked.length < 2) return;
    setLoading(true);
    setError(null);
    try {
      const d = await comparePortfolio(picked.map((p) => p.codename));
      setData(d);
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'failed to compare');
    } finally {
      setLoading(false);
    }
  }

  const cols = useMemo(() => data?.customers ?? [], [data]);

  const order = ['deployed', 'in_progress', 'idea', 'gap', 'not_applicable', 'out_of_scope'];

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      <Box>
        <Typography variant="h4" sx={{ fontWeight: 700, letterSpacing: '-0.02em' }}>
          Customer comparison
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Pick 2–6 customers and see their posture side by side. Useful for QBRs and
          spotting customers under-served on a given dimension.
        </Typography>
      </Box>

      <Card>
        <CardContent>
          <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} alignItems={{ md: 'center' }}>
            <Autocomplete
              multiple
              size="small"
              options={customers}
              value={picked}
              onChange={(_, v) => setPicked(v.slice(0, 6))}
              getOptionLabel={(c) => `${c.name} (${c.codename})`}
              sx={{ flex: 1, minWidth: 320 }}
              renderInput={(params) => (
                <TextField {...params} label="Customers (2–6)" placeholder="pick…" />
              )}
            />
            <Button
              variant="contained"
              startIcon={<CompareArrowsRoundedIcon fontSize="small" />}
              disabled={picked.length < 2 || loading}
              onClick={run}
            >
              Compare
            </Button>
          </Stack>
        </CardContent>
      </Card>

      {error && (
        <Alert severity="error" variant="outlined" sx={{ borderRadius: 3 }}>
          {error}
        </Alert>
      )}

      {loading && (
        <Box sx={{ py: 6, display: 'flex', justifyContent: 'center' }}>
          <CircularProgress />
        </Box>
      )}

      {!loading && data && (
        <Paper variant="outlined" sx={{ overflowX: 'auto' }}>
          <Box
            sx={{
              display: 'grid',
              gridAutoFlow: 'column',
              gridAutoColumns: 'minmax(220px, 1fr)',
              minWidth: cols.length * 230,
            }}
          >
            {cols.map((c) => (
              <CustomerColumn
                key={c.codename}
                col={c}
                order={order}
                bestBreadth={data.best_breadth}
                worstBreadth={data.worst_breadth}
              />
            ))}
          </Box>
        </Paper>
      )}
    </Box>
  );
}

function CustomerColumn({
  col,
  order,
  bestBreadth,
  worstBreadth,
}: {
  col: CompareCustomer;
  order: string[];
  bestBreadth: string | null;
  worstBreadth: string | null;
}) {
  const total = order.reduce((s, k) => s + (col.state_counts[k] ?? 0), 0);
  const isBest = bestBreadth === col.codename;
  const isWorst = worstBreadth === col.codename;
  const grade = col.posture_grade;
  return (
    <Box
      sx={(t) => ({
        p: 2,
        borderRight: `1px solid ${t.palette.divider}`,
        '&:last-of-type': { borderRight: 0 },
      })}
    >
      <Stack direction="row" alignItems="baseline" spacing={1}>
        <Typography variant="subtitle1" sx={{ fontWeight: 700, flex: 1 }}>
          {col.name}
        </Typography>
        <Chip
          label={grade}
          size="small"
          sx={{
            bgcolor: alpha(GRADE_COLOR[grade] ?? coverage.grey, 0.18),
            color: GRADE_COLOR[grade] ?? 'text.primary',
            fontWeight: 800,
            fontFamily: 'JetBrains Mono, monospace',
            minWidth: 32,
          }}
        />
      </Stack>
      <Typography
        variant="caption"
        color="text.secondary"
        sx={{ fontFamily: 'JetBrains Mono, monospace' }}
      >
        {col.codename} · {col.sector ?? 'no sector'}
      </Typography>

      {col.error ? (
        <Alert severity="warning" sx={{ mt: 2 }} variant="outlined">
          {col.error}
        </Alert>
      ) : (
        <>
          <Stack direction="row" spacing={0.5} mt={1.5}>
            {isBest && (
              <Chip
                size="small"
                label="best breadth"
                color="success"
                variant="outlined"
                sx={{ height: 18, fontSize: '0.62rem' }}
              />
            )}
            {isWorst && (
              <Chip
                size="small"
                label="worst breadth"
                color="error"
                variant="outlined"
                sx={{ height: 18, fontSize: '0.62rem' }}
              />
            )}
          </Stack>

          <Divider sx={{ my: 2 }} />

          <Box sx={{ mb: 2 }}>
            <Typography variant="caption" color="text.secondary">
              Breadth
            </Typography>
            <Typography variant="h5" sx={{ fontWeight: 800 }}>
              {Math.round(col.breadth_pct * 100)}%
            </Typography>
            <LinearProgress
              variant="determinate"
              value={Math.round(col.breadth_pct * 100)}
              sx={{ height: 6, borderRadius: 3, mt: 0.5 }}
            />
            <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5 }}>
              {col.covered_count}/{col.denominator_size} covered · {col.deployed_count} deployed
            </Typography>
          </Box>

          <Box sx={{ mb: 2 }}>
            <Typography variant="caption" color="text.secondary">
              Depth (0–5)
            </Typography>
            <Typography variant="h6" sx={{ fontWeight: 700 }}>
              {col.depth_avg.toFixed(1)} · {col.depth_grade}
            </Typography>
          </Box>

          <Divider sx={{ my: 2 }} />

          <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 700 }}>
            STATE MIX
          </Typography>
          <Stack
            direction="row"
            sx={(t) => ({
              mt: 1,
              height: 14,
              borderRadius: 2,
              overflow: 'hidden',
              border: `1px solid ${t.palette.divider}`,
            })}
          >
            {order.map((k) => {
              const v = col.state_counts[k] ?? 0;
              if (v === 0 || total === 0) return null;
              return (
                <Box
                  key={k}
                  sx={{
                    flexBasis: `${(v / total) * 100}%`,
                    bgcolor: STATE_COLOR[k],
                  }}
                />
              );
            })}
          </Stack>
          <Stack spacing={0.5} mt={1.5}>
            {order.map((k) => {
              const v = col.state_counts[k] ?? 0;
              return (
                <Stack
                  key={k}
                  direction="row"
                  alignItems="center"
                  spacing={1}
                >
                  <Box
                    sx={{
                      width: 10,
                      height: 10,
                      borderRadius: '3px',
                      bgcolor: STATE_COLOR[k],
                    }}
                  />
                  <Typography variant="caption" sx={{ flex: 1, fontWeight: 600 }}>
                    {STATE_LABELS[k]}
                  </Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600 }}>
                    {v}
                  </Typography>
                </Stack>
              );
            })}
          </Stack>
        </>
      )}
    </Box>
  );
}
