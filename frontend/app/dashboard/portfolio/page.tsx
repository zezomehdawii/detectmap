'use client';

import { useEffect, useMemo, useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  FormControlLabel,
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
  Typography,
  alpha,
} from '@mui/material';
import { PortfolioOverview, getPortfolioOverview } from '@/lib/api';
import { coverage } from '../../theme';

const GRADE_COLOR: Record<string, string> = {
  A: coverage.green,
  B: coverage.amber,
  C: '#e8895d',
  D: coverage.red,
};

export default function PortfolioPage() {
  const [data, setData] = useState<PortfolioOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Controls: search, sort, breadth-threshold alerting.
  const [query, setQuery] = useState('');
  const [sortBy, setSortBy] = useState<'name' | 'breadth' | 'grade'>('breadth');
  const [threshold, setThreshold] = useState(50); // breadth % target
  const [onlyBelow, setOnlyBelow] = useState(false);

  useEffect(() => {
    setLoading(true);
    setError(null);
    getPortfolioOverview('full')
      .then(setData)
      .catch((e) =>
        setError(e?.response?.data?.detail ?? 'failed to load portfolio'),
      )
      .finally(() => setLoading(false));
  }, []);

  const customers = data?.customers ?? [];
  const belowCount = useMemo(
    () => customers.filter((c) => !c.error && c.breadth_pct * 100 < threshold).length,
    [customers, threshold],
  );
  const visibleCustomers = useMemo(() => {
    const q = query.trim().toLowerCase();
    let rows = customers.filter(
      (c) =>
        !q ||
        c.name.toLowerCase().includes(q) ||
        c.codename.toLowerCase().includes(q) ||
        (c.sector ?? '').toLowerCase().includes(q),
    );
    if (onlyBelow) rows = rows.filter((c) => !c.error && c.breadth_pct * 100 < threshold);
    const sorted = [...rows];
    if (sortBy === 'name') sorted.sort((a, b) => a.name.localeCompare(b.name));
    else if (sortBy === 'grade') sorted.sort((a, b) => a.posture_grade.localeCompare(b.posture_grade));
    else sorted.sort((a, b) => b.breadth_pct - a.breadth_pct);
    return sorted;
  }, [customers, query, onlyBelow, threshold, sortBy]);

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      <Box>
        <Typography variant="h4" sx={{ fontWeight: 700, letterSpacing: '-0.02em' }}>
          Portfolio
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Cross-customer posture roll-up across the MSSP organisation. Live
          scoring against the full ATT&amp;CK enterprise denominator.
        </Typography>
      </Box>

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

      {data && !loading && (
        <>
          <Card>
            <CardContent>
              <Stack direction={{ xs: 'column', md: 'row' }} spacing={3} alignItems="center">
                <Box>
                  <Typography variant="caption" color="text.secondary">
                    Customers
                  </Typography>
                  <Typography variant="h4" sx={{ fontWeight: 700 }}>
                    {data.customer_count}
                  </Typography>
                </Box>
                <Stack direction="row" spacing={1.5}>
                  {(['A', 'B', 'C', 'D'] as const).map((g) => (
                    <Box
                      key={g}
                      sx={{
                        minWidth: 76,
                        textAlign: 'center',
                        p: 1.2,
                        borderRadius: 2,
                        border: 1,
                        borderColor: GRADE_COLOR[g],
                        bgcolor: alpha(GRADE_COLOR[g], 0.08),
                      }}
                    >
                      <Typography
                        variant="h5"
                        sx={{
                          fontWeight: 800,
                          color: GRADE_COLOR[g],
                          letterSpacing: '-0.04em',
                        }}
                      >
                        {data.posture_distribution[g] ?? 0}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        grade {g}
                      </Typography>
                    </Box>
                  ))}
                </Stack>
                <Box sx={{ flex: 1 }} />
                <Typography variant="caption" color="text.secondary">
                  denominator: {data.denominator_kind}
                  {data.denominator_ref ? ` · ${data.denominator_ref}` : ''}
                </Typography>
              </Stack>
            </CardContent>
          </Card>

          <Card>
            <CardContent>
              <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} alignItems={{ md: 'center' }}>
                <TextField
                  size="small"
                  label="Search customers"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  sx={{ minWidth: 220 }}
                />
                <TextField
                  select
                  size="small"
                  label="Sort by"
                  value={sortBy}
                  onChange={(e) => setSortBy(e.target.value as typeof sortBy)}
                  sx={{ minWidth: 160 }}
                >
                  <MenuItem value="breadth">Breadth (high→low)</MenuItem>
                  <MenuItem value="name">Name</MenuItem>
                  <MenuItem value="grade">Posture grade</MenuItem>
                </TextField>
                <TextField
                  size="small"
                  type="number"
                  label="Breadth target %"
                  value={threshold}
                  onChange={(e) => setThreshold(Math.max(0, Math.min(100, Number(e.target.value) || 0)))}
                  sx={{ width: 150 }}
                />
                <FormControlLabel
                  control={<Switch checked={onlyBelow} onChange={(e) => setOnlyBelow(e.target.checked)} />}
                  label="Only below target"
                />
                <Box sx={{ flex: 1 }} />
                <Chip
                  label={`${belowCount} below ${threshold}%`}
                  color={belowCount > 0 ? 'error' : 'success'}
                  variant={belowCount > 0 ? 'filled' : 'outlined'}
                />
              </Stack>
            </CardContent>
          </Card>

          <Paper variant="outlined" sx={{ overflow: 'hidden' }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Customer</TableCell>
                  <TableCell sx={{ width: 130 }}>Sector</TableCell>
                  <TableCell sx={{ width: 110 }}>Status</TableCell>
                  <TableCell sx={{ width: 100 }} align="center">
                    Posture
                  </TableCell>
                  <TableCell sx={{ width: 120 }} align="right">
                    Breadth
                  </TableCell>
                  <TableCell sx={{ width: 100 }} align="right">
                    Depth
                  </TableCell>
                  <TableCell sx={{ width: 140 }} align="right">
                    Covered
                  </TableCell>
                  <TableCell sx={{ width: 110 }} align="right">
                    Deployed
                  </TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {visibleCustomers.map((c) => {
                  const below = !c.error && c.breadth_pct * 100 < threshold;
                  return (
                  <TableRow
                    key={c.id}
                    hover
                    sx={below ? { bgcolor: (t) => alpha(t.palette.error.main, 0.06) } : undefined}
                  >
                    <TableCell>
                      <Typography variant="body2" sx={{ fontWeight: 500 }}>
                        {c.name}
                      </Typography>
                      <Typography
                        variant="caption"
                        color="text.secondary"
                        sx={{ fontFamily: 'JetBrains Mono, monospace' }}
                      >
                        {c.codename}
                      </Typography>
                    </TableCell>
                    <TableCell>{c.sector ?? '—'}</TableCell>
                    <TableCell>
                      <Chip
                        label={c.status}
                        size="small"
                        variant="outlined"
                        color={c.status === 'active' ? 'success' : 'default'}
                      />
                    </TableCell>
                    <TableCell align="center">
                      {c.error ? (
                        <Chip label="error" size="small" color="warning" />
                      ) : (
                        <Chip
                          label={c.posture_grade}
                          size="small"
                          sx={{
                            bgcolor: alpha(GRADE_COLOR[c.posture_grade] ?? coverage.grey, 0.18),
                            color: GRADE_COLOR[c.posture_grade] ?? 'text.primary',
                            fontWeight: 800,
                            fontFamily: 'JetBrains Mono, monospace',
                          }}
                        />
                      )}
                    </TableCell>
                    <TableCell align="right">
                      {Math.round(c.breadth_pct * 100)}% · {c.breadth_grade}
                    </TableCell>
                    <TableCell align="right">{c.depth_grade}</TableCell>
                    <TableCell align="right">
                      {c.covered_count}/{c.denominator_size}
                    </TableCell>
                    <TableCell align="right">{c.deployed_count}</TableCell>
                  </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </Paper>
        </>
      )}
    </Box>
  );
}
