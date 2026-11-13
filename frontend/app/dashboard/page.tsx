'use client';

import { useEffect, useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  Alert,
  Box,
  Button,
  ButtonBase,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  LinearProgress,
  Stack,
  ToggleButton,
  ToggleButtonGroup,
  Tooltip,
  Typography,
  alpha,
} from '@mui/material';
import ArrowOutwardRoundedIcon from '@mui/icons-material/ArrowOutwardRounded';
import TrendingUpRoundedIcon from '@mui/icons-material/TrendingUpRounded';

import {
  ACTIVE_CUSTOMER_EVENT,
  getActiveCustomer,
  getToken,
  setActiveCustomer,
} from '@/lib/auth';
import {
  AttackNotification,
  CoverageScore,
  GapTop,
  MeResponse,
  PortfolioOverview,
  PosturePoint,
  PostureTrend,
  fetchMe,
  getCoverageScore,
  getPortfolioOverview,
  getPostureTrend,
  getTopGaps,
  listAttackNotifications,
} from '@/lib/api';
import { accent, coverage, gradients } from '../theme';

const MSSP_ROLES = new Set([
  'mssp_admin',
  'mssp_analyst',
  'mssp_readonly',
  'product_super_admin',
]);

const GRADE_COLOR: Record<string, string> = {
  A: coverage.green,
  B: coverage.amber,
  C: '#e8895d',
  D: coverage.red,
};

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

export default function DashboardPage() {
  const router = useRouter();
  const [me, setMe] = useState<MeResponse | null>(null);
  const [activeCustomer, setActive] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!getToken()) {
      router.replace('/login');
      return;
    }
    let cancelled = false;
    fetchMe()
      .then((data) => {
        if (cancelled) return;
        setMe(data);
        setActive(getActiveCustomer());
      })
      .catch(() => {
        if (!cancelled) router.replace('/login');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [router]);

  useEffect(() => {
    const handler = (e: Event) => {
      const detail = (e as CustomEvent<string | null>).detail ?? null;
      setActive(detail);
    };
    window.addEventListener(ACTIVE_CUSTOMER_EVENT, handler);
    return () => window.removeEventListener(ACTIVE_CUSTOMER_EVENT, handler);
  }, []);

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', mt: 8 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (!me) return null;

  const isMssp = MSSP_ROLES.has(me.role);

  // MSSP users with no active customer selected see the cross-customer
  // roll-up; once they pick one in the topbar switcher, the dashboard
  // re-renders against that tenant.
  if (isMssp && !activeCustomer) {
    return <MSSPDashboard />;
  }

  return (
    <CustomerDashboard
      codename={activeCustomer ?? me.customer_codename ?? '—'}
    />
  );
}

// ---------------------------------------------------------------------------
// MSSP roll-up
// ---------------------------------------------------------------------------

type DashFilter = { grade: string | null; sector: string | null };

function MSSPDashboard() {
  const [data, setData] = useState<PortfolioOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<DashFilter>({ grade: null, sector: null });

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

  const filteredCustomers = useMemo(() => {
    if (!data) return [];
    return data.customers.filter((c) => {
      if (filter.grade && c.posture_grade !== filter.grade) return false;
      if (filter.sector) {
        const s = c.sector ?? 'unspecified';
        if (s !== filter.sector) return false;
      }
      return true;
    });
  }, [data, filter]);

  const stats = useMemo(() => {
    if (!data) return null;
    const scoped = filteredCustomers;
    const scored = scoped.filter((c) => !c.error && c.denominator_size > 0);
    const totalDeployed = scored.reduce((s, c) => s + c.deployed_count, 0);
    const totalCovered = scored.reduce((s, c) => s + c.covered_count, 0);
    const totalDenom = scored.reduce((s, c) => s + c.denominator_size, 0);
    const avgBreadth =
      scored.length === 0
        ? 0
        : scored.reduce((s, c) => s + c.breadth_pct, 0) / scored.length;

    const sectors: Record<string, number> = {};
    for (const c of scoped) {
      const s = c.sector ?? 'unspecified';
      sectors[s] = (sectors[s] ?? 0) + 1;
    }

    return {
      total: scoped.length,
      scored: scored.length,
      totalDeployed,
      totalCovered,
      totalDenom,
      avgBreadth,
      sectors,
    };
  }, [data, filteredCustomers]);

  const toggleGrade = (g: string) =>
    setFilter((f) => ({ ...f, grade: f.grade === g ? null : g }));
  const toggleSector = (s: string) =>
    setFilter((f) => ({ ...f, sector: f.sector === s ? null : s }));
  const pivotToCustomer = (codename: string) => {
    setActiveCustomer(codename);
  };
  const clearFilters = () => setFilter({ grade: null, sector: null });
  const hasFilter = Boolean(filter.grade || filter.sector);

  return (
    <Stack spacing={3}>
      <Stack
        direction={{ xs: 'column', md: 'row' }}
        spacing={2}
        alignItems={{ md: 'flex-end' }}
      >
        <Box sx={{ flex: 1 }}>
          <Typography variant="h4" sx={{ fontWeight: 700, letterSpacing: '-0.02em' }}>
            MSSP overview
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Cross-customer posture, coverage, and detection state across the
            organisation. Click any slice or customer to pivot.
          </Typography>
        </Box>
        {hasFilter && (
          <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
            <Typography variant="caption" color="text.secondary">
              Filtered:
            </Typography>
            {filter.grade && (
              <Chip
                size="small"
                label={`Grade ${filter.grade}`}
                onDelete={() => setFilter((f) => ({ ...f, grade: null }))}
                sx={{
                  bgcolor: alpha(
                    GRADE_COLOR[filter.grade] ?? coverage.grey,
                    0.18,
                  ),
                  color: GRADE_COLOR[filter.grade] ?? 'text.primary',
                  fontWeight: 700,
                }}
              />
            )}
            {filter.sector && (
              <Chip
                size="small"
                label={
                  filter.sector === 'unspecified'
                    ? 'No sector set'
                    : capitalize(filter.sector)
                }
                onDelete={() => setFilter((f) => ({ ...f, sector: null }))}
                sx={{ fontWeight: 700 }}
              />
            )}
            <Button size="small" onClick={clearFilters}>
              Clear all
            </Button>
          </Stack>
        )}
      </Stack>

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

      {!loading && data && stats && (
        <>
          <Box
            sx={{
              display: 'grid',
              gap: 2,
              gridTemplateColumns: {
                xs: '1fr 1fr',
                md: 'repeat(5, 1fr)',
              },
            }}
          >
            <StatTile
              label="Customers"
              value={stats.total.toString()}
              hint={
                hasFilter
                  ? `${stats.total} of ${data.customer_count} in filter`
                  : `${stats.scored} scored · ${
                      data.customer_count - stats.scored
                    } provisioning / error`
              }
              accentColor={accent.cyan}
            />
            <StatTile
              label="Avg breadth"
              value={`${Math.round(stats.avgBreadth * 100)}%`}
              hint="Across scored customers"
              accentColor={coverage.green}
            />
            <StatTile
              label="Deployed detections"
              value={stats.totalDeployed.toLocaleString()}
              hint={`${stats.totalCovered.toLocaleString()} techniques covered`}
              accentColor={accent.violet}
            />
            <StatTile
              label="Techniques in scope"
              value={stats.totalDenom > 0 ? stats.totalDenom.toLocaleString() : '—'}
              hint="Sum of per-customer denominators"
              accentColor={coverage.blue}
            />
            <StatTile
              label="Sectors"
              value={Object.keys(stats.sectors).length.toString()}
              hint={
                Object.entries(stats.sectors)
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 2)
                  .map(([k, v]) => `${k} (${v})`)
                  .join(' · ') || 'none'
              }
              accentColor={coverage.amber}
            />
          </Box>

          <Box
            sx={{
              display: 'grid',
              gap: 3,
              gridTemplateColumns: { xs: '1fr', md: '1fr 1.4fr' },
            }}
          >
            <PostureDistributionCard
              customers={data.customers}
              activeGrade={filter.grade}
              onSelectGrade={toggleGrade}
            />
            <CustomerBreadthCard
              customers={filteredCustomers}
              onPickCustomer={pivotToCustomer}
            />
          </Box>

          <PerCustomerStateCard
            customers={filteredCustomers}
            onPickCustomer={pivotToCustomer}
          />

          <SectorBreakdownCard
            customers={data.customers}
            activeSector={filter.sector}
            onSelectSector={toggleSector}
          />
        </>
      )}
    </Stack>
  );
}

function PostureDistributionCard({
  customers,
  activeGrade,
  onSelectGrade,
}: {
  customers: PortfolioOverview['customers'];
  activeGrade: string | null;
  onSelectGrade: (g: string) => void;
}) {
  const [view, setView] = useState<'donut' | 'bar'>('donut');
  const grades = ['A', 'B', 'C', 'D'] as const;
  const scored = customers.filter((c) => !c.error);
  const byGrade: Record<string, typeof scored> = { A: [], B: [], C: [], D: [] };
  for (const c of scored) {
    const g = c.posture_grade;
    if (byGrade[g]) byGrade[g].push(c);
  }
  const total = scored.length;
  const slices = grades
    .filter((g) => byGrade[g].length > 0)
    .map((g) => ({
      key: g,
      value: byGrade[g].length,
      color: GRADE_COLOR[g],
    }));
  const maxRow = Math.max(1, ...grades.map((g) => byGrade[g].length));

  return (
    <Card>
      <CardContent sx={{ p: { xs: 2.5, md: 3 } }}>
        <Stack direction="row" alignItems="flex-start" spacing={1} mb={1.5}>
          <Box sx={{ flex: 1 }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
              Posture distribution
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Click a grade to filter every card.
            </Typography>
          </Box>
          <ViewToggle
            value={view}
            options={[
              { value: 'donut', label: 'Donut' },
              { value: 'bar', label: 'Bar' },
            ]}
            onChange={setView}
          />
        </Stack>

        {view === 'donut' ? (
          <Stack direction="row" spacing={3} alignItems="center">
            <Donut
              slices={slices}
              total={total}
              centerLabel={`${total}`}
              centerHint="customers"
              activeKey={activeGrade}
              onSliceClick={onSelectGrade}
              sliceTooltip={(k) =>
                `Grade ${k}: ${byGrade[k].length} customer${
                  byGrade[k].length === 1 ? '' : 's'
                } — click to filter`
              }
            />
            <Stack spacing={1.25} sx={{ flex: 1, minWidth: 0 }}>
              {grades.map((g) => {
                const rows = byGrade[g];
                const pct = total === 0 ? 0 : (rows.length / total) * 100;
                return (
                  <ClickableLegendRow
                    key={g}
                    active={activeGrade === g}
                    onClick={() => onSelectGrade(g)}
                    color={GRADE_COLOR[g]}
                    label={`Grade ${g}`}
                    value={`${rows.length} (${Math.round(pct)}%)`}
                    sub={
                      rows.length > 0
                        ? rows.map((c) => c.name).join(' · ')
                        : undefined
                    }
                  />
                );
              })}
            </Stack>
          </Stack>
        ) : (
          <Stack spacing={1.5}>
            {grades.map((g) => {
              const rows = byGrade[g];
              const pct = total === 0 ? 0 : (rows.length / total) * 100;
              return (
                <ButtonBase
                  key={g}
                  onClick={() => onSelectGrade(g)}
                  sx={(t) => ({
                    display: 'block',
                    width: '100%',
                    textAlign: 'left',
                    p: 1,
                    borderRadius: 2,
                    bgcolor:
                      activeGrade === g
                        ? alpha(GRADE_COLOR[g], 0.12)
                        : 'transparent',
                    '&:hover': {
                      bgcolor: alpha(GRADE_COLOR[g], 0.08),
                    },
                    transition: 'background-color 120ms ease',
                  })}
                >
                  <Stack
                    direction="row"
                    alignItems="baseline"
                    spacing={1}
                    mb={0.5}
                  >
                    <Typography
                      variant="body2"
                      sx={{ fontWeight: 700, flex: 1 }}
                    >
                      Grade {g}
                    </Typography>
                    <Typography
                      variant="caption"
                      color="text.secondary"
                      sx={{ fontWeight: 600 }}
                    >
                      {rows.length} · {Math.round(pct)}%
                    </Typography>
                  </Stack>
                  <LinearProgress
                    variant="determinate"
                    value={(rows.length / maxRow) * 100}
                    sx={(t) => ({
                      height: 8,
                      borderRadius: 4,
                      bgcolor: 'rgba(15,18,35,0.06)',
                      ...t.applyStyles('dark', {
                        bgcolor: 'rgba(255,255,255,0.06)',
                      }),
                      '& .MuiLinearProgress-bar': {
                        bgcolor: GRADE_COLOR[g],
                        borderRadius: 4,
                      },
                    })}
                  />
                  {rows.length > 0 && (
                    <Typography
                      variant="caption"
                      color="text.secondary"
                      sx={{ display: 'block', mt: 0.5 }}
                    >
                      {rows.map((c) => c.name).join(' · ')}
                    </Typography>
                  )}
                </ButtonBase>
              );
            })}
          </Stack>
        )}
      </CardContent>
    </Card>
  );
}

function CustomerBreadthCard({
  customers,
  onPickCustomer,
}: {
  customers: PortfolioOverview['customers'];
  onPickCustomer: (codename: string) => void;
}) {
  const [view, setView] = useState<'bar' | 'table'>('bar');
  const sorted = [...customers]
    .filter((c) => !c.error)
    .sort((a, b) => b.breadth_pct - a.breadth_pct)
    .slice(0, 8);

  return (
    <Card>
      <CardContent sx={{ p: { xs: 2.5, md: 3 } }}>
        <Stack direction="row" alignItems="flex-start" spacing={1} mb={1.5}>
          <Box sx={{ flex: 1 }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
              Coverage breadth by customer
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Click any customer to open their scoped dashboard.
            </Typography>
          </Box>
          <ViewToggle
            value={view}
            options={[
              { value: 'bar', label: 'Bars' },
              { value: 'table', label: 'Table' },
            ]}
            onChange={setView}
          />
          <Button
            size="small"
            component={Link}
            href="/dashboard/portfolio"
            endIcon={<ArrowOutwardRoundedIcon sx={{ fontSize: 14 }} />}
          >
            Portfolio
          </Button>
        </Stack>
        {sorted.length === 0 ? (
          <Typography color="text.secondary">No scored customers yet.</Typography>
        ) : view === 'bar' ? (
          <Stack spacing={1.5}>
            {sorted.map((c) => (
              <ButtonBase
                key={c.id}
                onClick={() => onPickCustomer(c.codename)}
                sx={(t) => ({
                  display: 'block',
                  width: '100%',
                  textAlign: 'left',
                  p: 1,
                  borderRadius: 2,
                  '&:hover': {
                    bgcolor: 'rgba(15,18,35,0.04)',
                    ...t.applyStyles('dark', {
                      bgcolor: 'rgba(255,255,255,0.04)',
                    }),
                  },
                  transition: 'background-color 120ms ease',
                })}
              >
                <Stack direction="row" alignItems="baseline" mb={0.5} spacing={1}>
                  <Typography variant="body2" sx={{ fontWeight: 600, flex: 1 }}>
                    {c.name}
                    <Typography
                      component="span"
                      variant="caption"
                      color="text.secondary"
                      sx={{ ml: 1, fontFamily: 'JetBrains Mono, monospace' }}
                    >
                      {c.codename}
                    </Typography>
                  </Typography>
                  <Chip
                    label={c.posture_grade}
                    size="small"
                    sx={{
                      bgcolor: alpha(GRADE_COLOR[c.posture_grade] ?? coverage.grey, 0.18),
                      color: GRADE_COLOR[c.posture_grade] ?? 'text.primary',
                      fontWeight: 800,
                      fontFamily: 'JetBrains Mono, monospace',
                      minWidth: 32,
                    }}
                  />
                  <Typography
                    variant="body2"
                    sx={{ fontWeight: 700, minWidth: 48, textAlign: 'right' }}
                  >
                    {Math.round(c.breadth_pct * 100)}%
                  </Typography>
                </Stack>
                <LinearProgress
                  variant="determinate"
                  value={Math.max(0, Math.min(100, c.breadth_pct * 100))}
                  sx={(t) => ({
                    height: 6,
                    borderRadius: 4,
                    bgcolor: 'rgba(15,18,35,0.06)',
                    ...t.applyStyles('dark', {
                      bgcolor: 'rgba(255,255,255,0.06)',
                    }),
                    '& .MuiLinearProgress-bar': {
                      bgcolor: GRADE_COLOR[c.posture_grade] ?? accent.cyan,
                      borderRadius: 4,
                    },
                  })}
                />
              </ButtonBase>
            ))}
          </Stack>
        ) : (
          <Box sx={{ overflowX: 'auto' }}>
            <Box
              component="table"
              sx={(t) => ({
                width: '100%',
                borderCollapse: 'separate',
                borderSpacing: 0,
                '& th, & td': {
                  textAlign: 'left',
                  py: 1,
                  px: 1,
                  borderBottom: '1px solid',
                  borderBottomColor: 'divider',
                  fontSize: '0.78rem',
                },
                '& th': {
                  color: 'text.secondary',
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em',
                  fontSize: '0.68rem',
                },
                '& tbody tr': {
                  cursor: 'pointer',
                  transition: 'background-color 120ms ease',
                },
                '& tbody tr:hover': {
                  bgcolor: 'rgba(15,18,35,0.04)',
                  ...t.applyStyles('dark', {
                    bgcolor: 'rgba(255,255,255,0.04)',
                  }),
                },
              })}
            >
              <thead>
                <tr>
                  <th>Customer</th>
                  <th>Grade</th>
                  <th style={{ textAlign: 'right' }}>Breadth</th>
                  <th style={{ textAlign: 'right' }}>Deployed</th>
                  <th style={{ textAlign: 'right' }}>Covered</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((c) => (
                  <tr key={c.id} onClick={() => onPickCustomer(c.codename)}>
                    <td>
                      <Typography variant="body2" sx={{ fontWeight: 600 }}>
                        {c.name}
                      </Typography>
                      <Typography
                        variant="caption"
                        color="text.secondary"
                        sx={{ fontFamily: 'JetBrains Mono, monospace' }}
                      >
                        {c.codename}
                      </Typography>
                    </td>
                    <td>
                      <Chip
                        label={c.posture_grade}
                        size="small"
                        sx={{
                          bgcolor: alpha(
                            GRADE_COLOR[c.posture_grade] ?? coverage.grey,
                            0.18,
                          ),
                          color: GRADE_COLOR[c.posture_grade] ?? 'text.primary',
                          fontWeight: 800,
                          fontFamily: 'JetBrains Mono, monospace',
                          minWidth: 32,
                        }}
                      />
                    </td>
                    <td style={{ textAlign: 'right', fontWeight: 700 }}>
                      {Math.round(c.breadth_pct * 100)}%
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      {c.deployed_count.toLocaleString()}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      {c.covered_count}/{c.denominator_size}
                    </td>
                  </tr>
                ))}
              </tbody>
            </Box>
          </Box>
        )}
      </CardContent>
    </Card>
  );
}

function PerCustomerStateCard({
  customers,
  onPickCustomer,
}: {
  customers: PortfolioOverview['customers'];
  onPickCustomer: (codename: string) => void;
}) {
  const [view, setView] = useState<'per_customer' | 'aggregate'>('per_customer');
  const order = ['deployed', 'in_progress', 'idea', 'gap', 'not_applicable', 'out_of_scope'];
  const rows = [...customers]
    .filter((c) => !c.error && c.denominator_size > 0)
    .sort((a, b) => b.deployed_count - a.deployed_count);

  const aggregate: Record<string, number> = {};
  for (const c of rows) {
    for (const k of order) {
      aggregate[k] = (aggregate[k] ?? 0) + (c.state_counts[k] ?? 0);
    }
  }
  const aggTotal = order.reduce((s, k) => s + (aggregate[k] ?? 0), 0);

  return (
    <Card>
      <CardContent sx={{ p: { xs: 2.5, md: 3 } }}>
        <Stack direction="row" alignItems="flex-start" spacing={1} mb={1.5}>
          <Box sx={{ flex: 1 }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
              Detection state by customer
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {view === 'per_customer'
                ? 'Click any row to open the customer dashboard.'
                : 'Aggregate technique-cell mix across the filtered customers.'}
            </Typography>
          </Box>
          <ViewToggle
            value={view}
            options={[
              { value: 'per_customer', label: 'Per customer' },
              { value: 'aggregate', label: 'Aggregate' },
            ]}
            onChange={setView}
          />
        </Stack>

        {rows.length === 0 ? (
          <Typography color="text.secondary">No scored customers yet.</Typography>
        ) : view === 'per_customer' ? (
          <Stack spacing={1.5}>
            {rows.map((c) => {
              const total = order.reduce(
                (s, k) => s + (c.state_counts[k] ?? 0),
                0,
              );
              return (
                <ButtonBase
                  key={c.id}
                  onClick={() => onPickCustomer(c.codename)}
                  sx={(t) => ({
                    display: 'block',
                    width: '100%',
                    textAlign: 'left',
                    p: 1,
                    borderRadius: 2,
                    '&:hover': {
                      bgcolor: 'rgba(15,18,35,0.04)',
                      ...t.applyStyles('dark', {
                        bgcolor: 'rgba(255,255,255,0.04)',
                      }),
                    },
                    transition: 'background-color 120ms ease',
                  })}
                >
                  <Stack
                    direction="row"
                    alignItems="baseline"
                    mb={0.75}
                    spacing={1}
                  >
                    <Typography
                      variant="body2"
                      sx={{ fontWeight: 600, flex: 1, minWidth: 0 }}
                    >
                      {c.name}
                      <Typography
                        component="span"
                        variant="caption"
                        color="text.secondary"
                        sx={{
                          ml: 1,
                          fontFamily: 'JetBrains Mono, monospace',
                        }}
                      >
                        {c.codename}
                      </Typography>
                    </Typography>
                    <Chip
                      label={c.posture_grade}
                      size="small"
                      sx={{
                        bgcolor: alpha(
                          GRADE_COLOR[c.posture_grade] ?? coverage.grey,
                          0.18,
                        ),
                        color:
                          GRADE_COLOR[c.posture_grade] ?? 'text.primary',
                        fontWeight: 800,
                        fontFamily: 'JetBrains Mono, monospace',
                        minWidth: 32,
                      }}
                    />
                    <Typography
                      variant="caption"
                      color="text.secondary"
                      sx={{ minWidth: 130, textAlign: 'right' }}
                    >
                      {c.deployed_count.toLocaleString()} deployed ·{' '}
                      {total.toLocaleString()} cells
                    </Typography>
                  </Stack>
                  <StackedBar
                    segments={order
                      .filter((k) => (c.state_counts[k] ?? 0) > 0)
                      .map((k) => ({
                        key: k,
                        value: c.state_counts[k] ?? 0,
                        color: STATE_COLOR[k],
                        label: `${c.name} · ${STATE_LABEL[k]}`,
                      }))}
                    total={total}
                  />
                </ButtonBase>
              );
            })}
          </Stack>
        ) : (
          <Box>
            <StackedBar
              segments={order
                .filter((k) => (aggregate[k] ?? 0) > 0)
                .map((k) => ({
                  key: k,
                  value: aggregate[k] ?? 0,
                  color: STATE_COLOR[k],
                  label: STATE_LABEL[k],
                }))}
              total={aggTotal}
            />
            <Box
              sx={{
                mt: 2,
                display: 'grid',
                gap: 1,
                gridTemplateColumns: { xs: '1fr 1fr', sm: 'repeat(3, 1fr)' },
              }}
            >
              {order.map((k) => {
                const v = aggregate[k] ?? 0;
                const pct = aggTotal === 0 ? 0 : (v / aggTotal) * 100;
                return (
                  <Stack key={k} direction="row" spacing={1} alignItems="center">
                    <Box
                      sx={{
                        width: 10,
                        height: 10,
                        borderRadius: '3px',
                        bgcolor: STATE_COLOR[k],
                      }}
                    />
                    <Stack spacing={0} sx={{ minWidth: 0 }}>
                      <Typography variant="caption" sx={{ fontWeight: 600 }}>
                        {STATE_LABEL[k]}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {v.toLocaleString()} · {Math.round(pct)}%
                      </Typography>
                    </Stack>
                  </Stack>
                );
              })}
            </Box>
          </Box>
        )}

        {view === 'per_customer' && (
          <Box
            sx={{
              mt: 2.5,
              display: 'grid',
              gap: 1,
              gridTemplateColumns: {
                xs: '1fr 1fr',
                sm: 'repeat(3, 1fr)',
                md: 'repeat(6, 1fr)',
              },
            }}
          >
            {order.map((k) => (
              <Stack key={k} direction="row" spacing={1} alignItems="center">
                <Box
                  sx={{
                    width: 10,
                    height: 10,
                    borderRadius: '3px',
                    bgcolor: STATE_COLOR[k],
                  }}
                />
                <Typography variant="caption" sx={{ fontWeight: 600 }}>
                  {STATE_LABEL[k]}
                </Typography>
              </Stack>
            ))}
          </Box>
        )}
      </CardContent>
    </Card>
  );
}

function SectorBreakdownCard({
  customers,
  activeSector,
  onSelectSector,
}: {
  customers: PortfolioOverview['customers'];
  activeSector: string | null;
  onSelectSector: (s: string) => void;
}) {
  const [view, setView] = useState<'donut' | 'list'>('donut');
  const bySector = new Map<string, PortfolioOverview['customers']>();
  for (const c of customers) {
    const key = c.sector ?? 'unspecified';
    const arr = bySector.get(key) ?? [];
    arr.push(c);
    bySector.set(key, arr);
  }
  const entries = [...bySector.entries()].sort(
    (a, b) => b[1].length - a[1].length,
  );
  const total = customers.length;
  const palette = [
    accent.cyan,
    accent.violet,
    coverage.green,
    coverage.amber,
    coverage.red,
    coverage.blue,
    coverage.idea,
    coverage.grey,
  ];
  const colorFor = (k: string) => {
    const i = entries.findIndex(([key]) => key === k);
    return palette[(i < 0 ? 0 : i) % palette.length];
  };
  const labelFor = (k: string) =>
    k === 'unspecified' ? 'No sector set' : capitalize(k);
  const maxRow = Math.max(1, ...entries.map(([, rows]) => rows.length));

  return (
    <Card>
      <CardContent sx={{ p: { xs: 2.5, md: 3 } }}>
        <Stack direction="row" alignItems="flex-start" spacing={1} mb={1.5}>
          <Box sx={{ flex: 1 }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
              Sector mix
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Click a sector to filter every card.
            </Typography>
          </Box>
          <ViewToggle
            value={view}
            options={[
              { value: 'donut', label: 'Donut' },
              { value: 'list', label: 'List' },
            ]}
            onChange={setView}
          />
        </Stack>
        {entries.length === 0 ? (
          <Typography color="text.secondary">No sector data.</Typography>
        ) : view === 'donut' ? (
          <Stack
            direction={{ xs: 'column', sm: 'row' }}
            spacing={3}
            alignItems={{ sm: 'center' }}
          >
            <Donut
              slices={entries.map(([k]) => ({
                key: k,
                value: bySector.get(k)!.length,
                color: colorFor(k),
              }))}
              total={total}
              centerLabel={`${total}`}
              centerHint="customers"
              activeKey={activeSector}
              onSliceClick={onSelectSector}
              sliceTooltip={(k) =>
                `${labelFor(k)}: ${
                  bySector.get(k)!.length
                } — click to filter`
              }
            />
            <Stack spacing={1.25} sx={{ flex: 1, minWidth: 0 }}>
              {entries.map(([k, rows]) => (
                <ClickableLegendRow
                  key={k}
                  active={activeSector === k}
                  onClick={() => onSelectSector(k)}
                  color={colorFor(k)}
                  label={labelFor(k)}
                  value={rows.length.toString()}
                  sub={rows.map((c) => c.name).join(' · ')}
                />
              ))}
            </Stack>
          </Stack>
        ) : (
          <Stack spacing={1.25}>
            {entries.map(([k, rows]) => (
              <ButtonBase
                key={k}
                onClick={() => onSelectSector(k)}
                sx={(t) => ({
                  display: 'block',
                  width: '100%',
                  textAlign: 'left',
                  p: 1,
                  borderRadius: 2,
                  bgcolor:
                    activeSector === k
                      ? alpha(colorFor(k), 0.14)
                      : 'transparent',
                  '&:hover': { bgcolor: alpha(colorFor(k), 0.08) },
                  transition: 'background-color 120ms ease',
                })}
              >
                <Stack direction="row" alignItems="baseline" spacing={1} mb={0.5}>
                  <Typography
                    variant="body2"
                    sx={{ flex: 1, fontWeight: 700 }}
                  >
                    {labelFor(k)}
                  </Typography>
                  <Typography
                    variant="caption"
                    color="text.secondary"
                    sx={{ fontWeight: 600 }}
                  >
                    {rows.length} · {Math.round((rows.length / total) * 100)}%
                  </Typography>
                </Stack>
                <LinearProgress
                  variant="determinate"
                  value={(rows.length / maxRow) * 100}
                  sx={(t) => ({
                    height: 8,
                    borderRadius: 4,
                    bgcolor: 'rgba(15,18,35,0.06)',
                    ...t.applyStyles('dark', {
                      bgcolor: 'rgba(255,255,255,0.06)',
                    }),
                    '& .MuiLinearProgress-bar': {
                      bgcolor: colorFor(k),
                      borderRadius: 4,
                    },
                  })}
                />
                <Typography
                  variant="caption"
                  color="text.secondary"
                  sx={{ display: 'block', mt: 0.5 }}
                >
                  {rows.map((c) => c.name).join(' · ')}
                </Typography>
              </ButtonBase>
            ))}
          </Stack>
        )}
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Customer-scoped
// ---------------------------------------------------------------------------

function CustomerDashboard({ codename }: { codename: string }) {
  const [score, setScore] = useState<CoverageScore | null>(null);
  const [trend, setTrend] = useState<PostureTrend | null>(null);
  const [gaps, setGaps] = useState<GapTop | null>(null);
  const [notifications, setNotifications] = useState<AttackNotification[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    Promise.allSettled([
      getCoverageScore(),
      getPostureTrend(),
      getTopGaps('full', undefined, 5),
      listAttackNotifications(),
    ])
      .then((results) => {
        if (cancelled) return;
        const [s, t, g, n] = results;
        if (s.status === 'fulfilled') setScore(s.value);
        else
          setError(
            (s.reason as any)?.response?.data?.detail ??
              'failed to load coverage score',
          );
        if (t.status === 'fulfilled') setTrend(t.value);
        if (g.status === 'fulfilled') setGaps(g.value);
        if (n.status === 'fulfilled') setNotifications(n.value);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [codename]);

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', mt: 8 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error || !score) {
    return (
      <Stack spacing={3}>
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 700, letterSpacing: '-0.02em' }}>
            Detection posture · {codename}
          </Typography>
        </Box>
        <Alert severity="info" variant="outlined" sx={{ borderRadius: 3 }}>
          {error ??
            'No coverage data yet. Ingest ATT&CK and your detection catalog to populate the dashboard.'}
        </Alert>
      </Stack>
    );
  }

  return (
    <Stack spacing={3}>
      <PostureHero codename={codename} score={score} />

      <AttentionDigest score={score} gaps={gaps} notifications={notifications} />

      <Box
        sx={{
          display: 'grid',
          gap: 3,
          gridTemplateColumns: { xs: '1fr', md: '1fr 1.2fr' },
        }}
      >
        <CustomerStateDonut score={score} />
        <CustomerTrendCard trend={trend} />
      </Box>

      <CustomerTopGapsCard gaps={gaps} />
    </Stack>
  );
}

function AttentionDigest({
  score,
  gaps,
  notifications,
}: {
  score: CoverageScore;
  gaps: GapTop | null;
  notifications: AttackNotification[];
}) {
  const gapCount = score.state_counts?.gap ?? 0;
  const topGapCount = gaps?.items?.length ?? 0;
  const items: { text: string; href: string; severity: 'warning' | 'info' }[] = [];
  if (notifications.length > 0) {
    const techCount = new Set(
      notifications.flatMap((n) => [...n.deprecated_in_use, ...n.revoked_in_use]),
    ).size;
    items.push({
      text:
        `${notifications.length} ATT&CK release change${notifications.length === 1 ? '' : 's'}` +
        (techCount ? ` affecting ${techCount} of your mapped technique${techCount === 1 ? '' : 's'}` : ''),
      href: '/dashboard/settings?tab=catalog',
      severity: 'warning',
    });
  }
  if (gapCount > 0) {
    items.push({
      text: `${gapCount} technique${gapCount === 1 ? '' : 's'} with no detection (gap)`,
      href: '/dashboard/gaps',
      severity: 'info',
    });
  }
  if (topGapCount > 0) {
    items.push({
      text: `${topGapCount} high-priority gap${topGapCount === 1 ? '' : 's'} ranked by APT prevalence`,
      href: '/dashboard/gaps',
      severity: 'info',
    });
  }
  if (items.length === 0) return null;

  return (
    <Card sx={{ borderRadius: 3 }}>
      <CardContent>
        <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
          Needs attention
        </Typography>
        <Stack spacing={1} sx={{ mt: 1 }}>
          {items.map((it, i) => (
            <Stack key={i} direction="row" spacing={1.5} alignItems="center">
              <Box
                sx={{
                  width: 8,
                  height: 8,
                  borderRadius: '50%',
                  bgcolor: it.severity === 'warning' ? coverage.amber : coverage.blue,
                  flexShrink: 0,
                }}
              />
              <Typography variant="body2" sx={{ flex: 1 }}>
                {it.text}
              </Typography>
              <Link href={it.href} style={{ color: 'inherit' }}>
                <Typography variant="caption" sx={{ fontWeight: 600, '&:hover': { textDecoration: 'underline' } }}>
                  View →
                </Typography>
              </Link>
            </Stack>
          ))}
        </Stack>
      </CardContent>
    </Card>
  );
}

function PostureHero({
  codename,
  score,
}: {
  codename: string;
  score: CoverageScore;
}) {
  return (
    <Card
      sx={{
        position: 'relative',
        overflow: 'hidden',
        background: gradients.cta,
        color: '#001119',
        border: 'none',
      }}
    >
      <Box
        aria-hidden
        sx={{
          position: 'absolute',
          inset: 0,
          background:
            'radial-gradient(circle at 85% 15%, rgba(255,255,255,0.22), transparent 55%)',
          pointerEvents: 'none',
        }}
      />
      <CardContent sx={{ position: 'relative', p: { xs: 3, md: 4 } }}>
        <Stack
          direction={{ xs: 'column', md: 'row' }}
          spacing={3}
          alignItems={{ md: 'center' }}
          justifyContent="space-between"
        >
          <Box>
            <Typography variant="overline" sx={{ opacity: 0.7, letterSpacing: 1.5 }}>
              Detection posture · {codename}
            </Typography>
            <Stack direction="row" spacing={2} alignItems="center" mt={1}>
              <Typography variant="h2" sx={{ fontWeight: 800, lineHeight: 1 }}>
                {score.posture_grade}
              </Typography>
              <Stack spacing={0}>
                <Typography variant="caption" sx={{ opacity: 0.75 }}>
                  Breadth grade {score.breadth_grade} · Depth grade{' '}
                  {score.depth_grade}
                </Typography>
                <Typography variant="body2" sx={{ opacity: 0.85, maxWidth: 480 }}>
                  Posture grade is breadth × depth against{' '}
                  {score.denominator_kind === 'full'
                    ? 'the full ATT&CK enterprise denominator'
                    : `the ${score.denominator_kind} denominator${
                        score.denominator_ref ? ` (${score.denominator_ref})` : ''
                      }`}
                  .
                </Typography>
              </Stack>
            </Stack>
          </Box>
          <Stack spacing={1.5} direction={{ xs: 'row', md: 'column' }}>
            <HeroMetric
              label="Breadth"
              value={`${Math.round(score.breadth_pct * 100)}%`}
            />
            <HeroMetric label="Depth (0–5)" value={score.depth_avg.toFixed(1)} />
            <HeroMetric
              label="Covered"
              value={`${score.covered_count}/${score.denominator_size}`}
            />
          </Stack>
        </Stack>
      </CardContent>
    </Card>
  );
}

function HeroMetric({ label, value }: { label: string; value: string }) {
  return (
    <Box
      sx={{
        bgcolor: 'rgba(0,17,25,0.10)',
        border: '1px solid rgba(0,17,25,0.18)',
        borderRadius: 2,
        px: 2,
        py: 1.1,
        minWidth: 150,
      }}
    >
      <Typography variant="caption" sx={{ opacity: 0.75 }}>
        {label}
      </Typography>
      <Typography variant="h6" sx={{ fontWeight: 800, lineHeight: 1.2 }}>
        {value}
      </Typography>
    </Box>
  );
}

function CustomerStateDonut({ score }: { score: CoverageScore }) {
  const order = ['deployed', 'in_progress', 'idea', 'gap', 'not_applicable', 'out_of_scope'];
  const total = order.reduce((s, k) => s + (score.state_counts[k] ?? 0), 0);
  const slices = order
    .filter((k) => (score.state_counts[k] ?? 0) > 0)
    .map((k) => ({
      key: k,
      value: score.state_counts[k] ?? 0,
      color: STATE_COLOR[k],
      label: STATE_LABEL[k],
    }));

  return (
    <Card>
      <CardContent sx={{ p: { xs: 2.5, md: 3 } }}>
        <Stack direction="row" alignItems="center" mb={2}>
          <Box sx={{ flex: 1 }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
              Coverage state
            </Typography>
            <Typography variant="body2" color="text.secondary">
              ATT&amp;CK technique cells by detection state.
            </Typography>
          </Box>
          <Chip
            icon={<TrendingUpRoundedIcon sx={{ fontSize: 14 }} />}
            label={`${score.covered_count} covered`}
            size="small"
          />
        </Stack>
        <Stack direction="row" spacing={3} alignItems="center">
          <Donut
            slices={slices}
            total={total}
            centerLabel={total.toString()}
            centerHint="cells"
          />
          <Stack spacing={1} sx={{ flex: 1 }}>
            {order.map((k) => {
              const v = score.state_counts[k] ?? 0;
              const pct = total === 0 ? 0 : (v / total) * 100;
              return (
                <LegendRow
                  key={k}
                  color={STATE_COLOR[k]}
                  label={STATE_LABEL[k]}
                  value={`${v} · ${Math.round(pct)}%`}
                />
              );
            })}
          </Stack>
        </Stack>
      </CardContent>
    </Card>
  );
}

function CustomerTrendCard({ trend }: { trend: PostureTrend | null }) {
  const points = trend?.points ?? [];

  return (
    <Card>
      <CardContent sx={{ p: { xs: 2.5, md: 3 } }}>
        <Stack direction="row" alignItems="center" mb={2}>
          <Box sx={{ flex: 1 }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
              Posture trend
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Breadth × depth captured from each saved snapshot.
            </Typography>
          </Box>
          <Button
            size="small"
            component={Link}
            href="/dashboard/posture"
            endIcon={<ArrowOutwardRoundedIcon sx={{ fontSize: 14 }} />}
          >
            History
          </Button>
        </Stack>
        {points.length === 0 ? (
          <Typography color="text.secondary">
            No snapshots captured yet. Save one from the coverage matrix to
            start tracking change over time.
          </Typography>
        ) : (
          <TrendChart points={points} />
        )}
      </CardContent>
    </Card>
  );
}

function CustomerTopGapsCard({ gaps }: { gaps: GapTop | null }) {
  const items = gaps?.items ?? [];
  return (
    <Card>
      <CardContent sx={{ p: { xs: 2.5, md: 3 } }}>
        <Stack direction="row" alignItems="center" mb={2}>
          <Box sx={{ flex: 1 }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
              Top gaps by APT prevalence
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Uncovered techniques ranked by the number of adversary groups that use them.
            </Typography>
          </Box>
          <Button
            size="small"
            component={Link}
            href="/dashboard/gaps"
            endIcon={<ArrowOutwardRoundedIcon sx={{ fontSize: 14 }} />}
          >
            All gaps
          </Button>
        </Stack>
        {items.length === 0 ? (
          <Typography color="text.secondary">No prioritised gaps yet.</Typography>
        ) : (
          <Stack spacing={1}>
            {items.map((g) => (
              <Stack
                key={g.technique_id}
                direction="row"
                spacing={2}
                alignItems="center"
                sx={(t) => ({
                  p: 1.5,
                  borderRadius: 2,
                  border: `1px solid ${t.palette.divider}`,
                })}
              >
                <Typography
                  variant="body2"
                  sx={{
                    fontFamily: 'JetBrains Mono, monospace',
                    fontWeight: 700,
                    minWidth: 90,
                    color: 'primary.main',
                  }}
                >
                  {g.technique_id}
                </Typography>
                <Typography variant="body2" sx={{ flex: 1, fontWeight: 500 }}>
                  {g.name}
                </Typography>
                <Tooltip
                  title={
                    g.sample_groups
                      .map((s) => `${s.group_id} ${s.name}`)
                      .join(', ') || 'no groups'
                  }
                >
                  <Chip
                    label={`${g.apt_count} APTs`}
                    size="small"
                    sx={{
                      bgcolor: alpha(coverage.red, 0.16),
                      color: coverage.red,
                      fontWeight: 700,
                    }}
                  />
                </Tooltip>
              </Stack>
            ))}
          </Stack>
        )}
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Reusable chart + tile primitives
// ---------------------------------------------------------------------------

function ViewToggle<T extends string>({
  value,
  options,
  onChange,
}: {
  value: T;
  options: { value: T; label: string }[];
  onChange: (v: T) => void;
}) {
  return (
    <ToggleButtonGroup
      size="small"
      exclusive
      value={value}
      onChange={(_, v) => {
        if (v) onChange(v as T);
      }}
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
      {options.map((o) => (
        <ToggleButton key={o.value} value={o.value}>
          {o.label}
        </ToggleButton>
      ))}
    </ToggleButtonGroup>
  );
}

function StatTile({
  label,
  value,
  hint,
  accentColor,
}: {
  label: string;
  value: string;
  hint?: string;
  accentColor: string;
}) {
  return (
    <Card>
      <CardContent sx={{ p: 2.5, '&:last-child': { pb: 2.5 } }}>
        <Stack direction="row" alignItems="center" spacing={1.5}>
          <Box
            sx={{
              width: 4,
              height: 32,
              borderRadius: 2,
              bgcolor: accentColor,
            }}
          />
          <Box sx={{ minWidth: 0 }}>
            <Typography variant="caption" color="text.secondary">
              {label}
            </Typography>
            <Typography
              variant="h4"
              sx={{
                fontWeight: 800,
                letterSpacing: '-0.03em',
                lineHeight: 1.1,
              }}
            >
              {value}
            </Typography>
            {hint && (
              <Typography
                variant="caption"
                color="text.secondary"
                sx={{ display: 'block', mt: 0.25 }}
              >
                {hint}
              </Typography>
            )}
          </Box>
        </Stack>
      </CardContent>
    </Card>
  );
}

function LegendRow({
  color,
  label,
  value,
}: {
  color: string;
  label: string;
  value: string;
}) {
  return (
    <Stack direction="row" spacing={1} alignItems="center">
      <Box sx={{ width: 10, height: 10, borderRadius: '3px', bgcolor: color }} />
      <Typography variant="body2" sx={{ flex: 1, fontWeight: 500 }}>
        {label}
      </Typography>
      <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600 }}>
        {value}
      </Typography>
    </Stack>
  );
}

function ClickableLegendRow({
  color,
  label,
  value,
  sub,
  active,
  onClick,
}: {
  color: string;
  label: string;
  value: string;
  sub?: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <ButtonBase
      onClick={onClick}
      sx={(t) => ({
        display: 'block',
        width: '100%',
        textAlign: 'left',
        p: 0.75,
        borderRadius: 1.5,
        bgcolor: active ? alpha(color, 0.14) : 'transparent',
        '&:hover': { bgcolor: alpha(color, 0.08) },
        transition: 'background-color 120ms ease',
      })}
    >
      <Stack direction="row" spacing={1} alignItems="center">
        <Box sx={{ width: 10, height: 10, borderRadius: '3px', bgcolor: color }} />
        <Typography variant="body2" sx={{ flex: 1, fontWeight: 600 }}>
          {label}
        </Typography>
        <Typography
          variant="caption"
          color="text.secondary"
          sx={{ fontWeight: 600 }}
        >
          {value}
        </Typography>
      </Stack>
      {sub && (
        <Typography
          variant="caption"
          color="text.secondary"
          sx={{ display: 'block', pl: 2.25, lineHeight: 1.4, mt: 0.25 }}
        >
          {sub}
        </Typography>
      )}
    </ButtonBase>
  );
}

interface Slice {
  key: string;
  value: number;
  color: string;
}

function Donut({
  slices,
  total,
  centerLabel,
  centerHint,
  size = 140,
  thickness = 18,
  activeKey,
  onSliceClick,
  sliceTooltip,
}: {
  slices: Slice[];
  total: number;
  centerLabel: string;
  centerHint: string;
  size?: number;
  thickness?: number;
  activeKey?: string | null;
  onSliceClick?: (key: string) => void;
  sliceTooltip?: (key: string) => string;
}) {
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  const cx = size / 2;
  const cy = size / 2;
  const anyActive = Boolean(activeKey);

  let acc = 0;
  return (
    <Box sx={{ position: 'relative', width: size, height: size, flexShrink: 0 }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle
          cx={cx}
          cy={cy}
          r={r}
          fill="none"
          stroke="currentColor"
          strokeOpacity={0.08}
          strokeWidth={thickness}
        />
        {total > 0 &&
          slices.map((s) => {
            const len = (s.value / total) * c;
            const offset = -acc;
            acc += len;
            const isActive = activeKey === s.key;
            const dimmed = anyActive && !isActive;
            const circle = (
              <circle
                key={s.key}
                cx={cx}
                cy={cy}
                r={r}
                fill="none"
                stroke={s.color}
                strokeWidth={isActive ? thickness + 4 : thickness}
                strokeDasharray={`${len} ${c - len}`}
                strokeDashoffset={offset}
                transform={`rotate(-90 ${cx} ${cy})`}
                strokeLinecap="butt"
                style={{
                  cursor: onSliceClick ? 'pointer' : 'default',
                  opacity: dimmed ? 0.35 : 1,
                  transition:
                    'stroke-width 120ms ease, opacity 120ms ease',
                }}
                onClick={onSliceClick ? () => onSliceClick(s.key) : undefined}
              />
            );
            if (!sliceTooltip) return circle;
            return (
              <Tooltip key={s.key} title={sliceTooltip(s.key)}>
                {circle}
              </Tooltip>
            );
          })}
      </svg>
      <Box
        sx={{
          position: 'absolute',
          inset: 0,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          pointerEvents: 'none',
        }}
      >
        <Typography
          sx={{
            fontWeight: 800,
            fontSize: '1.5rem',
            letterSpacing: '-0.03em',
            lineHeight: 1,
          }}
        >
          {centerLabel}
        </Typography>
        <Typography variant="caption" color="text.secondary">
          {centerHint}
        </Typography>
      </Box>
    </Box>
  );
}

function StackedBar({
  segments,
  total,
}: {
  segments: { key: string; value: number; color: string; label: string }[];
  total: number;
}) {
  if (total === 0) {
    return (
      <Typography color="text.secondary">No technique cells yet.</Typography>
    );
  }
  return (
    <Stack
      direction="row"
      sx={(t) => ({
        height: 16,
        borderRadius: 2,
        overflow: 'hidden',
        border: `1px solid ${t.palette.divider}`,
      })}
    >
      {segments.map((s) => (
        <Tooltip
          key={s.key}
          title={`${s.label}: ${s.value.toLocaleString()} (${Math.round(
            (s.value / total) * 100,
          )}%)`}
        >
          <Box
            sx={{
              flexBasis: `${(s.value / total) * 100}%`,
              bgcolor: s.color,
              transition: 'flex-basis 200ms ease',
            }}
          />
        </Tooltip>
      ))}
    </Stack>
  );
}

function TrendChart({ points }: { points: PosturePoint[] }) {
  const w = 600;
  const h = 180;
  const pad = { top: 12, right: 16, bottom: 24, left: 36 };
  const innerW = w - pad.left - pad.right;
  const innerH = h - pad.top - pad.bottom;

  const xs =
    points.length <= 1
      ? [pad.left + innerW / 2]
      : points.map((_, i) => pad.left + (i / (points.length - 1)) * innerW);

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

  const breadthColor = accent.cyan;
  const depthColor = coverage.amber;

  return (
    <Box sx={{ width: '100%', overflowX: 'auto' }}>
      <svg
        viewBox={`0 0 ${w} ${h}`}
        preserveAspectRatio="xMinYMid meet"
        style={{ width: '100%', minWidth: 320 }}
      >
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
              <text
                x={4}
                y={y + 4}
                fontSize={10}
                fill="currentColor"
                opacity={0.55}
              >
                {Math.round(g * 100)}%
              </text>
            </g>
          );
        })}

        <path d={breadthPath} stroke={breadthColor} strokeWidth={2} fill="none" />
        {points.map((p, i) => (
          <circle
            key={`b-${p.id}`}
            cx={xs[i]}
            cy={yBreadth(p.breadth_pct)}
            r={3}
            fill={breadthColor}
          />
        ))}

        <path
          d={depthPath}
          stroke={depthColor}
          strokeWidth={2}
          fill="none"
          opacity={0.9}
          strokeDasharray="4 4"
        />
        {points.map((p, i) => (
          <circle
            key={`d-${p.id}`}
            cx={xs[i]}
            cy={yDepth(p.depth_avg)}
            r={2.5}
            fill={depthColor}
          />
        ))}

        <g transform={`translate(${pad.left}, ${h - 4})`}>
          <circle cx={4} cy={-6} r={3} fill={breadthColor} />
          <text x={12} y={-3} fontSize={11} fill="currentColor" opacity={0.7}>
            Breadth %
          </text>
          <circle cx={90} cy={-6} r={3} fill={depthColor} />
          <text x={98} y={-3} fontSize={11} fill="currentColor" opacity={0.7}>
            Depth (0–5)
          </text>
        </g>
      </svg>
    </Box>
  );
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
