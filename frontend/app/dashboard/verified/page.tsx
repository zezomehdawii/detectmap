'use client';

import { Fragment, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Divider,
  IconButton,
  InputAdornment,
  LinearProgress,
  MenuItem,
  Paper,
  Stack,
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
import ExpandLessRoundedIcon from '@mui/icons-material/ExpandLessRounded';
import ExpandMoreRoundedIcon from '@mui/icons-material/ExpandMoreRounded';
import FactCheckRoundedIcon from '@mui/icons-material/FactCheckRounded';
import FilterAltOffRoundedIcon from '@mui/icons-material/FilterAltOffRounded';
import SearchRoundedIcon from '@mui/icons-material/SearchRounded';
import WarningAmberRoundedIcon from '@mui/icons-material/WarningAmberRounded';

import {
  DetectionEvidence,
  TechniqueEvidence,
  VerifiedCoverage,
  apiErrorMessage,
  getVerifiedCoverage,
  getVerifiedTechnique,
} from '@/lib/api';
import { coverage } from '../../theme';

const PAGE_LIMIT = 200;

const LEVEL_META = [
  { level: 0, label: 'No detection', color: coverage.grey, hint: 'No detection exists for this technique.' },
  { level: 1, label: 'Designed', color: coverage.grey, hint: 'A Sigma rule exists.' },
  { level: 2, label: 'Mapped', color: coverage.amber, hint: 'ATT&CK technique and Sigma logsource are mapped.' },
  { level: 3, label: 'Tested', color: coverage.blue, hint: 'All positive/negative event samples pass.' },
  { level: 4, label: 'Deployed verified', color: coverage.green, hint: 'An enabled matching SIEM rule was imported.' },
  { level: 5, label: 'Telemetry ready', color: coverage.green, hint: 'Required telemetry is collected.' },
  { level: 6, label: 'Proven', color: coverage.green, hint: 'A true-positive outcome has been recorded.' },
];

const CLAIMED_META: Record<string, { label: string; color: string }> = {
  deployed: { label: 'Deployed', color: coverage.green },
  in_progress: { label: 'In progress', color: coverage.amber },
  idea: { label: 'Idea', color: coverage.blue },
  gap: { label: 'Gap', color: coverage.red },
  not_applicable: { label: 'Not applicable', color: coverage.grey },
};

const VISIBILITY_META: Record<string, { label: string; color: string }> = {
  visible: { label: 'Visible', color: coverage.green },
  partial: { label: 'Partial', color: coverage.amber },
  not_collected: { label: 'Not collected', color: coverage.red },
  no_data_source: { label: 'No data source', color: coverage.red },
  unknown: { label: 'Unknown', color: coverage.grey },
};

function levelMeta(level: number) {
  return LEVEL_META.find((item) => item.level === level) ?? LEVEL_META[0];
}

function pct(value: number, total: number): number {
  return total > 0 ? Math.round((value / total) * 100) : 0;
}

type TechniqueDetailState = {
  loading: boolean;
  error?: string;
  detections?: DetectionEvidence[];
};

export default function VerifiedCoveragePage() {
  const [data, setData] = useState<VerifiedCoverage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [levelFilter, setLevelFilter] = useState('all');
  const [onlyBlockers, setOnlyBlockers] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [details, setDetails] = useState<Record<string, TechniqueDetailState>>({});

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    getVerifiedCoverage()
      .then((payload) => {
        if (active) setData(payload);
      })
      .catch((e) => {
        if (active) {
          setError(apiErrorMessage(e, 'Failed to load verified coverage.'));
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  const filtered = useMemo(() => {
    if (!data) return [];
    const needle = query.trim().toLowerCase();
    return data.techniques
      .filter((technique) => {
        if (levelFilter !== 'all' && technique.level !== Number(levelFilter)) {
          return false;
        }
        if (onlyBlockers && technique.blockers.length === 0) return false;
        if (!needle) return true;
        const haystack =
          `${technique.technique_id} ${technique.name} ${technique.tactics.join(' ')}`.toLowerCase();
        return haystack.includes(needle);
      })
      .sort((a, b) => {
        // Put techniques with actual rules first; otherwise the first screen
        // is entirely "no detection" rows and the evidence work is hidden.
        if (a.detection_count === 0 && b.detection_count > 0) return 1;
        if (b.detection_count === 0 && a.detection_count > 0) return -1;
        if (b.detection_count !== a.detection_count) {
          return b.detection_count - a.detection_count;
        }
        return a.level - b.level || a.technique_id.localeCompare(b.technique_id);
      });
  }, [data, levelFilter, onlyBlockers, query]);

  const visible = filtered.slice(0, PAGE_LIMIT);
  const total = data?.total_techniques ?? 0;
  const detectionDebt = data ? Math.max(0, data.designed_count - data.verified_deployed_count) : 0;

  function toggleTechnique(technique: TechniqueEvidence) {
    const tid = technique.technique_id;
    const willOpen = expanded !== tid;
    setExpanded(willOpen ? tid : null);
    if (!willOpen || technique.detection_count === 0) return;

    const cached = details[tid];
    if (cached && !cached.error) return;

    setDetails((current) => ({ ...current, [tid]: { loading: true } }));
    getVerifiedTechnique(tid)
      .then((payload) => {
        setDetails((current) => ({
          ...current,
          [tid]: { loading: false, detections: payload.detections },
        }));
      })
      .catch((e) => {
        setDetails((current) => ({
          ...current,
          [tid]: {
            loading: false,
            error: apiErrorMessage(e, 'Failed to load detection evidence.'),
          },
        }));
      });
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2.5 }}>
      <Stack
        direction={{ xs: 'column', md: 'row' }}
        justifyContent="space-between"
        alignItems={{ xs: 'flex-start', md: 'center' }}
        gap={2}
      >
        <Box>
          <Stack direction="row" spacing={1.25} alignItems="center">
            <FactCheckRoundedIcon color="primary" />
            <Typography variant="h4" sx={{ fontWeight: 700, letterSpacing: '-0.02em' }}>
              Verified coverage
            </Typography>
          </Stack>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, maxWidth: 880 }}>
            Claims versus evidence. This view asks whether a covered technique is mapped,
            tested, actually deployed, fed by telemetry, and proven by an outcome — not just
            whether a detection row says <strong>deployed</strong>.
          </Typography>
        </Box>
        {data && (
          <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
            <Chip
              label={`${data.detections_total} detections assessed`}
              variant="outlined"
              size="small"
            />
            <Chip
              label={`${detectionDebt} techniques claimed but not verified`}
              color={detectionDebt > 0 ? 'warning' : 'success'}
              size="small"
            />
          </Stack>
        )}
      </Stack>

      <Alert severity="info" icon={<WarningAmberRoundedIcon />}>
        The evidence ladder runs from <strong>Designed</strong> to <strong>Proven</strong>.
        Deployment matches are inferred from imported SIEM rules and their metadata; confirm
        a match before treating it as authoritative.
      </Alert>

      {error && (
        <Alert severity="error" onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {loading && (
        <Box sx={{ py: 8, display: 'flex', justifyContent: 'center' }}>
          <CircularProgress />
        </Box>
      )}

      {!loading && data && data.verified_deployed_count === 0 && data.designed_count > 0 && (
        <Alert severity="warning">
          No verified deployments yet. Detection rules exist, but none are matched to an
          enabled SIEM rule. Import use-cases from a connector, or add event samples and
          telemetry evidence, to move rules up the ladder.
        </Alert>
      )}

      {!loading && data && (
        <>
          <Box
            sx={{
              display: 'grid',
              gridTemplateColumns: {
                xs: '1fr',
                sm: 'repeat(2, minmax(0, 1fr))',
                lg: 'repeat(5, minmax(0, 1fr))',
              },
              gap: 1.5,
            }}
          >
            <SummaryCard
              label="Designed"
              value={data.designed_count}
              total={total}
              color={coverage.grey}
              hint="Techniques with at least one Sigma rule."
            />
            <SummaryCard
              label="Claimed deployed"
              value={data.claimed_deployed_count}
              total={total}
              color={coverage.amber}
              hint="Techniques whose rules say deployed."
            />
            <SummaryCard
              label="Verified deployed"
              value={data.verified_deployed_count}
              total={total}
              color={coverage.green}
              hint="Rules matched to an enabled SIEM rule."
            />
            <SummaryCard
              label="Effective"
              value={data.effective_count}
              total={total}
              color={coverage.blue}
              hint="Verified plus required telemetry collected."
            />
            <SummaryCard
              label="Proven"
              value={data.proven_count}
              total={total}
              color={coverage.green}
              hint="Effective plus a recorded true positive."
            />
          </Box>

          <Card variant="outlined">
            <CardContent>
              <Stack
                direction={{ xs: 'column', sm: 'row' }}
                justifyContent="space-between"
                alignItems={{ xs: 'flex-start', sm: 'center' }}
                gap={1}
              >
                <Box>
                  <Typography variant="h6">Evidence ladder</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Techniques are counted at their highest evidenced level.
                  </Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  {data.not_applicable_count} not-applicable techniques excluded
                </Typography>
              </Stack>
              <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap sx={{ mt: 2 }}>
                {LEVEL_META.map((item) => {
                  const count = data.level_counts[String(item.level)] ?? 0;
                  return (
                    <Tooltip key={item.level} title={item.hint}>
                      <Chip
                        label={`${item.level} · ${item.label}: ${count}`}
                        size="small"
                        sx={{
                          bgcolor: alpha(item.color, 0.14),
                          color: item.color,
                          fontWeight: 700,
                          border: `1px solid ${alpha(item.color, 0.28)}`,
                        }}
                      />
                    </Tooltip>
                  );
                })}
              </Stack>
            </CardContent>
          </Card>

          <Paper variant="outlined" sx={{ p: 2 }}>
            <Stack
              direction={{ xs: 'column', lg: 'row' }}
              spacing={2}
              alignItems={{ xs: 'stretch', lg: 'center' }}
            >
              <TextField
                size="small"
                label="Search techniques"
                placeholder="T1059, LSASS, credential…"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                sx={{ minWidth: { xs: '100%', lg: 320 } }}
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
                label="Evidence level"
                value={levelFilter}
                onChange={(event) => setLevelFilter(event.target.value)}
                sx={{ minWidth: 210 }}
              >
                <MenuItem value="all">All levels</MenuItem>
                {LEVEL_META.map((item) => (
                  <MenuItem key={item.level} value={String(item.level)}>
                    {item.level} · {item.label}
                  </MenuItem>
                ))}
              </TextField>
              <Button
                variant={onlyBlockers ? 'contained' : 'outlined'}
                startIcon={<FilterAltOffRoundedIcon />}
                onClick={() => setOnlyBlockers((value) => !value)}
              >
                Only with blockers
              </Button>
              <Box sx={{ flex: 1 }} />
              <Typography variant="body2" color="text.secondary">
                {filtered.length} of {data.techniques.length} techniques
              </Typography>
            </Stack>
          </Paper>

          <Paper variant="outlined" sx={{ overflow: 'hidden' }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ width: 38 }} />
                  <TableCell>Technique</TableCell>
                  <TableCell sx={{ width: 135 }}>Claimed</TableCell>
                  <TableCell sx={{ width: 135 }}>Telemetry</TableCell>
                  <TableCell sx={{ width: 190 }}>Evidence</TableCell>
                  <TableCell sx={{ width: 90 }} align="right">
                    Rules
                  </TableCell>
                  <TableCell>Next action</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {visible.map((technique) => {
                  const open = expanded === technique.technique_id;
                  const evidence = levelMeta(technique.level);
                  const claimed = CLAIMED_META[technique.claimed_state] ?? {
                    label: technique.claimed_state,
                    color: coverage.grey,
                  };
                  const visibility = VISIBILITY_META[technique.visibility_state] ?? {
                    label: technique.visibility_state,
                    color: coverage.grey,
                  };
                  const detail = details[technique.technique_id];
                  return (
                    <Fragment key={technique.technique_id}>
                      <TableRow
                        hover
                        sx={{ cursor: 'pointer', '& > *': { verticalAlign: 'top' } }}
                        onClick={() => toggleTechnique(technique)}
                      >
                        <TableCell>
                          <IconButton size="small" aria-label={open ? 'Collapse' : 'Expand'}>
                            {open ? (
                              <ExpandLessRoundedIcon fontSize="small" />
                            ) : (
                              <ExpandMoreRoundedIcon fontSize="small" />
                            )}
                          </IconButton>
                        </TableCell>
                        <TableCell>
                          <Typography
                            variant="body2"
                            sx={{ fontWeight: 700, fontFamily: 'monospace' }}
                          >
                            {technique.technique_id}
                          </Typography>
                          <Typography variant="body2">{technique.name}</Typography>
                          <Typography variant="caption" color="text.secondary">
                            {technique.tactics.join(' · ') || 'uncategorised'}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            size="small"
                            label={claimed.label}
                            sx={{
                              bgcolor: alpha(claimed.color, 0.14),
                              color: claimed.color,
                              fontWeight: 700,
                            }}
                          />
                        </TableCell>
                        <TableCell>
                          <Chip
                            size="small"
                            label={visibility.label}
                            sx={{
                              bgcolor: alpha(visibility.color, 0.14),
                              color: visibility.color,
                              fontWeight: 700,
                            }}
                          />
                        </TableCell>
                        <TableCell>
                          <Tooltip title={evidence.hint}>
                            <Chip
                              size="small"
                              label={`${technique.level} · ${technique.level_label}`}
                              sx={{
                                bgcolor: alpha(evidence.color, 0.16),
                                color: evidence.color,
                                fontWeight: 700,
                              }}
                            />
                          </Tooltip>
                        </TableCell>
                        <TableCell align="right">
                          <Typography variant="body2">{technique.detection_count}</Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">{technique.next_action}</Typography>
                          {technique.blockers.length > 0 && (
                            <Typography variant="caption" color="text.secondary">
                              {technique.blockers.slice(0, 2).join(' · ')}
                              {technique.blockers.length > 2
                                ? ` · +${technique.blockers.length - 2} more`
                                : ''}
                            </Typography>
                          )}
                        </TableCell>
                      </TableRow>
                      {open && (
                        <TableRow>
                          <TableCell
                            colSpan={7}
                            sx={{ py: 0, bgcolor: alpha(coverage.grey, 0.05) }}
                          >
                            <Box sx={{ py: 2 }}>
                              {technique.detection_count === 0 ? (
                                <Alert severity="warning">
                                  No detection covers this technique yet. {technique.next_action}.
                                </Alert>
                              ) : !detail || detail.loading ? (
                                <Stack
                                  direction="row"
                                  spacing={1.5}
                                  alignItems="center"
                                  sx={{ py: 1 }}
                                >
                                  <CircularProgress size={20} />
                                  <Typography variant="body2" color="text.secondary">
                                    Loading detection evidence…
                                  </Typography>
                                </Stack>
                              ) : detail.error ? (
                                <Alert severity="error">{detail.error}</Alert>
                              ) : (
                                <Stack spacing={1.25}>
                                  {technique.blockers.length > 0 && (
                                    <Alert severity="warning">
                                      {technique.blockers.join(' · ')}
                                    </Alert>
                                  )}
                                  {(detail.detections ?? []).length === 0 ? (
                                    <Alert severity="warning">
                                      No detection evidence was returned for this technique.
                                    </Alert>
                                  ) : (
                                    (detail.detections ?? []).map((detection) => (
                                      <DetectionCard
                                        key={detection.id}
                                        detection={detection}
                                      />
                                    ))
                                  )}
                                </Stack>
                              )}
                            </Box>
                          </TableCell>
                        </TableRow>
                      )}
                    </Fragment>
                  );
                })}
              </TableBody>
            </Table>
          </Paper>

          {filtered.length > PAGE_LIMIT && (
            <Typography variant="body2" color="text.secondary">
              Showing the first {PAGE_LIMIT} of {filtered.length} matching techniques. Narrow
              the search or level filter to see the rest.
            </Typography>
          )}

          {filtered.length === 0 && (
            <Alert severity="success">No techniques match these filters.</Alert>
          )}
        </>
      )}
    </Box>
  );
}

function SummaryCard({
  label,
  value,
  total,
  color,
  hint,
}: {
  label: string;
  value: number;
  total: number;
  color: string;
  hint: string;
}) {
  const percentage = pct(value, total);
  return (
    <Card variant="outlined" sx={{ height: '100%' }}>
      <CardContent>
        <Typography variant="overline" color="text.secondary">
          {label}
        </Typography>
        <Stack direction="row" alignItems="baseline" spacing={1}>
          <Typography variant="h4" sx={{ fontWeight: 800, color }}>
            {value}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            / {total} · {percentage}%
          </Typography>
        </Stack>
        <LinearProgress
          variant="determinate"
          value={percentage}
          sx={{
            mt: 1.25,
            height: 6,
            borderRadius: 3,
            bgcolor: alpha(color, 0.14),
            '& .MuiLinearProgress-bar': { bgcolor: color },
          }}
        />
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1 }}>
          {hint}
        </Typography>
      </CardContent>
    </Card>
  );
}

function DetectionCard({ detection }: { detection: DetectionEvidence }) {
  const evidence = levelMeta(detection.level);
  return (
    <Paper variant="outlined" sx={{ p: 1.5 }}>
      <Stack
        direction={{ xs: 'column', md: 'row' }}
        justifyContent="space-between"
        spacing={1}
      >
        <Box>
          <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
            {detection.title}
          </Typography>
          <Typography variant="caption" color="text.secondary">
            {detection.sigma_id || 'no sigma id'} · {detection.status} · {detection.source}
          </Typography>
        </Box>
        <Stack direction="row" spacing={0.75} flexWrap="wrap" useFlexGap>
          <Chip
            size="small"
            label={`${detection.level} · ${detection.level_label}`}
            sx={{
              bgcolor: alpha(evidence.color, 0.16),
              color: evidence.color,
              fontWeight: 700,
            }}
          />
          <Chip
            size="small"
            variant="outlined"
            label={`Tests ${detection.samples_passed}/${detection.samples_total}`}
          />
          <Chip
            size="small"
            variant="outlined"
            label={`TP ${detection.tp_count} · FP ${detection.fp_count}`}
          />
          <Chip
            size="small"
            variant="outlined"
            label={`Telemetry: ${detection.telemetry_state}`}
          />
        </Stack>
      </Stack>

      {detection.blockers.length > 0 && (
        <Alert severity="warning" sx={{ mt: 1 }}>
          {detection.blockers.join(' · ')}
        </Alert>
      )}

      <Typography variant="body2" sx={{ mt: 1 }}>
        <strong>Next:</strong> {detection.next_action}
      </Typography>

      {detection.deployed_matches.length > 0 && (
        <>
          <Divider sx={{ my: 1 }} />
          <Stack direction="row" spacing={0.75} flexWrap="wrap" useFlexGap>
            {detection.deployed_matches.map((match, index) => (
              <Chip
                key={`${match.connector}-${match.name}-${index}`}
                size="small"
                variant="outlined"
                color={match.enabled ? 'success' : 'default'}
                label={`${match.connector}: ${match.name}${match.enabled ? '' : ' (disabled)'}`}
              />
            ))}
          </Stack>
        </>
      )}

      {detection.missing_data_sources.length > 0 && (
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1 }}>
          Missing data: {detection.missing_data_sources.slice(0, 4).join(', ')}
          {detection.missing_data_sources.length > 4 ? '…' : ''}
        </Typography>
      )}
    </Paper>
  );
}
