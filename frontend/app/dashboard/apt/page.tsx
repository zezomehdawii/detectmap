'use client';

import { useCallback, useEffect, useState } from 'react';
import {
  Autocomplete,
  Box,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Divider,
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
import {
  APTListItem,
  GroupBreakdown,
  getAPTGroup,
  listAPTPaginated,
} from '@/lib/api';
import Link from 'next/link';
import { coverage } from '../../theme';

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

export default function APTPage() {
  const [query, setQuery] = useState('');
  const [options, setOptions] = useState<APTListItem[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [breakdown, setBreakdown] = useState<GroupBreakdown | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const handle = setTimeout(() => {
      listAPTPaginated(query || undefined, 1, 30)
        .then((r) => setOptions(r.items))
        .catch(() => setOptions([]));
    }, 200);
    return () => clearTimeout(handle);
  }, [query]);

  const fetchDetail = useCallback(async (id: string) => {
    setLoading(true);
    setError(null);
    setBreakdown(null);
    try {
      const b = await getAPTGroup(id);
      setBreakdown(b);
    } catch (e: any) {
      setError(
        e?.response?.data?.detail ??
          'failed to load — pick a customer in the topbar if you are an MSSP user.',
      );
    } finally {
      setLoading(false);
    }
  }, []);

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      <Box>
        <Typography variant="h4" sx={{ fontWeight: 700, letterSpacing: '-0.02em' }}>
          APT coverage
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Detection posture against a specific adversary's TTP set. Includes
          techniques the group uses directly and via the software they leverage.
        </Typography>
      </Box>

      <Card>
        <CardContent>
          <Autocomplete
            options={options}
            getOptionLabel={(g) => `${g.group_id} · ${g.name}`}
            onInputChange={(_, v) => setQuery(v)}
            onChange={(_, v) => {
              if (v) {
                setSelectedId(v.group_id);
                fetchDetail(v.group_id);
              }
            }}
            renderInput={(params) => (
              <TextField
                {...params}
                label="Adversary group"
                placeholder="Start typing — APT28, Sandworm, Lazarus…"
              />
            )}
          />
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

      {!loading && !selectedId && !error && (
        <Card>
          <CardContent>
            <Typography color="text.secondary">
              Select an adversary above to see their TTPs broken down by tactic
              with your current coverage state.
            </Typography>
          </CardContent>
        </Card>
      )}

      {breakdown && (
        <>
          <Card>
            <CardContent>
              <Stack
                direction={{ xs: 'column', md: 'row' }}
                spacing={3}
                alignItems={{ md: 'center' }}
              >
                <PostureBadge grade={breakdown.posture_grade} />
                <Stack spacing={0.5} sx={{ flex: 1 }}>
                  <Typography variant="h5" sx={{ fontWeight: 700 }}>
                    {breakdown.group_id} · {breakdown.name}
                  </Typography>
                  <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                    {breakdown.aliases.slice(0, 8).map((a) => (
                      <Chip key={a} label={a} size="small" variant="outlined" />
                    ))}
                    {breakdown.aliases.length > 8 && (
                      <Chip label={`+${breakdown.aliases.length - 8}`} size="small" />
                    )}
                  </Stack>
                </Stack>
                <Divider orientation="vertical" flexItem />
                <Box>
                  <Typography variant="caption" color="text.secondary">
                    Techniques in scope
                  </Typography>
                  <Typography variant="h5">{breakdown.technique_count}</Typography>
                </Box>
                <Box>
                  <Typography variant="caption" color="text.secondary">
                    Covered
                  </Typography>
                  <Typography variant="h5">{breakdown.covered_count}</Typography>
                </Box>
                <Box>
                  <Typography variant="caption" color="text.secondary">
                    Deployed
                  </Typography>
                  <Typography variant="h5">{breakdown.deployed_count}</Typography>
                </Box>
                <Box>
                  <Typography variant="caption" color="text.secondary">
                    Breadth × depth
                  </Typography>
                  <Typography variant="h5">
                    {breakdown.breadth_grade} · {breakdown.depth_grade}
                  </Typography>
                </Box>
              </Stack>
            </CardContent>
          </Card>

          {Object.entries(breakdown.by_tactic).map(([tac, techs]) => (
            <Card key={tac}>
              <CardContent>
                <Typography
                  variant="overline"
                  sx={{ fontWeight: 700, color: 'text.secondary' }}
                >
                  {TACTIC_LABELS[tac] ?? tac} · {techs.length} techniques
                </Typography>
                <Table size="small" sx={{ mt: 1 }}>
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ width: 110 }}>ID</TableCell>
                      <TableCell>Technique</TableCell>
                      <TableCell sx={{ width: 110 }}>State</TableCell>
                      <TableCell sx={{ width: 80 }} align="right">
                        Detections
                      </TableCell>
                      <TableCell sx={{ width: 90 }} align="right">
                        Max depth
                      </TableCell>
                      <TableCell sx={{ width: 200 }}>Source</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {techs.map((t) => (
                      <TableRow key={`${tac}-${t.technique_id}`} hover>
                        <TableCell sx={{ fontFamily: 'JetBrains Mono, monospace' }}>
                          {t.technique_id}
                          {t.is_subtechnique && (
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
                          <Link
                            href={`/dashboard/detections?technique_id=${encodeURIComponent(t.technique_id)}`}
                            style={{ color: 'inherit', textDecoration: 'none' }}
                          >
                            <Box
                              component="span"
                              sx={{ '&:hover': { textDecoration: 'underline' }, cursor: 'pointer' }}
                            >
                              {t.name}
                            </Box>
                          </Link>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={STATE_LABEL[t.state]}
                            size="small"
                            sx={{
                              bgcolor: STATE_COLOR[t.state],
                              color: '#ffffff',
                              fontWeight: 700,
                            }}
                          />
                        </TableCell>
                        <TableCell align="right">{t.detection_count}</TableCell>
                        <TableCell align="right">
                          {t.detection_count > 0 ? `${t.max_depth}/5` : '—'}
                        </TableCell>
                        <TableCell>
                          <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                            {t.sources.map((s) => (
                              <Chip
                                key={s}
                                label={s}
                                size="small"
                                variant="outlined"
                                sx={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.7rem' }}
                              />
                            ))}
                          </Stack>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          ))}
        </>
      )}
    </Box>
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
        width: 72,
        height: 72,
        borderRadius: '16px',
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
          fontSize: '2.2rem',
          letterSpacing: '-0.04em',
        }}
      >
        {grade}
      </Typography>
    </Box>
  );
}
