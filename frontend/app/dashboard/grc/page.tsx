'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Autocomplete,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Divider,
  Drawer,
  IconButton,
  ListSubheader,
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
import AddRoundedIcon from '@mui/icons-material/AddRounded';
import CloseRoundedIcon from '@mui/icons-material/CloseRounded';
import DeleteOutlineRoundedIcon from '@mui/icons-material/DeleteOutlineRounded';
import DownloadRoundedIcon from '@mui/icons-material/DownloadRounded';
import {
  ControlState,
  GRCControl,
  GRCControlD3FEND,
  GRCFrameworkCoverage,
  GRCFrameworkSummary,
  GRCMapping,
  GRCScorecardRow,
  deleteGRCMapping,
  downloadReport,
  getGRCFrameworkCoverage,
  getGRCScorecard,
  listGRCControlD3FEND,
  listGRCFrameworks,
  listGRCMappings,
  upsertGRCMapping,
} from '@/lib/api';
import { useFeatures } from '@/lib/features';
import { coverage } from '../../theme';

const STATE_COLOR: Record<ControlState, string> = {
  deployed: coverage.green,
  partial: '#7fc88a',
  in_progress: coverage.amber,
  idea: coverage.idea,
  gap: coverage.red,
  unmapped: coverage.grey,
};

const STATE_LABEL: Record<ControlState, string> = {
  deployed: 'Deployed',
  partial: 'Partial',
  in_progress: 'In progress',
  idea: 'Idea',
  gap: 'Gap',
  unmapped: 'Unmapped',
};

export default function GRCPage() {
  const [frameworks, setFrameworks] = useState<GRCFrameworkSummary[]>([]);
  const [selectedKey, setSelectedKey] = useState<string>('');
  const [coverageData, setCoverageData] = useState<GRCFrameworkCoverage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [openControl, setOpenControl] = useState<GRCControl | null>(null);
  const [scorecard, setScorecard] = useState<GRCScorecardRow[]>([]);

  useEffect(() => {
    listGRCFrameworks()
      .then((rows) => {
        setFrameworks(rows);
        if (rows.length && !selectedKey) setSelectedKey(rows[0].key);
      })
      .catch((e) => setError(e?.response?.data?.detail ?? 'failed to load frameworks'));
    getGRCScorecard().then(setScorecard).catch(() => setScorecard([]));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const refresh = useCallback(async () => {
    if (!selectedKey) return;
    setLoading(true);
    setError(null);
    try {
      const d = await getGRCFrameworkCoverage(selectedKey);
      setCoverageData(d);
      if (openControl) {
        const next = d.controls.find((c) => c.id === openControl.id) ?? null;
        setOpenControl(next);
      }
    } catch (e: any) {
      setError(
        e?.response?.data?.detail ??
          'failed to load coverage — pick a customer in the topbar if you are an MSSP user.',
      );
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedKey]);

  useEffect(() => {
    if (selectedKey) refresh();
  }, [refresh, selectedKey]);

  const selectedFramework = useMemo(
    () => frameworks.find((f) => f.key === selectedKey),
    [frameworks, selectedKey],
  );

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      <Box>
        <Typography variant="h4" sx={{ fontWeight: 700, letterSpacing: '-0.02em' }}>
          GRC crosswalk
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Map ATT&amp;CK techniques and mitigations to compliance controls.
          Each row rolls up your detection state across its mapped TTPs.
        </Typography>
      </Box>

      {scorecard.length > 0 && (
        <Stack direction="row" spacing={2} flexWrap="wrap" useFlexGap>
          {scorecard.map((s) => {
            const pct = s.weighted_pct;
            const color = pct >= 75 ? coverage.green : pct >= 40 ? coverage.amber : coverage.red;
            return (
              <Card
                key={s.key}
                onClick={() => setSelectedKey(s.key)}
                sx={{
                  flex: '1 1 220px',
                  cursor: 'pointer',
                  outline: s.key === selectedKey ? `2px solid ${coverage.green}` : 'none',
                }}
              >
                <CardContent sx={{ p: 2, '&:last-child': { pb: 2 } }}>
                  <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600 }}>
                    {s.label}
                  </Typography>
                  <Stack direction="row" alignItems="baseline" spacing={1}>
                    <Typography variant="h5" sx={{ fontWeight: 800, color }}>
                      {pct}%
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      weighted
                    </Typography>
                  </Stack>
                  <Box
                    sx={{
                      mt: 0.5,
                      height: 6,
                      borderRadius: 3,
                      bgcolor: alpha(color, 0.18),
                      overflow: 'hidden',
                    }}
                  >
                    <Box sx={{ width: `${pct}%`, height: '100%', bgcolor: color }} />
                  </Box>
                  <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: 'block' }}>
                    {s.addressed_pct}% addressed · {s.total_controls} controls
                  </Typography>
                </CardContent>
              </Card>
            );
          })}
        </Stack>
      )}

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
              label="Framework"
              value={selectedKey}
              onChange={(e) => setSelectedKey(e.target.value)}
              sx={{ minWidth: 280 }}
            >
              {(() => {
                // Group frameworks visually: international standards first,
                // then the Saudi NCA family. Within each group items are
                // listed in registry order so the picker is predictable.
                const intl = frameworks.filter((f) => !f.key.startsWith('nca_'));
                const nca = frameworks.filter((f) => f.key.startsWith('nca_'));
                const items: React.ReactNode[] = [];
                if (intl.length > 0) {
                  items.push(
                    <ListSubheader key="hdr-intl" disableSticky>
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
                    <ListSubheader key="hdr-nca" disableSticky>
                      Saudi NCA
                    </ListSubheader>,
                  );
                  for (const f of nca) {
                    // Inside the NCA group, the "NCA …" prefix is redundant
                    // with the header — show the short framework code.
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
            {selectedFramework && (
              <Stack direction="row" spacing={1}>
                <Chip
                  size="small"
                  label={`${selectedFramework.control_count} controls`}
                  variant="outlined"
                />
                <Chip
                  size="small"
                  label={`${selectedFramework.technique_mapping_count} TTP mappings`}
                  variant="outlined"
                />
                <Chip
                  size="small"
                  label={`${selectedFramework.mitigation_mapping_count} mitigation mappings`}
                  variant="outlined"
                />
              </Stack>
            )}
            <Box sx={{ flex: 1 }} />
            {selectedKey && (
              <Stack direction="row" spacing={1}>
                <Button
                  size="small"
                  variant="outlined"
                  startIcon={<DownloadRoundedIcon />}
                  onClick={() =>
                    downloadReport(
                      `/grc/evidence/${selectedKey}.csv`,
                      `evidence-${selectedKey}.csv`,
                    )
                  }
                >
                  Evidence CSV
                </Button>
                <Button
                  size="small"
                  variant="outlined"
                  startIcon={<DownloadRoundedIcon />}
                  onClick={() =>
                    downloadReport(
                      `/grc/evidence/${selectedKey}.json`,
                      `evidence-${selectedKey}.json`,
                    )
                  }
                >
                  Evidence JSON
                </Button>
                <Button
                  size="small"
                  variant="contained"
                  startIcon={<DownloadRoundedIcon />}
                  onClick={() =>
                    downloadReport(
                      `/grc/evidence/${selectedKey}.pdf`,
                      `evidence-${selectedKey}.pdf`,
                    )
                  }
                >
                  Evidence PDF
                </Button>
              </Stack>
            )}
          </Stack>
          {coverageData && (
            <Stack direction="row" spacing={1.5} sx={{ mt: 2 }} flexWrap="wrap" useFlexGap>
              {(Object.keys(coverageData.counts_by_state) as ControlState[]).map((s) => (
                <Chip
                  key={s}
                  size="small"
                  label={`${STATE_LABEL[s] ?? s}: ${coverageData.counts_by_state[s] ?? 0}`}
                  sx={{
                    bgcolor: alpha(STATE_COLOR[s] ?? coverage.grey, 0.18),
                    color: STATE_COLOR[s] ?? 'text.primary',
                    fontWeight: 700,
                  }}
                />
              ))}
            </Stack>
          )}
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

      {coverageData && !loading && (
        <Paper variant="outlined" sx={{ overflow: 'hidden' }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell sx={{ width: 110 }}>Control</TableCell>
                <TableCell sx={{ width: 150 }}>Family</TableCell>
                <TableCell>Name</TableCell>
                <TableCell sx={{ width: 130 }}>State</TableCell>
                <TableCell sx={{ width: 110 }} align="right">
                  Mapped
                </TableCell>
                <TableCell sx={{ width: 240 }}>Techniques</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {coverageData.controls.map((c) => (
                <TableRow
                  key={c.id}
                  hover
                  onClick={() => setOpenControl(c)}
                  sx={{ cursor: 'pointer' }}
                >
                  <TableCell sx={{ fontFamily: 'JetBrains Mono, monospace', fontWeight: 600 }}>
                    {c.control_id}
                  </TableCell>
                  <TableCell>{c.family ?? '—'}</TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontWeight: 500 }}>
                      {c.name}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={STATE_LABEL[c.state]}
                      size="small"
                      sx={{
                        bgcolor: STATE_COLOR[c.state],
                        color: '#ffffff',
                        fontWeight: 700,
                      }}
                    />
                  </TableCell>
                  <TableCell align="right">
                    <Tooltip
                      title={`${c.seeded_count} seeded · ${c.user_count} user`}
                      arrow
                    >
                      <span>
                        {c.technique_count}
                        {c.user_count > 0 && (
                          <Chip
                            size="small"
                            label="+user"
                            color="primary"
                            sx={{ ml: 1, height: 18, fontSize: '0.65rem' }}
                          />
                        )}
                      </span>
                    </Tooltip>
                  </TableCell>
                  <TableCell>
                    <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                      {c.mapped_techniques.slice(0, 4).map((t) => (
                        <Chip
                          key={t}
                          label={t}
                          size="small"
                          variant="outlined"
                          sx={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.7rem' }}
                        />
                      ))}
                      {c.mapped_techniques.length > 4 && (
                        <Chip label={`+${c.mapped_techniques.length - 4}`} size="small" />
                      )}
                    </Stack>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Paper>
      )}

      <MappingEditor
        control={openControl}
        onClose={() => setOpenControl(null)}
        onChanged={refresh}
      />
    </Box>
  );
}

function MappingEditor({
  control,
  onClose,
  onChanged,
}: {
  control: GRCControl | null;
  onClose: () => void;
  onChanged: () => void;
}) {
  const { isEnabled, customer: activeCustomer } = useFeatures();
  // The grc_editing toggle is per-customer; MSSP-wide GRC catalog edits
  // (no active customer) aren't gated — match the backend's
  // optional_customer enforcement so the UI stays consistent.
  const canEdit = !activeCustomer || isEnabled('grc_editing');
  const [mappings, setMappings] = useState<GRCMapping[]>([]);
  const [d3fend, setD3fend] = useState<GRCControlD3FEND[]>([]);
  const [loading, setLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Add-form state
  const [kind, setKind] = useState<'technique' | 'mitigation'>('technique');
  const [target, setTarget] = useState('');
  const [rationale, setRationale] = useState('');

  const reload = useCallback(async () => {
    if (!control) return;
    setLoading(true);
    setError(null);
    try {
      const [r, d3] = await Promise.all([
        listGRCMappings(control.id),
        listGRCControlD3FEND(control.id).catch(() => []),
      ]);
      setMappings(r);
      setD3fend(d3);
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'failed to load mappings');
    } finally {
      setLoading(false);
    }
  }, [control]);

  useEffect(() => {
    if (control) {
      setTarget('');
      setRationale('');
      setError(null);
      reload();
    } else {
      setMappings([]);
    }
  }, [control, reload]);

  async function addMapping() {
    if (!control || !target.trim()) return;
    setSubmitting(true);
    setError(null);
    try {
      await upsertGRCMapping({
        control_id: control.id,
        target_kind: kind,
        target_id: target.trim().toUpperCase(),
        rationale: rationale.trim() || undefined,
      });
      setTarget('');
      setRationale('');
      await reload();
      onChanged();
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'add failed');
    } finally {
      setSubmitting(false);
    }
  }

  async function removeMapping(m: GRCMapping) {
    if (!confirm(`Remove mapping ${m.target_id} (${m.source})?`)) return;
    try {
      await deleteGRCMapping(m.id, m.target_kind);
      await reload();
      onChanged();
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'remove failed');
    }
  }

  return (
    <Drawer
      anchor="right"
      open={control !== null}
      onClose={onClose}
      PaperProps={{ sx: { width: { xs: '100%', md: 560 } } }}
    >
      {control && (
        <Box sx={{ p: 3, display: 'flex', flexDirection: 'column', gap: 2 }}>
          <Stack direction="row" alignItems="center" spacing={1}>
            <Box>
              <Typography
                sx={{ fontFamily: 'JetBrains Mono, monospace', fontWeight: 700 }}
              >
                {control.control_id}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {control.family ?? ''}
              </Typography>
            </Box>
            <Box sx={{ flex: 1 }} />
            <Chip
              label={STATE_LABEL[control.state]}
              size="small"
              sx={{
                bgcolor: STATE_COLOR[control.state],
                color: '#ffffff',
                fontWeight: 700,
              }}
            />
            <IconButton onClick={onClose} size="small">
              <CloseRoundedIcon />
            </IconButton>
          </Stack>

          <Typography variant="h6" sx={{ fontWeight: 700 }}>
            {control.name}
          </Typography>
          {control.description && (
            <Typography variant="body2" color="text.secondary">
              {control.description}
            </Typography>
          )}

          <Stack direction="row" spacing={2}>
            <Box>
              <Typography variant="caption" color="text.secondary">
                Deployed
              </Typography>
              <Typography variant="h6">{control.deployed_count}</Typography>
            </Box>
            <Box>
              <Typography variant="caption" color="text.secondary">
                In progress
              </Typography>
              <Typography variant="h6">{control.in_progress_count}</Typography>
            </Box>
            <Box>
              <Typography variant="caption" color="text.secondary">
                Idea
              </Typography>
              <Typography variant="h6">{control.idea_count}</Typography>
            </Box>
            <Box>
              <Typography variant="caption" color="text.secondary">
                Gap
              </Typography>
              <Typography variant="h6">{control.gap_count}</Typography>
            </Box>
            <Box>
              <Typography variant="caption" color="text.secondary">
                D3FEND
              </Typography>
              <Typography variant="h6">{control.d3fend_count}</Typography>
            </Box>
          </Stack>

          <Divider />

          <Typography
            variant="overline"
            sx={{ fontWeight: 700, color: 'text.secondary' }}
          >
            Mappings ({mappings.length})
          </Typography>

          {error && <Typography color="error">{error}</Typography>}

          {loading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', py: 2 }}>
              <CircularProgress size={22} />
            </Box>
          ) : (
            <Paper variant="outlined" sx={{ p: 0.5 }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ width: 80 }}>Kind</TableCell>
                    <TableCell sx={{ width: 110 }}>ID</TableCell>
                    <TableCell>Rationale</TableCell>
                    <TableCell sx={{ width: 80 }}>Source</TableCell>
                    <TableCell sx={{ width: 50 }}></TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {mappings.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={5} align="center" sx={{ color: 'text.secondary' }}>
                        No mappings yet.
                      </TableCell>
                    </TableRow>
                  )}
                  {mappings.map((m) => (
                    <TableRow key={m.id}>
                      <TableCell>{m.target_kind}</TableCell>
                      <TableCell sx={{ fontFamily: 'JetBrains Mono, monospace' }}>
                        {m.target_id}
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption">
                          {m.rationale ?? '—'}
                        </Typography>
                        {m.author && (
                          <Typography
                            variant="caption"
                            color="text.secondary"
                            sx={{ display: 'block' }}
                          >
                            by {m.author}
                          </Typography>
                        )}
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={m.source}
                          size="small"
                          color={m.source === 'user' ? 'primary' : 'default'}
                          variant={m.source === 'user' ? 'filled' : 'outlined'}
                        />
                      </TableCell>
                      <TableCell>
                        <IconButton
                          size="small"
                          color="error"
                          onClick={() => removeMapping(m)}
                          disabled={!canEdit}
                          title={
                            canEdit
                              ? 'Remove mapping'
                              : 'GRC editing is disabled for this customer'
                          }
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

          <Divider />

          <Typography
            variant="overline"
            sx={{ fontWeight: 700, color: 'text.secondary' }}
          >
            Defensive countermeasures · D3FEND ({d3fend.length})
          </Typography>
          <Typography variant="caption" color="text.secondary" sx={{ mt: -1 }}>
            Derived from this control&apos;s mapped ATT&amp;CK techniques via the
            D3FEND ontology. Read-only.
          </Typography>
          {d3fend.length === 0 ? (
            <Typography variant="body2" color="text.secondary">
              No D3FEND linkage. Either no techniques are mapped, or the D3FEND
              catalog isn&apos;t populated (Settings → Schedule → Refresh D3FEND now).
            </Typography>
          ) : (
            <Stack spacing={1}>
              {d3fend.map((d) => (
                <Box
                  key={d.d3fend_id}
                  sx={(t) => ({
                    border: `1px solid ${t.palette.divider}`,
                    borderRadius: 2,
                    p: 1,
                  })}
                >
                  <Stack direction="row" alignItems="baseline" spacing={1} flexWrap="wrap" useFlexGap>
                    <Typography
                      variant="caption"
                      sx={{ fontFamily: 'JetBrains Mono, monospace', fontWeight: 700 }}
                    >
                      {d.d3fend_id}
                    </Typography>
                    <Typography variant="body2" sx={{ fontWeight: 600, flex: 1 }}>
                      {d.name}
                    </Typography>
                    {d.relations.map((r) => (
                      <Chip
                        key={r}
                        label={r}
                        size="small"
                        variant="outlined"
                        sx={{ height: 18, fontSize: '0.6rem' }}
                      />
                    ))}
                  </Stack>
                  <Typography variant="caption" color="text.secondary">
                    addresses {d.via_techniques.join(', ')}
                  </Typography>
                </Box>
              ))}
            </Stack>
          )}

          <Divider />

          <Typography
            variant="overline"
            sx={{ fontWeight: 700, color: 'text.secondary' }}
          >
            Add mapping
          </Typography>
          {!canEdit && (
            <Typography variant="caption" color="text.secondary">
              GRC editing is disabled for this customer. Switch out of the
              customer context or ask an MSSP admin to re-enable it.
            </Typography>
          )}
          <Stack direction="row" spacing={1.5} alignItems="flex-start">
            <TextField
              select
              size="small"
              label="Kind"
              value={kind}
              onChange={(e) => setKind(e.target.value as 'technique' | 'mitigation')}
              sx={{ minWidth: 130 }}
              disabled={!canEdit}
            >
              <MenuItem value="technique">Technique</MenuItem>
              <MenuItem value="mitigation">Mitigation</MenuItem>
            </TextField>
            <TextField
              size="small"
              label={kind === 'technique' ? 'Technique ID' : 'Mitigation ID'}
              placeholder={kind === 'technique' ? 'T1059.001' : 'M1040'}
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              sx={{ flex: 1 }}
              disabled={!canEdit}
            />
          </Stack>
          <TextField
            size="small"
            label="Rationale (optional)"
            value={rationale}
            multiline
            minRows={2}
            onChange={(e) => setRationale(e.target.value)}
            disabled={!canEdit}
          />
          <Box>
            <Button
              variant="contained"
              startIcon={submitting ? <CircularProgress size={14} /> : <AddRoundedIcon />}
              onClick={addMapping}
              disabled={submitting || !target.trim() || !canEdit}
            >
              Add mapping
            </Button>
          </Box>
        </Box>
      )}
    </Drawer>
  );
}
