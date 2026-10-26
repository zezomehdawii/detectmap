'use client';

import { useEffect, useState } from 'react';
import {
  Autocomplete,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Divider,
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
} from '@mui/material';
import Alert from '@mui/material/Alert';
import DownloadRoundedIcon from '@mui/icons-material/DownloadRounded';
import PlayArrowRoundedIcon from '@mui/icons-material/PlayArrowRounded';
import ContentCopyRoundedIcon from '@mui/icons-material/ContentCopyRounded';
import LockOutlinedIcon from '@mui/icons-material/LockOutlined';
import { useFeatures } from '@/lib/features';
import {
  APTListItem,
  SavedView,
  SectorProfileSummary,
  SigmaBackend,
  SigmaConvertResponse,
  convertSigma,
  deleteSavedView,
  downloadReport,
  listAPTPaginated,
  listSavedViews,
  listSectorProfiles,
  saveView,
} from '@/lib/api';

type Kind = 'full' | 'sector' | 'apt';

const BACKEND_LABEL: Record<SigmaBackend, string> = {
  splunk: 'Splunk SPL',
  elastic: 'Elastic Lucene',
  sentinel: 'Microsoft Sentinel (KQL)',
};

export default function ReportsPage() {
  const { isEnabled } = useFeatures();
  const canExport = isEnabled('bulk_export');
  const [kind, setKind] = useState<Kind>('full');
  const [ref, setRef] = useState<string>('');
  const [sectors, setSectors] = useState<SectorProfileSummary[]>([]);
  const [groups, setGroups] = useState<APTListItem[]>([]);
  const [groupQuery, setGroupQuery] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  // Sigma converter state.
  const [backend, setBackend] = useState<SigmaBackend>('splunk');
  const [converting, setConverting] = useState(false);
  const [convertResult, setConvertResult] = useState<SigmaConvertResponse | null>(null);

  // Export presets (reuse the saved_views table, namespaced kind='reports').
  const [presets, setPresets] = useState<SavedView[]>([]);
  const [presetName, setPresetName] = useState('');

  const loadPresets = () =>
    listSavedViews('reports').then(setPresets).catch(() => setPresets([]));

  useEffect(() => {
    listSectorProfiles().then(setSectors).catch(() => {});
    loadPresets();
  }, []);

  async function savePreset() {
    const name = presetName.trim();
    if (!name) return;
    await saveView({ kind: 'reports', name, payload: { kind, ref, backend } });
    setPresetName('');
    loadPresets();
  }

  function applyPreset(v: SavedView) {
    const p = v.payload as { kind?: Kind; ref?: string; backend?: SigmaBackend };
    if (p.kind) setKind(p.kind);
    setRef(p.ref ?? '');
    if (p.backend) setBackend(p.backend);
  }

  async function removePreset(id: string) {
    await deleteSavedView(id);
    loadPresets();
  }

  useEffect(() => {
    if (kind !== 'apt') return;
    const handle = setTimeout(() => {
      listAPTPaginated(groupQuery || undefined, 1, 30)
        .then((r) => setGroups(r.items))
        .catch(() => {});
    }, 200);
    return () => clearTimeout(handle);
  }, [kind, groupQuery]);

  function reportPath(extension: string): string {
    const parts: string[] = [];
    parts.push(`denominator=${kind}`);
    if (kind !== 'full' && ref) parts.push(`ref=${encodeURIComponent(ref)}`);
    return `/reports/${extension}?${parts.join('&')}`;
  }

  async function download(extension: string, filename: string) {
    setBusy(extension);
    setErr(null);
    try {
      await downloadReport(reportPath(extension), filename);
    } catch (e: any) {
      setErr(
        e?.response?.data?.detail ??
          'download failed — pick a customer in the topbar if you are an MSSP user.',
      );
    } finally {
      setBusy(null);
    }
  }

  async function runConvert(sampleOnly: boolean) {
    setConverting(true);
    setErr(null);
    setConvertResult(null);
    try {
      // For "sample", restrict to the first 5 detections by fetching IDs from /detections.
      let ids: string[] | undefined;
      if (sampleOnly) {
        const { listDetections } = await import('@/lib/api');
        const r = await listDetections({ page: 1, page_size: 5 });
        ids = r.items.map((i) => i.id);
      }
      const res = await convertSigma(backend, ids);
      setConvertResult(res);
    } catch (e: any) {
      setErr(
        e?.response?.data?.detail ??
          'conversion failed — pick a customer in the topbar if you are an MSSP user.',
      );
    } finally {
      setConverting(false);
    }
  }

  function refLabel(): string {
    if (kind === 'full') return 'Full ATT&CK';
    if (kind === 'sector') return `sector-${ref || 'unset'}`;
    return `apt-${ref || 'unset'}`;
  }

  const denominatorReady = kind === 'full' || !!ref;

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      <Box>
        <Typography variant="h4" sx={{ fontWeight: 700, letterSpacing: '-0.02em' }}>
          Reports & exports
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Coverage data in JSON, CSV, XLSX, ATT&amp;CK Navigator JSON, branded
          PDF. Sigma rule pack + Splunk/Elastic/Sentinel conversion.
        </Typography>
      </Box>

      {!canExport && (
        <Alert severity="info" icon={<LockOutlinedIcon />}>
          Bulk exports are disabled for this customer. Ask an MSSP
          administrator to re-enable them on the customer's feature
          settings.
        </Alert>
      )}

      {/* Denominator selector — shared across all exports */}
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
                setKind(e.target.value as Kind);
                setRef('');
              }}
              sx={{ minWidth: 220 }}
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
            <Box sx={{ flex: 1 }} />
            <Chip
              label={refLabel()}
              color={denominatorReady ? 'primary' : 'default'}
              variant="outlined"
            />
          </Stack>

          <Divider sx={{ my: 2 }} />
          <Stack direction={{ xs: 'column', md: 'row' }} spacing={1.5} alignItems={{ md: 'center' }} flexWrap="wrap" useFlexGap>
            <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600 }}>
              Presets:
            </Typography>
            {presets.length === 0 && (
              <Typography variant="caption" color="text.secondary">none saved</Typography>
            )}
            {presets.map((p) => (
              <Chip
                key={p.id}
                label={p.name}
                size="small"
                onClick={() => applyPreset(p)}
                onDelete={() => removePreset(p.id)}
                variant="outlined"
              />
            ))}
            <Box sx={{ flex: 1 }} />
            <TextField
              size="small"
              label="Save current as…"
              value={presetName}
              onChange={(e) => setPresetName(e.target.value)}
              sx={{ minWidth: 200 }}
            />
            <Button size="small" variant="outlined" onClick={savePreset} disabled={!presetName.trim()}>
              Save preset
            </Button>
          </Stack>
        </CardContent>
      </Card>

      {err && (
        <Card>
          <CardContent>
            <Typography color="error">{err}</Typography>
          </CardContent>
        </Card>
      )}

      {/* Coverage downloads */}
      <Card>
        <CardContent>
          <Typography
            variant="overline"
            sx={{ fontWeight: 700, color: 'text.secondary' }}
          >
            Coverage exports
          </Typography>
          <Stack
            direction={{ xs: 'column', md: 'row' }}
            spacing={1.5}
            sx={{ mt: 2 }}
            flexWrap="wrap"
            useFlexGap
          >
            <DownloadButton
              label="CSV"
              busy={busy === 'coverage.csv'}
              disabled={!denominatorReady || !canExport}
              onClick={() => download('coverage.csv', `coverage-${refLabel()}.csv`)}
            />
            <DownloadButton
              label="XLSX"
              busy={busy === 'coverage.xlsx'}
              disabled={!denominatorReady || !canExport}
              onClick={() => download('coverage.xlsx', `coverage-${refLabel()}.xlsx`)}
            />
            <DownloadButton
              label="ATT&CK Navigator JSON"
              busy={busy === 'coverage.navigator.json'}
              disabled={!denominatorReady || !canExport}
              onClick={() =>
                download(
                  'coverage.navigator.json',
                  `coverage-${refLabel()}.navigator.json`,
                )
              }
            />
            <DownloadButton
              label="Executive PDF"
              busy={busy === 'coverage.pdf'}
              disabled={!denominatorReady || !canExport}
              onClick={() => download('coverage.pdf', `coverage-${refLabel()}.pdf`)}
            />
          </Stack>
          {!denominatorReady && canExport && (
            <Typography
              variant="caption"
              color="text.secondary"
              sx={{ display: 'block', mt: 1 }}
            >
              Pick a {kind === 'sector' ? 'sector' : 'group'} above to enable
              downloads.
            </Typography>
          )}
        </CardContent>
      </Card>

      {/* Sigma rule pack */}
      <Card>
        <CardContent>
          <Typography
            variant="overline"
            sx={{ fontWeight: 700, color: 'text.secondary' }}
          >
            Sigma rule pack
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            ZIP of every Sigma rule in this customer's catalog, grouped by
            source folder, plus a MANIFEST.csv index.
          </Typography>
          <DownloadButton
            label="sigma-bundle.zip"
            busy={busy === 'sigma-bundle.zip'}
            disabled={!canExport}
            onClick={() =>
              download('sigma-bundle.zip', `sigma-bundle.zip`)
            }
          />
        </CardContent>
      </Card>

      <Divider sx={{ my: 1 }} />

      {/* Sigma → SIEM conversion */}
      <Card>
        <CardContent>
          <Typography
            variant="overline"
            sx={{ fontWeight: 700, color: 'text.secondary' }}
          >
            pySigma conversion
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Convert Sigma YAML to your SIEM's query language. "Sample" runs on
            the first 5 rules so you can preview; "All" converts everything for
            this customer.
          </Typography>
          <Stack direction={{ xs: 'column', md: 'row' }} spacing={1.5} alignItems={{ md: 'center' }}>
            <TextField
              select
              size="small"
              label="Backend"
              value={backend}
              onChange={(e) => setBackend(e.target.value as SigmaBackend)}
              sx={{ minWidth: 240 }}
            >
              {Object.entries(BACKEND_LABEL).map(([k, v]) => (
                <MenuItem key={k} value={k}>
                  {v}
                </MenuItem>
              ))}
            </TextField>
            <Button
              variant="outlined"
              startIcon={converting ? <CircularProgress size={14} /> : <PlayArrowRoundedIcon />}
              disabled={converting || !canExport}
              onClick={() => runConvert(true)}
            >
              Sample (5)
            </Button>
            <Button
              variant="contained"
              startIcon={converting ? <CircularProgress size={14} /> : <PlayArrowRoundedIcon />}
              disabled={converting || !canExport}
              onClick={() => runConvert(false)}
            >
              Convert all
            </Button>
            {convertResult && (
              <Chip
                label={`${convertResult.converted} / ${convertResult.total} converted · ${convertResult.failed} failed`}
                color={convertResult.failed ? 'warning' : 'success'}
                size="small"
              />
            )}
          </Stack>

          {convertResult && convertResult.results.length > 0 && (
            <Paper variant="outlined" sx={{ overflow: 'hidden', mt: 2 }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ width: 220 }}>Detection</TableCell>
                    <TableCell>Query ({BACKEND_LABEL[backend]})</TableCell>
                    <TableCell sx={{ width: 60 }}></TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {convertResult.results.map((r) => (
                    <TableRow key={r.detection_id} hover>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontWeight: 500 }}>
                          {r.title}
                        </Typography>
                        <Typography
                          variant="caption"
                          color="text.secondary"
                          sx={{ fontFamily: 'JetBrains Mono, monospace' }}
                        >
                          {r.sigma_id.slice(0, 8)}…
                        </Typography>
                      </TableCell>
                      <TableCell>
                        {r.error ? (
                          <Typography variant="caption" color="error">
                            {r.error}
                          </Typography>
                        ) : (
                          <Box
                            component="pre"
                            sx={{
                              m: 0,
                              fontFamily: 'JetBrains Mono, monospace',
                              fontSize: '0.75rem',
                              whiteSpace: 'pre-wrap',
                              wordBreak: 'break-all',
                            }}
                          >
                            {r.queries.join('\n\n')}
                          </Box>
                        )}
                      </TableCell>
                      <TableCell>
                        {r.queries.length > 0 && (
                          <IconButton
                            size="small"
                            onClick={() => navigator.clipboard.writeText(r.queries.join('\n'))}
                            title="Copy"
                          >
                            <ContentCopyRoundedIcon fontSize="small" />
                          </IconButton>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Paper>
          )}
        </CardContent>
      </Card>
    </Box>
  );
}

function DownloadButton({
  label,
  busy,
  disabled,
  onClick,
}: {
  label: string;
  busy: boolean;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <Button
      variant="outlined"
      startIcon={busy ? <CircularProgress size={14} /> : <DownloadRoundedIcon />}
      disabled={busy || disabled}
      onClick={onClick}
    >
      {label}
    </Button>
  );
}
