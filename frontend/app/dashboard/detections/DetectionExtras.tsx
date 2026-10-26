'use client';

import { useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Chip,
  Divider,
  IconButton,
  LinearProgress,
  Link as MuiLink,
  MenuItem,
  Paper,
  Stack,
  TextField,
  Tooltip,
  Typography,
  alpha,
} from '@mui/material';
import OpenInNewRoundedIcon from '@mui/icons-material/OpenInNewRounded';
import AutoAwesomeRoundedIcon from '@mui/icons-material/AutoAwesomeRounded';
import PlayArrowRoundedIcon from '@mui/icons-material/PlayArrowRounded';
import {
  AIDraftResult,
  DetectionEffectiveness,
  DetectionOutcomeRow,
  DetectionSample,
  PromotionSuggestion,
  OutcomeKind,
  aiDraftDetection,
  createDetection,
  createDetectionOutcome,
  deleteDetectionOutcome,
  deleteDetectionSample,
  getDetectionEffectiveness,
  listDetectionOutcomes,
  listDetectionSamples,
  listRulePromotions,
  promoteSuggestion,
  runDetectionSamples,
  upsertDetectionSample,
} from '@/lib/api';
import { FeatureGate } from '@/lib/features';
import Link from 'next/link';

// ----- cross-customer suggestions strip ---------------------------------

export function SuggestionsStrip() {
  const [items, setItems] = useState<PromotionSuggestion[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  useEffect(() => {
    listRulePromotions()
      .then(setItems)
      .catch(() => setItems([]))
      .finally(() => setLoading(false));
  }, []);

  async function doImport(s: PromotionSuggestion) {
    setBusy(s.detection_id);
    setMsg(null);
    try {
      const res = await promoteSuggestion(
        s.source_customer_codename,
        s.detection_id,
      );
      setItems((prev) => prev.filter((p) => p.detection_id !== s.detection_id));
      setMsg(`Imported "${res.title}" — review it in the detection library before deploying.`);
    } catch (e: any) {
      setMsg(e?.response?.data?.detail ?? 'import failed');
    } finally {
      setBusy(null);
    }
  }

  if (loading || items.length === 0) return null;

  return (
    <Paper
      variant="outlined"
      sx={(t) => ({
        p: 2,
        borderRadius: 3,
        borderColor: alpha(t.palette.primary.main, 0.35),
        bgcolor: alpha(t.palette.primary.main, 0.04),
      })}
    >
      <Stack direction="row" alignItems="center" spacing={1} mb={1.5}>
        <Typography variant="subtitle2" sx={{ fontWeight: 700, flex: 1 }}>
          Promote rules from sibling tenants
        </Typography>
        <Typography variant="caption" color="text.secondary">
          {items.length} suggestion{items.length === 1 ? '' : 's'}
        </Typography>
      </Stack>
      {msg && (
        <Alert severity="info" variant="outlined" sx={{ mb: 1.5, borderRadius: 2 }}>
          {msg}
        </Alert>
      )}
      <Stack
        direction="row"
        spacing={1}
        sx={{ overflowX: 'auto', pb: 1 }}
      >
        {items.slice(0, 12).map((s) => (
          <Paper
            key={s.detection_id}
            variant="outlined"
            sx={{ p: 1.5, minWidth: 280, flexShrink: 0 }}
          >
            <Stack direction="row" alignItems="baseline" spacing={1} mb={0.5}>
              <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'JetBrains Mono, monospace' }}>
                {s.source_customer_codename}
              </Typography>
              {s.same_sector && (
                <Chip
                  size="small"
                  label="same sector"
                  color="primary"
                  variant="outlined"
                  sx={{ height: 18, fontSize: '0.6rem' }}
                />
              )}
              <Chip
                size="small"
                label={s.detection_status}
                sx={{ height: 18, fontSize: '0.6rem' }}
                variant="outlined"
              />
            </Stack>
            <Typography
              variant="body2"
              sx={{
                fontWeight: 600,
                overflow: 'hidden',
                display: '-webkit-box',
                WebkitLineClamp: 2,
                WebkitBoxOrient: 'vertical',
                mb: 0.5,
              }}
            >
              {s.title}
            </Typography>
            <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap mb={1}>
              {s.techniques.slice(0, 4).map((t) => (
                <Chip
                  key={t}
                  label={t}
                  size="small"
                  sx={{ fontFamily: 'JetBrains Mono, monospace', height: 18, fontSize: '0.6rem' }}
                />
              ))}
              {s.techniques.length > 4 && (
                <Typography variant="caption" color="text.secondary">
                  +{s.techniques.length - 4}
                </Typography>
              )}
            </Stack>
            <Button
              size="small"
              variant="outlined"
              onClick={() => doImport(s)}
              disabled={busy === s.detection_id}
            >
              {busy === s.detection_id ? 'Importing…' : 'Import to this tenant'}
            </Button>
          </Paper>
        ))}
      </Stack>
    </Paper>
  );
}

// ----- detection effectiveness + unit tests + AI mockup -----------------

export function DetectionDrawerExtras({ detectionId }: { detectionId: string }) {
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      <EffectivenessPanel detectionId={detectionId} />
      <Divider />
      <UnitTestsPanel detectionId={detectionId} />
      <FeatureGate feature="ai_authoring">
        <Divider />
        <AiAuthorPanel detectionId={detectionId} />
      </FeatureGate>
    </Box>
  );
}

function EffectivenessPanel({ detectionId }: { detectionId: string }) {
  const [summary, setSummary] = useState<DetectionEffectiveness | null>(null);
  const [rows, setRows] = useState<DetectionOutcomeRow[]>([]);
  const [kind, setKind] = useState<OutcomeKind>('tp');
  const [text, setText] = useState('');
  const [saving, setSaving] = useState(false);

  function refresh() {
    listDetectionOutcomes(detectionId).then(setRows).catch(() => setRows([]));
    getDetectionEffectiveness(detectionId).then(setSummary).catch(() => setSummary(null));
  }

  useEffect(() => {
    refresh();
  }, [detectionId]);

  async function add() {
    setSaving(true);
    try {
      await createDetectionOutcome(detectionId, { kind, summary: text || undefined });
      setText('');
      refresh();
    } finally {
      setSaving(false);
    }
  }

  async function remove(id: string) {
    await deleteDetectionOutcome(id);
    refresh();
  }

  const precisionPct = summary ? Math.round(summary.precision * 100) : 0;

  return (
    <Box>
      <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
        Effectiveness loop
      </Typography>
      {summary && (
        <Stack direction="row" spacing={2} alignItems="center" mb={1.5}>
          <Box sx={{ flex: 1 }}>
            <Typography variant="caption" color="text.secondary">
              Precision (TP / decided)
            </Typography>
            <Typography variant="h5" sx={{ fontWeight: 800 }}>
              {summary.total === 0 ? '—' : `${precisionPct}%`}
            </Typography>
            <LinearProgress
              variant="determinate"
              value={precisionPct}
              sx={{ mt: 0.5, height: 6, borderRadius: 3 }}
            />
          </Box>
          <Stack spacing={0.5}>
            <Chip size="small" label={`${summary.tp} TP`} color="success" variant="outlined" />
            <Chip size="small" label={`${summary.fp} FP`} color="error" variant="outlined" />
            <Chip size="small" label={`${summary.unsure} ?`} variant="outlined" />
          </Stack>
        </Stack>
      )}
      <Stack direction="row" spacing={1} mb={1}>
        <TextField
          select
          size="small"
          value={kind}
          onChange={(e) => setKind(e.target.value as OutcomeKind)}
          sx={{ minWidth: 130 }}
        >
          <MenuItem value="tp">True positive</MenuItem>
          <MenuItem value="fp">False positive</MenuItem>
          <MenuItem value="unsure">Inconclusive</MenuItem>
        </TextField>
        <TextField
          size="small"
          placeholder="What happened? (optional)"
          value={text}
          onChange={(e) => setText(e.target.value)}
          sx={{ flex: 1 }}
        />
        <Button size="small" variant="contained" onClick={add} disabled={saving}>
          Log
        </Button>
      </Stack>
      <Stack spacing={0.5} sx={{ maxHeight: 180, overflowY: 'auto' }}>
        {rows.map((r) => (
          <Stack
            key={r.id}
            direction="row"
            alignItems="baseline"
            spacing={1}
            sx={(t) => ({ p: 1, border: `1px solid ${t.palette.divider}`, borderRadius: 1 })}
          >
            <Chip
              size="small"
              label={r.kind}
              color={r.kind === 'tp' ? 'success' : r.kind === 'fp' ? 'error' : 'default'}
              sx={{ height: 18, fontSize: '0.62rem', textTransform: 'uppercase' }}
            />
            <Box sx={{ flex: 1, minWidth: 0 }}>
              <Typography variant="caption" sx={{ display: 'block', fontWeight: 600 }}>
                {r.summary || '(no notes)'}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {r.author_email ? `${r.author_email} · ` : ''}
                {new Date(r.observed_at).toLocaleString()}
              </Typography>
            </Box>
            <Button size="small" onClick={() => remove(r.id)}>
              Delete
            </Button>
          </Stack>
        ))}
      </Stack>
    </Box>
  );
}

function UnitTestsPanel({ detectionId }: { detectionId: string }) {
  const [samples, setSamples] = useState<DetectionSample[]>([]);
  const [label, setLabel] = useState('');
  const [kind, setKind] = useState<'positive' | 'negative'>('positive');
  const [eventJson, setEventJson] = useState(
    JSON.stringify({ Image: 'powershell.exe', CommandLine: '-EncodedCommand …' }, null, 2),
  );
  const [running, setRunning] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  function refresh() {
    listDetectionSamples(detectionId).then(setSamples).catch(() => setSamples([]));
  }
  useEffect(() => {
    refresh();
  }, [detectionId]);

  async function addSample() {
    setErr(null);
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(eventJson);
      if (typeof parsed !== 'object' || parsed === null) throw new Error('event must be JSON object');
    } catch (e: any) {
      setErr(`invalid JSON: ${e.message}`);
      return;
    }
    try {
      await upsertDetectionSample(detectionId, {
        label: label || `${kind} sample`,
        kind,
        event: parsed,
      });
      setLabel('');
      refresh();
    } catch (e: any) {
      setErr(e?.response?.data?.detail ?? 'failed to save sample');
    }
  }

  async function runAll() {
    setRunning(true);
    try {
      await runDetectionSamples(detectionId);
      refresh();
    } finally {
      setRunning(false);
    }
  }

  async function remove(id: string) {
    await deleteDetectionSample(id);
    refresh();
  }

  return (
    <Box>
      <Stack direction="row" alignItems="center" spacing={1} mb={1}>
        <Typography variant="subtitle2" sx={{ fontWeight: 700, flex: 1 }}>
          Unit tests
        </Typography>
        <Button
          size="small"
          variant="outlined"
          startIcon={<PlayArrowRoundedIcon fontSize="small" />}
          onClick={runAll}
          disabled={samples.length === 0 || running}
        >
          Run all
        </Button>
      </Stack>
      <Stack spacing={1} sx={{ maxHeight: 220, overflowY: 'auto', mb: 1 }}>
        {samples.length === 0 && (
          <Typography variant="caption" color="text.secondary">
            No samples yet. Add a known-good or known-bad event below.
          </Typography>
        )}
        {samples.map((s) => (
          <Box
            key={s.id}
            sx={(t) => ({ p: 1, border: `1px solid ${t.palette.divider}`, borderRadius: 1 })}
          >
            <Stack direction="row" alignItems="center" spacing={1}>
              <Chip
                size="small"
                label={s.kind}
                color={s.kind === 'positive' ? 'success' : 'default'}
                sx={{ height: 18, fontSize: '0.6rem', textTransform: 'uppercase' }}
              />
              <Typography variant="body2" sx={{ flex: 1, fontWeight: 600 }}>
                {s.label}
              </Typography>
              {s.last_run_pass === true && (
                <Chip size="small" label="PASS" color="success" sx={{ height: 18 }} />
              )}
              {s.last_run_pass === false && (
                <Chip size="small" label="FAIL" color="error" sx={{ height: 18 }} />
              )}
              {s.last_run_pass === null && s.last_run_at && (
                <Chip size="small" label="?" sx={{ height: 18 }} />
              )}
              <Button size="small" onClick={() => remove(s.id)}>
                Delete
              </Button>
            </Stack>
            {s.last_run_message && (
              <Typography
                variant="caption"
                color="text.secondary"
                sx={{ display: 'block', fontFamily: 'JetBrains Mono, monospace', mt: 0.5 }}
              >
                {s.last_run_message}
              </Typography>
            )}
          </Box>
        ))}
      </Stack>
      <Stack spacing={1}>
        <Stack direction="row" spacing={1}>
          <TextField
            select
            size="small"
            value={kind}
            onChange={(e) => setKind(e.target.value as 'positive' | 'negative')}
            sx={{ minWidth: 130 }}
          >
            <MenuItem value="positive">Positive (should match)</MenuItem>
            <MenuItem value="negative">Negative (should NOT match)</MenuItem>
          </TextField>
          <TextField
            size="small"
            placeholder="Sample label"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            sx={{ flex: 1 }}
          />
        </Stack>
        <TextField
          size="small"
          label="Event JSON"
          multiline
          minRows={3}
          value={eventJson}
          onChange={(e) => setEventJson(e.target.value)}
          sx={{ fontFamily: 'JetBrains Mono, monospace' }}
        />
        {err && (
          <Alert severity="error" sx={{ py: 0 }}>
            {err}
          </Alert>
        )}
        <Stack direction="row" justifyContent="flex-end">
          <Button size="small" variant="contained" onClick={addSample}>
            Add sample
          </Button>
        </Stack>
      </Stack>
    </Box>
  );
}

function AiAuthorPanel({ detectionId }: { detectionId: string }) {
  const [intent, setIntent] = useState('');
  const [techniques, setTechniques] = useState('');
  const [product, setProduct] = useState('windows');
  const [category, setCategory] = useState('process_creation');
  const [service, setService] = useState('');
  const [severity, setSeverity] = useState('medium');
  const [fpNotes, setFpNotes] = useState('');
  const [refs, setRefs] = useState('');
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
        techniques: techniques
          .split(/[,\s]+/)
          .map((t) => t.trim())
          .filter(Boolean),
        log_source_product: product || null,
        log_source_category: category || null,
        log_source_service: service || null,
        severity,
        fp_notes: fpNotes,
        reference_urls: refs
          .split(/\s+/)
          .map((u) => u.trim())
          .filter(Boolean),
      });
      setResult(r);
    } catch (e: any) {
      const detail = e?.response?.data?.detail;
      if (typeof detail === 'string') {
        setError(detail);
        if (detail.toLowerCase().includes('not configured')) {
          setNeedsConfig(true);
        }
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

  async function saveDraft() {
    if (!result) return;
    setBusy(true);
    setError(null);
    try {
      const saved = await createDetection({
        raw_yaml: result.yaml,
        detection_status: 'idea',
      });
      setSavedId(saved.id);
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'save failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Box>
      <Stack direction="row" alignItems="center" spacing={1} mb={1}>
        <AutoAwesomeRoundedIcon fontSize="small" color="primary" />
        <Typography variant="subtitle2" sx={{ fontWeight: 700, flex: 1 }}>
          AI-assisted authoring
        </Typography>
        <Chip
          size="small"
          label="anthropic"
          variant="outlined"
          sx={{ height: 20, fontSize: '0.6rem', fontWeight: 700 }}
        />
      </Stack>
      <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1.5 }}>
        Drafts a sibling Sigma rule from a structured brief. Output is
        validated by pySigma before showing — invalid drafts auto-retry
        up to twice. Configure the API key under{' '}
        <MuiLink component={Link} href="/dashboard/settings?tab=ai" underline="hover">
          Settings → AI authoring
        </MuiLink>
        .
      </Typography>
      <Stack spacing={1.5}>
        <TextField
          size="small"
          label="What should the rule catch?"
          multiline
          minRows={2}
          value={intent}
          onChange={(e) => setIntent(e.target.value)}
          placeholder="e.g. lateral movement via WMI from a non-admin host"
        />
        <Stack direction="row" spacing={1}>
          <TextField
            size="small"
            label="ATT&CK techniques (space- or comma-separated)"
            value={techniques}
            onChange={(e) => setTechniques(e.target.value)}
            placeholder="T1047 T1021.006"
            sx={{ flex: 1, fontFamily: 'JetBrains Mono, monospace' }}
          />
          <TextField
            select
            size="small"
            label="Severity"
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            sx={{ minWidth: 130 }}
          >
            <MenuItem value="informational">Informational</MenuItem>
            <MenuItem value="low">Low</MenuItem>
            <MenuItem value="medium">Medium</MenuItem>
            <MenuItem value="high">High</MenuItem>
            <MenuItem value="critical">Critical</MenuItem>
          </TextField>
        </Stack>
        <Stack direction="row" spacing={1}>
          <TextField
            size="small"
            label="logsource.product"
            value={product}
            onChange={(e) => setProduct(e.target.value)}
            sx={{ flex: 1 }}
          />
          <TextField
            size="small"
            label="logsource.category"
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            sx={{ flex: 1 }}
          />
          <TextField
            size="small"
            label="logsource.service"
            value={service}
            onChange={(e) => setService(e.target.value)}
            sx={{ flex: 1 }}
            placeholder="optional"
          />
        </Stack>
        <TextField
          size="small"
          label="Known false-positive considerations"
          multiline
          minRows={2}
          value={fpNotes}
          onChange={(e) => setFpNotes(e.target.value)}
        />
        <TextField
          size="small"
          label="Reference URLs (whitespace-separated)"
          value={refs}
          onChange={(e) => setRefs(e.target.value)}
          placeholder="https://… https://…"
        />
        <Box>
          <Button
            variant="contained"
            startIcon={<AutoAwesomeRoundedIcon />}
            onClick={draft}
            disabled={busy || (!intent.trim() && !techniques.trim())}
          >
            {busy ? 'Drafting…' : 'Draft with AI'}
          </Button>
        </Box>
      </Stack>

      {error && (
        <Alert
          severity={needsConfig ? 'warning' : 'error'}
          sx={{ mt: 2 }}
          action={
            needsConfig ? (
              <Button
                component={Link}
                href="/dashboard/settings?tab=ai"
                size="small"
              >
                Configure
              </Button>
            ) : undefined
          }
        >
          <Typography variant="body2">{error}</Typography>
          {errorDetails.length > 0 && (
            <Box component="ul" sx={{ pl: 2, mt: 0.5 }}>
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
        <Box sx={{ mt: 2 }}>
          <Stack direction="row" alignItems="center" spacing={1} mb={0.5}>
            <Typography variant="caption" color="text.secondary">
              Generated in {result.attempts} attempt{result.attempts === 1 ? '' : 's'}
            </Typography>
            {result.warnings.length > 0 && (
              <Tooltip title={result.warnings.join('\n')}>
                <Chip
                  size="small"
                  label={`${result.warnings.length} retry note(s)`}
                  variant="outlined"
                  sx={{ height: 18, fontSize: '0.6rem' }}
                />
              </Tooltip>
            )}
          </Stack>
          <Paper
            variant="outlined"
            sx={(t) => ({
              p: 1.5,
              bgcolor: alpha(t.palette.primary.main, 0.05),
              fontFamily: 'JetBrains Mono, monospace',
              fontSize: '0.72rem',
              whiteSpace: 'pre-wrap',
              maxHeight: 360,
              overflowY: 'auto',
            })}
          >
            {result.yaml}
          </Paper>
          <Stack direction="row" spacing={1} mt={1.5}>
            <Button
              size="small"
              variant="contained"
              onClick={saveDraft}
              disabled={busy || !!savedId}
            >
              {savedId ? 'Saved as new detection' : 'Save as new detection'}
            </Button>
            <Button
              size="small"
              variant="outlined"
              onClick={() => navigator.clipboard.writeText(result.yaml)}
            >
              Copy YAML
            </Button>
            {savedId && (
              <Typography variant="caption" color="text.secondary" sx={{ alignSelf: 'center' }}>
                Saved — open it in the detection library.
              </Typography>
            )}
          </Stack>
        </Box>
      )}
    </Box>
  );
}
