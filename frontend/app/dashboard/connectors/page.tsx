'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Divider,
  Drawer,
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
  Tooltip,
  Typography,
} from '@mui/material';
import AddRoundedIcon from '@mui/icons-material/AddRounded';
import CloseRoundedIcon from '@mui/icons-material/CloseRounded';
import CloudSyncRoundedIcon from '@mui/icons-material/CloudSyncRounded';
import DeleteOutlineRoundedIcon from '@mui/icons-material/DeleteOutlineRounded';
import LockOutlinedIcon from '@mui/icons-material/LockOutlined';
import PlayArrowRoundedIcon from '@mui/icons-material/PlayArrowRounded';
import SaveRoundedIcon from '@mui/icons-material/SaveRounded';
import UploadFileRoundedIcon from '@mui/icons-material/UploadFileRounded';
import {
  ConnectorKind,
  ConnectorOut,
  DeployedUseCase,
  UseCaseImportSummary,
  createConnector,
  deleteConnector,
  deleteUseCase,
  importUseCasesCsv,
  listConnectors,
  listUseCases,
  patchConnector,
  syncUseCases,
  testConnector,
} from '@/lib/api';
import { useFeatures } from '@/lib/features';

const KIND_LABEL: Record<ConnectorKind, string> = {
  splunk: 'Splunk',
  sentinel: 'Microsoft Sentinel',
  elastic: 'Elastic',
  logrhythm: 'LogRhythm',
};

// Field schema per kind. `secret: true` flags Fernet-encrypted fields.
type FieldSpec = { name: string; label: string; secret?: boolean; placeholder?: string };

const KIND_FIELDS: Record<ConnectorKind, FieldSpec[]> = {
  splunk: [
    { name: 'host', label: 'Host', placeholder: 'splunk.example.com' },
    { name: 'port', label: 'Port', placeholder: '8088' },
    { name: 'index', label: 'Index' },
    { name: 'hec_token', label: 'HEC token', secret: true },
  ],
  sentinel: [
    { name: 'workspace_id', label: 'Workspace ID' },
    { name: 'tenant_id', label: 'Azure tenant ID' },
    { name: 'client_id', label: 'Client (App) ID' },
    { name: 'workspace_key', label: 'Workspace key', secret: true },
    { name: 'client_secret', label: 'Client secret', secret: true },
  ],
  elastic: [
    { name: 'host', label: 'Host URL', placeholder: 'https://es.example.com:9200' },
    { name: 'username', label: 'Username' },
    { name: 'api_key', label: 'API key', secret: true },
    { name: 'password', label: 'Password (if no API key)', secret: true },
  ],
  logrhythm: [
    { name: 'host', label: 'API URL', placeholder: 'https://platform-manager:8501' },
    { name: 'api_token', label: 'API token', secret: true },
  ],
};

export default function ConnectorsPage() {
  const [items, setItems] = useState<ConnectorOut[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<ConnectorOut | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const rows = await listConnectors();
      setItems(rows);
    } catch (e: any) {
      setError(
        e?.response?.data?.detail ??
          'failed to load — pick a customer in the topbar if you are an MSSP user.',
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      <Stack direction="row" alignItems="flex-end" spacing={2}>
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 700, letterSpacing: '-0.02em' }}>
            Connectors
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Splunk / Sentinel / Elastic configuration. Credentials are
            Fernet-encrypted at rest. Open a connector to test the connection
            and import the use-cases deployed in its SIEM — live via the API
            or from an uploaded CSV export.
          </Typography>
        </Box>
        <Box sx={{ flex: 1 }} />
        <Button
          variant="contained"
          startIcon={<AddRoundedIcon />}
          onClick={() => {
            setEditing(null);
            setOpen(true);
          }}
        >
          Add connector
        </Button>
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

      {!loading && items.length === 0 && !error && (
        <Card>
          <CardContent>
            <Typography color="text.secondary">
              No connectors configured yet. Add one to start.
            </Typography>
          </CardContent>
        </Card>
      )}

      {!loading && items.length > 0 && (
        <Paper variant="outlined" sx={{ overflow: 'hidden' }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell sx={{ width: 140 }}>Kind</TableCell>
                <TableCell>Label</TableCell>
                <TableCell sx={{ width: 200 }}>Secrets</TableCell>
                <TableCell sx={{ width: 110 }}>Status</TableCell>
                <TableCell sx={{ width: 180 }}>Last tested</TableCell>
                <TableCell sx={{ width: 70 }}></TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {items.map((c) => (
                <TableRow
                  key={c.id}
                  hover
                  onClick={() => {
                    setEditing(c);
                    setOpen(true);
                  }}
                  sx={{ cursor: 'pointer' }}
                >
                  <TableCell>
                    <Chip label={KIND_LABEL[c.kind] ?? c.kind} size="small" />
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontWeight: 500 }}>
                      {c.label}
                    </Typography>
                    {c.description && (
                      <Typography variant="caption" color="text.secondary">
                        {c.description}
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell>
                    <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                      {Object.entries(c.secret_fields).map(([k, v]) => (
                        <Tooltip key={k} title={`${k}: ${v}`} arrow>
                          <Chip
                            icon={<LockOutlinedIcon style={{ fontSize: 14 }} />}
                            label={k}
                            size="small"
                            variant="outlined"
                            sx={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.7rem' }}
                          />
                        </Tooltip>
                      ))}
                    </Stack>
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={c.status}
                      size="small"
                      color={c.status === 'connected' ? 'success' : 'default'}
                      variant="outlined"
                    />
                  </TableCell>
                  <TableCell>
                    {c.last_test_at ? (
                      <Typography variant="caption" color="text.secondary">
                        {new Date(c.last_test_at).toLocaleString()}
                      </Typography>
                    ) : (
                      <Typography variant="caption" color="text.secondary">
                        never
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell>
                    <IconButton
                      size="small"
                      color="error"
                      onClick={async (e) => {
                        e.stopPropagation();
                        if (confirm(`Delete ${c.label}?`)) {
                          await deleteConnector(c.id);
                          reload();
                        }
                      }}
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

      <ConnectorEditor
        open={open}
        existing={editing}
        onClose={() => setOpen(false)}
        onSaved={() => {
          setOpen(false);
          reload();
        }}
      />
    </Box>
  );
}

function ConnectorEditor({
  open,
  existing,
  onClose,
  onSaved,
}: {
  open: boolean;
  existing: ConnectorOut | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { isEnabled } = useFeatures();
  const canTest = isEnabled('connector_tests');
  const [kind, setKind] = useState<ConnectorKind>('splunk');
  const [label, setLabel] = useState('');
  const [description, setDescription] = useState('');
  const [values, setValues] = useState<Record<string, string>>({});
  const [submitting, setSubmitting] = useState(false);
  const [testing, setTesting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<string | null>(null);

  useEffect(() => {
    if (existing) {
      setKind(existing.kind);
      setLabel(existing.label);
      setDescription(existing.description ?? '');
      const v: Record<string, string> = {};
      for (const [k, val] of Object.entries(existing.config)) {
        v[k] = String(val ?? '');
      }
      setValues(v);
      setError(null);
      setTestResult(null);
    } else {
      setKind('splunk');
      setLabel('');
      setDescription('');
      setValues({});
      setError(null);
      setTestResult(null);
    }
  }, [existing, open]);

  const fields = KIND_FIELDS[kind];
  const isEdit = !!existing;

  async function save() {
    setSubmitting(true);
    setError(null);
    try {
      // Only send non-empty fields. Secret fields kept empty by the user are
      // preserved on the backend (no rotation).
      const config: Record<string, unknown> = {};
      for (const f of fields) {
        const v = (values[f.name] ?? '').trim();
        if (v) config[f.name] = v;
      }
      if (existing) {
        await patchConnector(existing.id, {
          label,
          description: description || undefined,
          config,
        });
      } else {
        await createConnector({
          kind,
          label,
          description: description || undefined,
          config,
        });
      }
      onSaved();
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'save failed');
    } finally {
      setSubmitting(false);
    }
  }

  async function runTest() {
    if (!existing) return;
    setTesting(true);
    setTestResult(null);
    try {
      const r = await testConnector(existing.id);
      setTestResult(`${r.status} — ${r.message}`);
    } catch (e: any) {
      setTestResult(e?.response?.data?.detail ?? 'test failed');
    } finally {
      setTesting(false);
    }
  }

  return (
    <Drawer
      anchor="right"
      open={open}
      onClose={onClose}
      PaperProps={{ sx: { width: { xs: '100%', md: 520 } } }}
    >
      <Box sx={{ p: 3, display: 'flex', flexDirection: 'column', gap: 2 }}>
        <Stack direction="row" alignItems="center" spacing={1}>
          <Typography variant="h6" sx={{ fontWeight: 700, flex: 1 }}>
            {isEdit ? `Edit ${existing!.label}` : 'New connector'}
          </Typography>
          <IconButton onClick={onClose} size="small">
            <CloseRoundedIcon />
          </IconButton>
        </Stack>

        <TextField
          select
          size="small"
          label="Kind"
          value={kind}
          onChange={(e) => setKind(e.target.value as ConnectorKind)}
          disabled={isEdit}
        >
          {(Object.keys(KIND_LABEL) as ConnectorKind[]).map((k) => (
            <MenuItem key={k} value={k}>
              {KIND_LABEL[k]}
            </MenuItem>
          ))}
        </TextField>
        <TextField
          size="small"
          label="Label"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
        />
        <TextField
          size="small"
          label="Description (optional)"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />

        <Typography
          variant="overline"
          sx={{ fontWeight: 700, color: 'text.secondary' }}
        >
          Configuration
        </Typography>
        {fields.map((f) => (
          <TextField
            key={f.name}
            size="small"
            label={f.label}
            placeholder={
              f.secret && isEdit && existing?.secret_fields[f.name]
                ? `(unchanged · ${existing.secret_fields[f.name]})`
                : f.placeholder
            }
            type={f.secret ? 'password' : 'text'}
            value={values[f.name] ?? ''}
            onChange={(e) => setValues((v) => ({ ...v, [f.name]: e.target.value }))}
            helperText={f.secret ? 'Fernet-encrypted at rest' : undefined}
          />
        ))}

        {error && <Typography color="error">{error}</Typography>}

        <Stack direction="row" spacing={1.5}>
          <Button
            variant="contained"
            startIcon={submitting ? <CircularProgress size={14} /> : <SaveRoundedIcon />}
            onClick={save}
            disabled={submitting || !label.trim()}
          >
            {isEdit ? 'Save changes' : 'Create connector'}
          </Button>
          {isEdit && (
            <Tooltip
              title={
                canTest
                  ? ''
                  : 'Live connector tests are disabled for this customer.'
              }
              disableHoverListener={canTest}
            >
              <span>
                <Button
                  variant="outlined"
                  startIcon={testing ? <CircularProgress size={14} /> : <PlayArrowRoundedIcon />}
                  onClick={runTest}
                  disabled={testing || !canTest}
                >
                  Test connection
                </Button>
              </span>
            </Tooltip>
          )}
        </Stack>

        {testResult && (
          <Card variant="outlined">
            <CardContent>
              <Typography variant="caption" color="text.secondary">
                Test result
              </Typography>
              <Typography variant="body2" sx={{ mt: 0.5 }}>
                {testResult}
              </Typography>
            </CardContent>
          </Card>
        )}

        {isEdit && (
          <>
            <Divider sx={{ my: 1 }} />
            <UseCasesPanel connectorId={existing!.id} kindLabel={KIND_LABEL[kind] ?? kind} />
          </>
        )}
      </Box>
    </Drawer>
  );
}

function UseCasesPanel({
  connectorId,
  kindLabel,
}: {
  connectorId: string;
  kindLabel: string;
}) {
  const [items, setItems] = useState<DeployedUseCase[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<'sync' | 'csv' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [summary, setSummary] = useState<UseCaseImportSummary | null>(null);
  const fileInput = useRef<HTMLInputElement | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setItems(await listUseCases(connectorId));
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'failed to load use-cases');
    } finally {
      setLoading(false);
    }
  }, [connectorId]);

  useEffect(() => {
    reload();
  }, [reload]);

  async function runSync() {
    setBusy('sync');
    setError(null);
    setSummary(null);
    try {
      setSummary(await syncUseCases(connectorId));
      await reload();
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'sync failed');
    } finally {
      setBusy(null);
    }
  }

  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = ''; // allow re-selecting the same file
    if (!file) return;
    setBusy('csv');
    setError(null);
    setSummary(null);
    try {
      setSummary(await importUseCasesCsv(connectorId, file));
      await reload();
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'import failed');
    } finally {
      setBusy(null);
    }
  }

  async function remove(id: string) {
    await deleteUseCase(connectorId, id);
    reload();
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
      <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
        Deployed use-cases
      </Typography>
      <Typography variant="caption" color="text.secondary" sx={{ mt: -1 }}>
        The detection rules running in this {kindLabel} deployment. Fetch them
        live from the API, or upload a CSV export — ATT&CK technique IDs are
        parsed automatically from each rule.
      </Typography>

      <Stack direction="row" spacing={1.5}>
        <Button
          size="small"
          variant="outlined"
          startIcon={busy === 'sync' ? <CircularProgress size={14} /> : <CloudSyncRoundedIcon />}
          onClick={runSync}
          disabled={busy !== null}
        >
          Fetch from API
        </Button>
        <Button
          size="small"
          variant="outlined"
          startIcon={busy === 'csv' ? <CircularProgress size={14} /> : <UploadFileRoundedIcon />}
          onClick={() => fileInput.current?.click()}
          disabled={busy !== null}
        >
          Upload CSV
        </Button>
        <input
          ref={fileInput}
          type="file"
          accept=".csv,text/csv"
          hidden
          onChange={onFile}
        />
      </Stack>

      {summary && (
        <Alert severity="success" sx={{ py: 0.5 }}>
          Imported {summary.imported} use-case{summary.imported === 1 ? '' : 's'} (
          {summary.created} new, {summary.updated} updated) covering{' '}
          {summary.technique_count} technique{summary.technique_count === 1 ? '' : 's'} via{' '}
          {summary.source === 'api' ? 'API' : 'CSV'}.
        </Alert>
      )}
      {error && (
        <Alert severity="error" sx={{ py: 0.5 }}>
          {error}
        </Alert>
      )}

      {loading ? (
        <Box sx={{ py: 2, display: 'flex', justifyContent: 'center' }}>
          <CircularProgress size={20} />
        </Box>
      ) : items.length === 0 ? (
        <Typography variant="body2" color="text.secondary">
          None imported yet.
        </Typography>
      ) : (
        <Paper variant="outlined" sx={{ overflow: 'hidden' }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Use-case</TableCell>
                <TableCell sx={{ width: 90 }}>Severity</TableCell>
                <TableCell sx={{ width: 150 }}>Techniques</TableCell>
                <TableCell sx={{ width: 44 }}></TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {items.map((u) => (
                <TableRow key={u.id} hover>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontWeight: 500 }}>
                      {u.name}
                    </Typography>
                    <Stack direction="row" spacing={0.5} alignItems="center">
                      <Chip
                        label={u.import_source === 'api' ? 'API' : 'CSV'}
                        size="small"
                        variant="outlined"
                        sx={{ height: 16, fontSize: '0.6rem' }}
                      />
                      {!u.enabled && (
                        <Chip
                          label="disabled"
                          size="small"
                          variant="outlined"
                          color="warning"
                          sx={{ height: 16, fontSize: '0.6rem' }}
                        />
                      )}
                    </Stack>
                  </TableCell>
                  <TableCell>
                    <Typography variant="caption" color="text.secondary">
                      {u.severity ?? '—'}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    {u.technique_ids.length === 0 ? (
                      <Typography variant="caption" color="text.secondary">
                        none
                      </Typography>
                    ) : (
                      <Tooltip title={u.technique_ids.join(', ')} arrow>
                        <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                          {u.technique_ids.slice(0, 3).map((t) => (
                            <Chip
                              key={t}
                              label={t}
                              size="small"
                              sx={{
                                height: 18,
                                fontFamily: 'JetBrains Mono, monospace',
                                fontSize: '0.65rem',
                              }}
                            />
                          ))}
                          {u.technique_ids.length > 3 && (
                            <Chip
                              label={`+${u.technique_ids.length - 3}`}
                              size="small"
                              variant="outlined"
                              sx={{ height: 18, fontSize: '0.65rem' }}
                            />
                          )}
                        </Stack>
                      </Tooltip>
                    )}
                  </TableCell>
                  <TableCell>
                    <IconButton size="small" color="error" onClick={() => remove(u.id)}>
                      <DeleteOutlineRoundedIcon fontSize="small" />
                    </IconButton>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Paper>
      )}
    </Box>
  );
}
