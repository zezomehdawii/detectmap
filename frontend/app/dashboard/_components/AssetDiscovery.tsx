'use client';

import { useEffect, useRef, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Checkbox,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  MenuItem,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TablePagination,
  TableRow,
  TextField,
  Typography,
} from '@mui/material';
import RadarRoundedIcon from '@mui/icons-material/RadarRounded';
import UploadFileRoundedIcon from '@mui/icons-material/UploadFileRounded';
import {
  ASSET_KINDS,
  apiErrorMessage,
  fetchMe,
  importCaptureAssets,
  previewCaptureAssets,
  type CaptureImportResult,
  type CaptureImportRow,
  type CapturePreview,
} from '@/lib/api';

const PAGE_SIZE = 15;
const IMPORT_LIMIT = 500;
const MAX_CAPTURE_BYTES = 128 * 1024 * 1024;
type AssetKind = (typeof ASSET_KINDS)[number];
type Draft = { name: string; kind: AssetKind };

export default function AssetDiscovery({
  customer,
  disabled = false,
  onImported,
}: {
  customer?: string;
  disabled?: boolean;
  onImported: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [canWriteAssets, setCanWriteAssets] = useState(false);

  useEffect(() => {
    let current = true;
    fetchMe().then((me) => {
      if (current) setCanWriteAssets(me.can_write_assets === true);
    }).catch(() => {
      if (current) setCanWriteAssets(false);
    });
    return () => { current = false; };
  }, []);

  if (!canWriteAssets) return null;

  return (
    <>
      <Button
        size="small"
        variant="outlined"
        startIcon={<RadarRoundedIcon />}
        onClick={() => setOpen(true)}
        disabled={disabled}
      >
        Discover assets
      </Button>
      {open && (
        <DiscoveryDialog
          customer={customer}
          onClose={() => setOpen(false)}
          onImported={onImported}
        />
      )}
    </>
  );
}

function DiscoveryDialog({
  customer,
  onClose,
  onImported,
}: {
  customer?: string;
  onClose: () => void;
  onImported: () => void;
}) {
  const fileInput = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<CapturePreview | null>(null);
  const [drafts, setDrafts] = useState<Record<string, Draft>>({});
  const [selection, setSelection] = useState<Set<string>>(new Set());
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(0);
  const [busy, setBusy] = useState<'preview' | 'import' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<CaptureImportResult | null>(null);

  function reset() {
    setPreview(null);
    setDrafts({});
    setSelection(new Set());
    setQuery('');
    setPage(0);
    setError(null);
  }

  async function loadPreview() {
    if (!file || busy) return;
    setBusy('preview');
    setError(null);
    try {
      const data = await previewCaptureAssets(file, customer);
      setDrafts(Object.fromEntries(data.endpoints.map((item) => [
        item.ip_address, { name: item.suggested_name, kind: item.suggested_kind },
      ])));
      setPreview(data);
    } catch (err) {
      setError(apiErrorMessage(err, 'Could not read the capture. Check the file format and try again.'));
    } finally {
      setBusy(null);
    }
  }

  const search = query.trim().toLowerCase();
  const filtered = (preview?.endpoints ?? []).filter((item) =>
    [item.ip_address, drafts[item.ip_address]?.name ?? '', ...item.mac_addresses, ...item.protocols]
      .some((value) => value.toLowerCase().includes(search)),
  );
  const shown = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const visibleChoices = shown.filter((item) => !item.existing_asset_id);
  const visibleSelected = visibleChoices.filter((item) => selection.has(item.ip_address)).length;
  const allVisibleSelected = visibleChoices.length > 0 && visibleSelected === visibleChoices.length;
  const rows: CaptureImportRow[] = Array.from(selection, (ip_address) => ({
    ip_address,
    name: drafts[ip_address].name.trim(),
    kind: drafts[ip_address].kind,
  }));
  const namesMissing = rows.some((row) => !row.name);

  function toggleAddresses(addresses: string[], checked: boolean) {
    setSelection((current) => {
      const next = new Set(current);
      for (const address of addresses) {
        if (checked) next.add(address);
        else next.delete(address);
      }
      return next.size <= IMPORT_LIMIT ? next : current;
    });
  }

  function updateDraft(address: string, patch: Partial<Draft>) {
    setDrafts((current) => ({ ...current, [address]: { ...current[address], ...patch } }));
  }

  async function importSelection() {
    if (busy || !rows.length || namesMissing) return;
    setBusy('import');
    setError(null);
    try {
      setResult(await importCaptureAssets(rows, customer));
    } catch (err) {
      setError(apiErrorMessage(err, 'Could not add the selected assets. Try again.'));
      return;
    } finally {
      setBusy(null);
    }
    onImported();
  }

  return (
    <Dialog open fullWidth maxWidth={preview && !result ? 'lg' : 'sm'} onClose={() => !busy && onClose()}>
      <DialogTitle>Discover assets</DialogTitle>
      <DialogContent dividers>
        <Stack spacing={2}>
          {error && <Alert severity="error">{error}</Alert>}
          {result ? (
            <Alert severity={result.created ? 'success' : 'info'}>
              {result.created} {result.created === 1 ? 'asset' : 'assets'} added to the inventory.
              {result.skipped > 0 && ` ${result.skipped} already in the inventory and skipped.`}
            </Alert>
          ) : !preview ? (
            <>
              <Box>
                <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Packet capture</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                  Choose a PCAP or PCAPNG file up to 128 MiB, then review the observed endpoints before adding assets.
                </Typography>
              </Box>
              <Stack direction="row" alignItems="center" spacing={1.5} flexWrap="wrap" useFlexGap>
                <Button
                  variant="outlined"
                  startIcon={<UploadFileRoundedIcon />}
                  disabled={Boolean(busy)}
                  onClick={() => fileInput.current?.click()}
                >
                  Choose capture
                </Button>
                <input
                  ref={fileInput}
                  type="file"
                  hidden
                  disabled={Boolean(busy)}
                  aria-label="Packet capture file"
                  accept=".pcap,.pcapng"
                  onChange={(event) => {
                    const next = event.target.files?.[0] ?? null;
                    event.target.value = '';
                    if (!next) return;
                    if (!/\.(pcap|pcapng)$/i.test(next.name)) {
                      setFile(null);
                      setError('Choose a file ending in .pcap or .pcapng.');
                      return;
                    }
                    if (next.size > MAX_CAPTURE_BYTES) {
                      setFile(null);
                      setError('Choose a capture up to 128 MiB.');
                      return;
                    }
                    setFile(next);
                    setError(null);
                  }}
                />
                {file && <Typography variant="body2" sx={{ overflowWrap: 'anywhere' }}>{file.name}</Typography>}
              </Stack>
              {['Live capture on this machine', 'Network sweep'].map((method) => (
                <Stack key={method} direction="row" alignItems="center" spacing={1}>
                  <Button disabled size="small" sx={{ textAlign: 'left' }}>{method}</Button>
                  <Chip label="Coming later" size="small" variant="outlined" />
                </Stack>
              ))}
            </>
          ) : (
            <>
              <Typography variant="body2" sx={{ overflowWrap: 'anywhere' }}>
                <strong>{file?.name}</strong> · {preview.packet_count.toLocaleString()} packets examined ·{' '}
                {preview.endpoints.length.toLocaleString()} endpoint candidates
              </Typography>
              <Alert severity="info">
                Confirm candidates before importing. Captures can include off-network peers and
                shared or translated IPs. A MAC can belong to the next hop. Treat port-based
                protocol labels as hints about traffic.
              </Alert>
              {(preview.truncated || preview.warnings.length > 0) && (
                <Alert severity="warning">
                  {preview.truncated && preview.warnings.length === 0 && (
                    <Typography variant="body2">The capture preview was limited.</Typography>
                  )}
                  {preview.warnings.map((warning, index) => (
                    <Typography key={index} variant="body2">{warning}</Typography>
                  ))}
                </Alert>
              )}
              {preview.endpoints.length === 0 ? (
                <Typography variant="body2" color="text.secondary">No IP endpoints were found in this capture.</Typography>
              ) : (
                <>
                  <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} alignItems={{ sm: 'center' }}>
                    <TextField
                      label="Filter endpoints"
                      size="small"
                      placeholder="IP, name, MAC or protocol"
                      value={query}
                      disabled={Boolean(busy)}
                      onChange={(event) => { setQuery(event.target.value); setPage(0); }}
                      sx={{ flex: 1 }}
                    />
                    <Typography variant="body2" color="text.secondary">
                      {selection.size.toLocaleString()} selected · up to {IMPORT_LIMIT} per import
                    </Typography>
                  </Stack>
                  <TableContainer sx={{ maxHeight: 420 }}>
                    <Table size="small" stickyHeader sx={{ minWidth: 700 }}>
                      <TableHead>
                        <TableRow>
                          <TableCell padding="checkbox">
                            <Checkbox
                              size="small"
                              checked={allVisibleSelected}
                              indeterminate={visibleSelected > 0 && !allVisibleSelected}
                              inputProps={{ 'aria-label': 'Select endpoints on this page' }}
                              disabled={Boolean(busy) || visibleChoices.length === 0 || (
                                !allVisibleSelected && selection.size + visibleChoices.length - visibleSelected > IMPORT_LIMIT
                              )}
                              onChange={(event) => toggleAddresses(visibleChoices.map((item) => item.ip_address), event.target.checked)}
                            />
                          </TableCell>
                          <TableCell>IP address</TableCell>
                          <TableCell>Observed traffic</TableCell>
                          <TableCell>Asset name</TableCell>
                          <TableCell>Asset type</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {shown.length === 0 && (
                          <TableRow><TableCell colSpan={5}>No endpoints match this filter.</TableCell></TableRow>
                        )}
                        {shown.map((item) => {
                          const address = item.ip_address;
                          const existing = Boolean(item.existing_asset_id);
                          const chosen = selection.has(address);
                          const draft = drafts[address];
                          return (
                            <TableRow key={address} hover selected={chosen}>
                              <TableCell padding="checkbox">
                                <Checkbox
                                  size="small"
                                  checked={chosen}
                                  inputProps={{ 'aria-label': `Select ${address}` }}
                                  disabled={Boolean(busy) || existing || (!chosen && selection.size >= IMPORT_LIMIT)}
                                  onChange={(event) => toggleAddresses([address], event.target.checked)}
                                />
                              </TableCell>
                              <TableCell sx={{ fontFamily: 'JetBrains Mono, monospace', overflowWrap: 'anywhere', minWidth: 135 }}>
                                {address}
                              </TableCell>
                              <TableCell sx={{ minWidth: 160 }}>
                                <Typography variant="body2">{item.protocols.join(', ') || 'IP'}</Typography>
                                <Typography variant="caption" display="block" color="text.secondary">
                                  {item.packet_count.toLocaleString()} {item.packet_count === 1 ? 'packet' : 'packets'}
                                  {item.mac_addresses.length ? ` · ${item.mac_addresses.join(', ')}` : ''}
                                </Typography>
                              </TableCell>
                              {existing ? (
                                <TableCell colSpan={2}>
                                  <Chip size="small" variant="outlined" label="Already in inventory" />
                                  <Typography variant="caption" display="block" color="text.secondary">
                                    {item.existing_asset_name}
                                  </Typography>
                                </TableCell>
                              ) : (
                                <>
                                  <TableCell sx={{ minWidth: 165 }}>
                                    <TextField
                                      size="small"
                                      fullWidth
                                      value={draft.name}
                                      error={chosen && !draft.name.trim()}
                                      disabled={Boolean(busy)}
                                      inputProps={{ 'aria-label': `Asset name for ${address}`, maxLength: 200 }}
                                      onChange={(event) => updateDraft(address, { name: event.target.value })}
                                    />
                                  </TableCell>
                                  <TableCell sx={{ minWidth: 150 }}>
                                    <TextField
                                      size="small"
                                      fullWidth
                                      select
                                      value={draft.kind}
                                      disabled={Boolean(busy)}
                                      SelectProps={{ inputProps: { 'aria-label': `Asset type for ${address}` } }}
                                      onChange={(event) => updateDraft(address, { kind: event.target.value as AssetKind })}
                                    >
                                      {ASSET_KINDS.map((kind) => (
                                        <MenuItem key={kind} value={kind}>{kind === 'iot_ot' ? 'IoT / OT' : kind.replace('_', ' ')}</MenuItem>
                                      ))}
                                    </TextField>
                                  </TableCell>
                                </>
                              )}
                            </TableRow>
                          );
                        })}
                      </TableBody>
                    </Table>
                  </TableContainer>
                  {filtered.length > PAGE_SIZE && (
                    <TablePagination
                      component="div"
                      count={filtered.length}
                      rowsPerPage={PAGE_SIZE}
                      rowsPerPageOptions={[PAGE_SIZE]}
                      page={page}
                      onPageChange={(_, next) => setPage(next)}
                    />
                  )}
                  {namesMissing && <Alert severity="warning">Enter a name for every selected asset.</Alert>}
                </>
              )}
            </>
          )}
        </Stack>
      </DialogContent>
      <DialogActions>
        {!result && preview && (
          <Button onClick={() => { reset(); setFile(null); }} disabled={Boolean(busy)}>
            Choose another capture
          </Button>
        )}
        <Button onClick={onClose} disabled={Boolean(busy)}>{result ? 'Done' : 'Cancel'}</Button>
        {!result && (
          <Button
            variant="contained"
            startIcon={busy ? <CircularProgress size={16} color="inherit" /> : undefined}
            disabled={Boolean(busy) || (preview ? !rows.length || namesMissing : !file)}
            onClick={preview ? importSelection : loadPreview}
          >
            {busy === 'preview' ? 'Previewing…' : busy === 'import' ? 'Importing…' :
              preview ? 'Import selected' : 'Preview endpoints'}
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
}
