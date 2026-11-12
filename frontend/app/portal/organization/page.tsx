'use client';

// Customer-facing organization profile. Users with asset-write permission
// can register assets in their own inventory.
//
// API auth: customer_user is hard-pinned to their own customer in the
// JWT, so calls land on their tenant schema automatically — no need to
// pass an explicit `customer` arg to the lib/api helpers.

import { useCallback, useEffect, useMemo, useState } from 'react';
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
  Paper,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip,
  Typography,
} from '@mui/material';
import AddRoundedIcon from '@mui/icons-material/AddRounded';
import DownloadRoundedIcon from '@mui/icons-material/DownloadRounded';
import EmailRoundedIcon from '@mui/icons-material/EmailRounded';
import ImageRoundedIcon from '@mui/icons-material/ImageRounded';
import InsertDriveFileRoundedIcon from '@mui/icons-material/InsertDriveFileRounded';
import LocationOnRoundedIcon from '@mui/icons-material/LocationOnRounded';
import PhoneRoundedIcon from '@mui/icons-material/PhoneRounded';
import PictureAsPdfRoundedIcon from '@mui/icons-material/PictureAsPdfRounded';
import StarRoundedIcon from '@mui/icons-material/StarRounded';
import WarningAmberRoundedIcon from '@mui/icons-material/WarningAmberRounded';

import {
  AssetOut,
  ContactOut,
  DiagramOut,
  MeResponse,
  downloadDiagramFile,
  fetchDiagramBlobUrl,
  fetchMe,
  listAssets,
  listContacts,
  listDiagrams,
} from '@/lib/api';
import AssetEditor from '@/app/dashboard/_components/AssetEditor';

const CRITICALITY_COLOR: Record<string, 'default' | 'success' | 'warning' | 'error'> = {
  low: 'default',
  medium: 'success',
  high: 'warning',
  critical: 'error',
};

function bytesHuman(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export default function OrganizationPage() {
  const [me, setMe] = useState<MeResponse | null>(null);
  const [meLoading, setMeLoading] = useState(true);

  useEffect(() => {
    fetchMe()
      .then(setMe)
      .finally(() => setMeLoading(false));
  }, []);

  return (
    <Stack spacing={3}>
      <Box>
        <Typography variant="h4" sx={{ fontWeight: 700, letterSpacing: '-0.02em' }}>
          {meLoading
            ? 'Organization'
            : me?.customer_name
              ? `${me.customer_name} profile`
              : 'Organization'}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Asset inventory, network diagrams, and emergency contacts.
        </Typography>
      </Box>

      <AssetsView canAddAsset={Boolean(me?.can_write_assets && me.customer_codename)} />
      <Divider />
      <DiagramsView />
      <Divider />
      <ContactsView />
    </Stack>
  );
}

// ---- Assets -------------------------------------------------------------

function AssetsView({ canAddAsset }: { canAddAsset: boolean }) {
  const [items, setItems] = useState<AssetOut[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setItems(await listAssets());
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'failed to load assets');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  const criticalCount = useMemo(
    () => items.filter((a) => a.criticality === 'critical').length,
    [items],
  );

  return (
    <Box>
      <Stack direction="row" alignItems="center" spacing={1} mb={1.5}>
        <Box sx={{ flex: 1 }}>
          <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
            Assets ({items.length})
          </Typography>
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>
            Systems recorded for your organization.
          </Typography>
        </Box>
        {criticalCount > 0 && (
          <Chip
            icon={<WarningAmberRoundedIcon />}
            label={`${criticalCount} critical`}
            size="small"
            color="error"
            variant="outlined"
          />
        )}
        {canAddAsset && (
          <Button
            size="small"
            variant="contained"
            startIcon={<AddRoundedIcon />}
            onClick={() => setAdding(true)}
          >
            Add asset
          </Button>
        )}
      </Stack>

      {error && <Alert severity="error" sx={{ mb: 1.5 }}>{error}</Alert>}

      {loading ? (
        <Stack alignItems="center" p={4}><CircularProgress size={24} /></Stack>
      ) : items.length === 0 ? (
        <Paper variant="outlined" sx={{ p: 3, textAlign: 'center' }}>
          <Typography variant="body2" color="text.secondary">
            No assets recorded yet.
          </Typography>
        </Paper>
      ) : (
        <TableContainer component={Paper} variant="outlined">
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Kind</TableCell>
                <TableCell>Primary IP</TableCell>
                <TableCell>Location</TableCell>
                <TableCell>Criticality</TableCell>
                <TableCell>Environment</TableCell>
                <TableCell>Business function</TableCell>
                <TableCell align="right">Coverage</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {items.map((a) => (
                <TableRow key={a.id} hover>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontWeight: 500 }}>{a.name}</Typography>
                    {a.hostname && (
                      <Typography variant="caption" color="text.secondary">
                        {a.hostname}
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell>
                    <Chip size="small" label={a.kind.replace('_', ' ')} variant="outlined" />
                  </TableCell>
                  <TableCell>{a.ip_address ?? '—'}</TableCell>
                  <TableCell>{a.location ?? '—'}</TableCell>
                  <TableCell>
                    <Chip
                      size="small"
                      label={a.criticality}
                      color={CRITICALITY_COLOR[a.criticality] ?? 'default'}
                      variant={a.criticality === 'critical' ? 'filled' : 'outlined'}
                    />
                  </TableCell>
                  <TableCell>{a.environment}</TableCell>
                  <TableCell>{a.business_function ?? '—'}</TableCell>
                  <TableCell align="right">
                    <Tooltip
                      title={`${a.coverage.deployed_detections} deployed of ${a.coverage.linked_detections} linked · ${a.coverage.techniques_covered} techniques`}
                    >
                      <Chip
                        size="small"
                        variant="outlined"
                        label={`${a.coverage.linked_detections} rules`}
                      />
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
      {canAddAsset && adding && (
        <AssetEditor
          target="new"
          onClose={() => setAdding(false)}
          onSaved={() => {
            setAdding(false);
            void reload();
          }}
        />
      )}
    </Box>
  );
}

// ---- Diagrams (read-only gallery) ---------------------------------------

function DiagramsView() {
  const [items, setItems] = useState<DiagramOut[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setItems(await listDiagrams());
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'failed to load diagrams');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  return (
    <Box>
      <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
        Network diagrams ({items.length})
      </Typography>
      <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1.5 }}>
        Topology and dataflow references kept by your MSSP. Images and
        PDFs render inline; other formats are available for download.
      </Typography>

      {error && <Alert severity="error" sx={{ mb: 1.5 }}>{error}</Alert>}

      {loading ? (
        <Stack alignItems="center" p={4}><CircularProgress size={24} /></Stack>
      ) : items.length === 0 ? (
        <Paper variant="outlined" sx={{ p: 3, textAlign: 'center' }}>
          <Typography variant="body2" color="text.secondary">
            No diagrams yet.
          </Typography>
        </Paper>
      ) : (
        <Stack direction="row" flexWrap="wrap" useFlexGap spacing={2}>
          {items.map((d) => (
            <DiagramCardReadOnly key={d.id} diagram={d} />
          ))}
        </Stack>
      )}
    </Box>
  );
}

function DiagramCardReadOnly({ diagram }: { diagram: DiagramOut }) {
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [previewError, setPreviewError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    let url: string | null = null;
    if (diagram.kind === 'image' || diagram.kind === 'pdf') {
      fetchDiagramBlobUrl(diagram.id)
        .then((u) => {
          if (cancelled) {
            URL.revokeObjectURL(u);
            return;
          }
          url = u;
          setPreviewUrl(u);
        })
        .catch(() => {
          if (!cancelled) setPreviewError(true);
        });
    }
    return () => {
      cancelled = true;
      if (url) URL.revokeObjectURL(url);
    };
  }, [diagram.id, diagram.kind]);

  const icon =
    diagram.kind === 'image' ? <ImageRoundedIcon fontSize="small" />
    : diagram.kind === 'pdf' ? <PictureAsPdfRoundedIcon fontSize="small" />
    : <InsertDriveFileRoundedIcon fontSize="small" />;

  return (
    <Card variant="outlined" sx={{ width: 280, display: 'flex', flexDirection: 'column' }}>
      <Box
        sx={{
          height: 160,
          bgcolor: 'action.hover',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          overflow: 'hidden',
        }}
      >
        {diagram.kind === 'image' && previewUrl && !previewError ? (
          // eslint-disable-next-line @next/next/no-img-element
          <img
            src={previewUrl}
            alt={diagram.title}
            style={{ maxWidth: '100%', maxHeight: '100%', objectFit: 'contain' }}
          />
        ) : diagram.kind === 'pdf' && previewUrl && !previewError ? (
          <embed
            src={previewUrl}
            type="application/pdf"
            style={{ width: '100%', height: '100%' }}
          />
        ) : diagram.kind === 'image' || diagram.kind === 'pdf' ? (
          <CircularProgress size={20} />
        ) : (
          <Stack alignItems="center" spacing={0.5}>
            <InsertDriveFileRoundedIcon sx={{ fontSize: 40, color: 'text.disabled' }} />
            <Typography variant="caption" color="text.secondary">
              {diagram.mime_type || 'binary'}
            </Typography>
          </Stack>
        )}
      </Box>
      <CardContent sx={{ p: 1.5, flex: 1, display: 'flex', flexDirection: 'column' }}>
        <Stack direction="row" alignItems="flex-start" spacing={1}>
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Typography
              variant="subtitle2"
              noWrap
              title={diagram.title}
              sx={{ fontWeight: 600 }}
            >
              {diagram.title}
            </Typography>
            <Stack direction="row" alignItems="center" spacing={0.5} mt={0.25}>
              {icon}
              <Typography variant="caption" color="text.secondary" noWrap>
                {diagram.filename} · {bytesHuman(diagram.size_bytes)}
              </Typography>
            </Stack>
          </Box>
          {diagram.is_primary && (
            <Tooltip title="Primary diagram">
              <StarRoundedIcon fontSize="small" sx={{ color: 'warning.main' }} />
            </Tooltip>
          )}
        </Stack>
        {diagram.description && (
          <Typography
            variant="caption"
            color="text.secondary"
            sx={{
              mt: 0.5,
              display: '-webkit-box',
              WebkitLineClamp: 2,
              WebkitBoxOrient: 'vertical',
              overflow: 'hidden',
            }}
          >
            {diagram.description}
          </Typography>
        )}
        <Stack direction="row" mt="auto" pt={1} justifyContent="flex-end">
          <Tooltip title="Download">
            <IconButton size="small" onClick={() => downloadDiagramFile(diagram)}>
              <DownloadRoundedIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Stack>
      </CardContent>
    </Card>
  );
}

// ---- Contacts (read-only cards) -----------------------------------------

function ContactsView() {
  const [items, setItems] = useState<ContactOut[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setItems(await listContacts());
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'failed to load contacts');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  return (
    <Box>
      <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
        Emergency contacts ({items.length})
      </Typography>
      <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1.5 }}>
        Personnel your MSSP will reach out to during incidents.
      </Typography>

      {error && <Alert severity="error" sx={{ mb: 1.5 }}>{error}</Alert>}

      {loading ? (
        <Stack alignItems="center" p={4}><CircularProgress size={24} /></Stack>
      ) : items.length === 0 ? (
        <Paper variant="outlined" sx={{ p: 3, textAlign: 'center' }}>
          <Typography variant="body2" color="text.secondary">
            No emergency contacts recorded yet.
          </Typography>
        </Paper>
      ) : (
        <Stack direction="row" flexWrap="wrap" useFlexGap spacing={2}>
          {items.map((c) => (
            <Card key={c.id} variant="outlined" sx={{ width: 320 }}>
              <CardContent sx={{ p: 2 }}>
                <Stack direction="row" alignItems="center" spacing={1} mb={0.5}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, flex: 1 }}>
                    {c.name}
                  </Typography>
                  {c.is_primary && (
                    <Tooltip title="Primary contact">
                      <StarRoundedIcon fontSize="small" sx={{ color: 'warning.main' }} />
                    </Tooltip>
                  )}
                </Stack>
                {c.role && (
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1 }}>
                    {c.role}
                  </Typography>
                )}
                <Stack spacing={0.75}>
                  {c.email && (
                    <Stack direction="row" alignItems="center" spacing={1}>
                      <EmailRoundedIcon fontSize="small" sx={{ color: 'text.secondary' }} />
                      <Typography
                        variant="body2"
                        component="a"
                        href={`mailto:${c.email}`}
                        sx={{ color: 'primary.main', textDecoration: 'none' }}
                      >
                        {c.email}
                      </Typography>
                    </Stack>
                  )}
                  {c.phone && (
                    <Stack direction="row" alignItems="center" spacing={1}>
                      <PhoneRoundedIcon fontSize="small" sx={{ color: 'text.secondary' }} />
                      <Typography variant="body2">{c.phone}</Typography>
                    </Stack>
                  )}
                  {c.office_address && (
                    <Stack direction="row" alignItems="flex-start" spacing={1}>
                      <LocationOnRoundedIcon fontSize="small" sx={{ color: 'text.secondary', mt: 0.25 }} />
                      <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
                        {c.office_address}
                      </Typography>
                    </Stack>
                  )}
                  {c.notes && (
                    <Typography
                      variant="caption"
                      color="text.secondary"
                      sx={{ mt: 0.5, fontStyle: 'italic' }}
                    >
                      {c.notes}
                    </Typography>
                  )}
                </Stack>
              </CardContent>
            </Card>
          ))}
        </Stack>
      )}
    </Box>
  );
}
