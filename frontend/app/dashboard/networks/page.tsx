'use client';

import { type FormEvent, useEffect, useId, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  List,
  ListItemButton,
  ListItemText,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import AddRoundedIcon from '@mui/icons-material/AddRounded';
import EditRoundedIcon from '@mui/icons-material/EditRounded';
import RefreshRoundedIcon from '@mui/icons-material/RefreshRounded';

import {
  CUSTOMER_SELECTION_REQUIRED_MESSAGE,
  clearApiCache,
  deleteNetwork,
  fetchMe,
  listNetworks,
  type NetworkOut,
  saveNetwork,
} from '@/lib/api';
import { getActiveCustomer } from '@/lib/auth';
import { apiErrorMessage } from '@/lib/cmf-utils';
import NetworkEvidence from './NetworkEvidence';

type NetworkAction = { kind: 'create' } | { kind: 'edit' | 'remove'; network: NetworkOut };

function NetworkEditor({
  customer, action, onClose, onSaved, onRemoved,
}: {
  customer: string;
  action: NetworkAction;
  onClose: () => void;
  onSaved: (network: NetworkOut) => void;
  onRemoved: (networkId: string) => void;
}) {
  const existing = 'network' in action ? action.network : null;
  const removing = action.kind === 'remove';
  const [name, setName] = useState(existing?.name ?? '');
  const [cidr, setCidr] = useState(existing?.cidr ?? '');
  const [location, setLocation] = useState(existing?.location ?? '');
  const [description, setDescription] = useState(existing?.description ?? '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const titleId = useId();

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (removing && existing) {
        await deleteNetwork(existing.id, customer);
        onRemoved(existing.id);
      } else {
        const saved = await saveNetwork({
          name: name.trim(),
          cidr: cidr.trim(),
          location: location.trim() || null,
          description: description.trim() || null,
        }, customer, existing?.id);
        onSaved(saved);
      }
    } catch (err) {
      setError(apiErrorMessage(err, removing ? 'Could not remove the network.' : 'Could not save the network.'));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open fullWidth maxWidth="sm" aria-labelledby={titleId} onClose={busy ? undefined : onClose}>
      <Box component="form" onSubmit={submit}>
        <DialogTitle id={titleId}>
          {removing ? 'Remove network' : existing ? 'Edit network' : 'Register network'}
        </DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            {error && <Alert severity="error">{error}</Alert>}
            {removing && existing ? (
              <Typography variant="body2">
                Remove <strong>{existing.name}</strong> ({existing.cidr}) and its network assignments?
              </Typography>
            ) : (
              <>
                <TextField label="Name" value={name} onChange={(event) => setName(event.target.value)} slotProps={{ htmlInput: { maxLength: 200 } }} required disabled={busy} autoFocus />
                <TextField
                  label="CIDR"
                  value={cidr}
                  onChange={(event) => setCidr(event.target.value)}
                  helperText="IPv4 or IPv6 range, for example 192.0.2.0/24 or 2001:db8::/64."
                  required
                  disabled={busy}
                />
                {existing && cidr.trim() !== existing.cidr && (
                  <Alert severity="info">Existing assignments will be retained. Review them after changing the subnet.</Alert>
                )}
                <TextField label="Location" value={location} onChange={(event) => setLocation(event.target.value)} slotProps={{ htmlInput: { maxLength: 200 } }} disabled={busy} />
                <TextField label="Description" value={description} onChange={(event) => setDescription(event.target.value)} slotProps={{ htmlInput: { maxLength: 4000 } }} multiline minRows={2} disabled={busy} />
              </>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose} disabled={busy}>Cancel</Button>
          <Button
            type="submit"
            variant="contained"
            color={removing ? 'error' : 'primary'}
            disabled={busy || (!removing && (!name.trim() || !cidr.trim()))}
          >
            {removing ? 'Remove network' : existing ? 'Save changes' : 'Register network'}
          </Button>
        </DialogActions>
      </Box>
    </Dialog>
  );
}

export default function NetworksPage() {
  const customer = getActiveCustomer();
  const [networks, setNetworks] = useState<NetworkOut[] | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [canWrite, setCanWrite] = useState(false);
  const [listError, setListError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const [action, setAction] = useState<NetworkAction | null>(null);
  const selected = networks?.find((network) => network.id === selectedId) ?? networks?.[0];

  useEffect(() => {
    if (!customer) return;
    let active = true;
    fetchMe(customer).then((me) => {
      if (active) setCanWrite(Boolean(me.can_write_assets));
    }).catch(() => {
      if (active) setCanWrite(false);
    });
    return () => { active = false; };
  }, [customer]);

  useEffect(() => {
    if (!customer) return;
    let active = true;
    listNetworks(customer).then((items) => {
      if (!active) return;
      setNetworks(items);
      setListError(null);
    }).catch((err) => {
      if (!active) return;
      setNetworks(null);
      setListError(apiErrorMessage(err, 'Could not load networks.'));
    });
    return () => { active = false; };
  }, [customer, revision]);

  function refresh() {
    clearApiCache();
    setListError(null);
    setRevision((value) => value + 1);
  }

  return (
    <Stack spacing={3}>
      <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" alignItems={{ sm: 'flex-start' }} spacing={2}>
        <Box>
          <Typography component="h1" variant="h4">Networks</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
            Register subnets and review collection and detection evidence for each network.
          </Typography>
        </Box>
        {customer && (
          <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap" flexShrink={0}>
            <Button startIcon={<RefreshRoundedIcon />} onClick={refresh}>Refresh</Button>
            {canWrite && networks && (
              <Button variant="contained" startIcon={<AddRoundedIcon />} onClick={() => setAction({ kind: 'create' })}>
                Register network
              </Button>
            )}
          </Stack>
        )}
      </Stack>
      {!customer && <Alert severity="info">{CUSTOMER_SELECTION_REQUIRED_MESSAGE}</Alert>}
      {customer && listError && <Alert severity="error">{listError}</Alert>}
      {customer && !networks && !listError && <CircularProgress size={26} aria-label="Loading networks" />}
      {customer && networks && !selected && (
        <Card variant="outlined">
          <CardContent>
            <Typography component="h2" variant="h6">No networks registered</Typography>
            {canWrite && (
              <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                Register an IPv4 or IPv6 subnet to assign collection sources and detection rules.
              </Typography>
            )}
          </CardContent>
        </Card>
      )}
      {customer && networks && selected && (
        <Box sx={{ display: 'grid', gridTemplateColumns: { xs: 'minmax(0, 1fr)', lg: '244px minmax(0, 1fr)' }, gap: 2.5, alignItems: 'start' }}>
          <Card variant="outlined">
            <Typography component="h2" variant="subtitle2" sx={{ px: 2, pt: 1.5, fontWeight: 700 }}>
              Registered networks ({networks.length})
            </Typography>
            <List component="div" dense sx={{ px: 1, maxHeight: { xs: 224, lg: 640 }, overflowY: 'auto' }}>
              {networks.map((network) => (
                <ListItemButton
                  key={network.id}
                  selected={selected.id === network.id}
                  aria-current={selected.id === network.id ? 'true' : undefined}
                  onClick={() => setSelectedId(network.id)}
                  sx={{ borderRadius: 1, overflowWrap: 'anywhere' }}
                >
                  <ListItemText
                    primary={network.name}
                    secondary={network.cidr}
                    slotProps={{ secondary: { sx: { fontFamily: 'monospace' } } }}
                  />
                </ListItemButton>
              ))}
            </List>
          </Card>
          <Stack spacing={2} sx={{ minWidth: 0 }}>
            <Stack direction={{ xs: 'column', md: 'row' }} justifyContent="space-between" spacing={1}>
              <Box sx={{ overflowWrap: 'anywhere' }}>
                <Typography component="h2" variant="h5">{selected.name}</Typography>
                <Typography variant="body2" color="text.secondary">
                  <Box component="span" sx={{ fontFamily: 'monospace' }}>{selected.cidr}</Box>
                  {selected.location && ` · ${selected.location}`}
                </Typography>
                {selected.description && <Typography variant="body2" sx={{ mt: 0.75 }}>{selected.description}</Typography>}
              </Box>
              {canWrite && (
                <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap" alignSelf="flex-start" flexShrink={0}>
                  <Button startIcon={<EditRoundedIcon />} onClick={() => setAction({ kind: 'edit', network: selected })}>Edit network</Button>
                  <Button color="error" onClick={() => setAction({ kind: 'remove', network: selected })}>Remove network</Button>
                </Stack>
              )}
            </Stack>
            <NetworkEvidence key={selected.id} network={selected} customer={customer} canWrite={canWrite} revision={revision} />
          </Stack>
        </Box>
      )}
      {customer && action && (
        <NetworkEditor
          customer={customer}
          action={action}
          onClose={() => setAction(null)}
          onSaved={(network) => {
            setAction(null);
            setSelectedId(network.id);
            setNetworks((items) => [...(items ?? []).filter((item) => item.id !== network.id), network]
              .sort((a, b) => a.name.localeCompare(b.name)));
            refresh();
          }}
          onRemoved={(id) => {
            setAction(null);
            setSelectedId(null);
            setNetworks((items) => items?.filter((item) => item.id !== id) ?? []);
            refresh();
          }}
        />
      )}
    </Stack>
  );
}
