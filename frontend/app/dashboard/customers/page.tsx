'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Drawer,
  IconButton,
  MenuItem,
  Paper,
  Stack,
  Switch,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Tabs,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import AddRoundedIcon from '@mui/icons-material/AddRounded';
import ArchiveRoundedIcon from '@mui/icons-material/ArchiveRounded';
import CloseRoundedIcon from '@mui/icons-material/CloseRounded';
import DeleteOutlineRoundedIcon from '@mui/icons-material/DeleteOutlineRounded';
import PauseCircleOutlineRoundedIcon from '@mui/icons-material/PauseCircleOutlineRounded';
import PlayCircleOutlineRoundedIcon from '@mui/icons-material/PlayCircleOutlineRounded';
import SaveRoundedIcon from '@mui/icons-material/SaveRounded';
import {
  CustomRole,
  CustomerFeatureMeta,
  CustomerFeaturesOut,
  CustomerOut,
  CustomerStatus,
  CustomerUserOut,
  createCustomer,
  createCustomerUser,
  deleteCustomerUser,
  getCustomerFeatures,
  listCustomers,
  listCustomRoles,
  listCustomerUsers,
  patchCustomer,
  patchCustomerFeatures,
  updateCustomerUser,
} from '@/lib/api';
import { notifyFeaturesChanged } from '@/lib/features';
import { useDeployment } from '@/lib/deployment';
import ProfileTab from './ProfileTab';

const SECTOR_OPTIONS = [
  { value: '', label: '— none —' },
  { value: 'finance', label: 'Finance / banking' },
  { value: 'healthcare', label: 'Healthcare' },
  { value: 'energy', label: 'Energy / utilities' },
  { value: 'retail', label: 'Retail / e-commerce' },
  { value: 'government', label: 'Government / public sector' },
];

const STATUS_COLOR: Record<string, 'default' | 'success' | 'warning' | 'info' | 'error'> = {
  provisioning: 'info',
  active: 'success',
  suspended: 'warning',
  archived: 'default',
};

const STATUS_BLURB: Record<CustomerStatus, string> = {
  provisioning: 'Schema is being created — wait for activation.',
  active: 'Tenant is live; analysts can view and edit.',
  suspended: 'Access paused. Data preserved. Switch back to active to resume.',
  archived: 'Read-only and terminal. No further edits via the API.',
};

export default function CustomersPage() {
  const deployment = useDeployment();
  const singleEnvironment = deployment?.mode === 'single';
  const [items, setItems] = useState<CustomerOut[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [editing, setEditing] = useState<CustomerOut | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const rows = await listCustomers();
      rows.sort((a, b) => a.name.localeCompare(b.name));
      setItems(rows);
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'failed to load customers');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  const counts = useMemo(() => {
    const c: Record<string, number> = {
      active: 0,
      provisioning: 0,
      suspended: 0,
      archived: 0,
    };
    for (const r of items) c[r.status] = (c[r.status] ?? 0) + 1;
    return c;
  }, [items]);

  if (singleEnvironment) {
    return (
      <EnvironmentPage
        customer={items.find((item) => item.codename === deployment.active_customer)}
        canEdit={deployment.can_edit}
        loading={loading}
        error={error}
        onSaved={reload}
      />
    );
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      <Stack direction="row" alignItems="flex-end" spacing={2}>
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 700, letterSpacing: '-0.02em' }}>
            Customers
          </Typography>
          <Typography variant="body2" color="text.secondary">
            MSSP-scoped customer lifecycle. Provision new tenants, edit
            metadata, manage tenant users + feature toggles, suspend or archive.
          </Typography>
        </Box>
        <Box sx={{ flex: 1 }} />
        <Button
          variant="contained"
          startIcon={<AddRoundedIcon />}
          onClick={() => setCreateOpen(true)}
        >
          New customer
        </Button>
      </Stack>

      <Stack direction="row" spacing={1.5} flexWrap="wrap" useFlexGap>
        {(['active', 'provisioning', 'suspended', 'archived'] as const).map((s) => (
          <Card key={s} variant="outlined" sx={{ minWidth: 130 }}>
            <CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}>
              <Typography variant="caption" color="text.secondary">
                {s}
              </Typography>
              <Typography variant="h5" sx={{ fontWeight: 800, letterSpacing: '-0.04em' }}>
                {counts[s] ?? 0}
              </Typography>
            </CardContent>
          </Card>
        ))}
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
              No customers yet. Click <strong>New customer</strong> to provision one.
            </Typography>
          </CardContent>
        </Card>
      )}

      {!loading && items.length > 0 && (
        <Paper variant="outlined" sx={{ overflow: 'hidden' }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Customer</TableCell>
                <TableCell sx={{ width: 140 }}>Sector</TableCell>
                <TableCell sx={{ width: 130 }}>Status</TableCell>
                <TableCell sx={{ width: 210 }}>Schema</TableCell>
                <TableCell sx={{ width: 170 }}>Created</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {items.map((c) => (
                <TableRow
                  key={c.id}
                  hover
                  onClick={() => setEditing(c)}
                  sx={{ cursor: 'pointer' }}
                >
                  <TableCell>
                    <Stack direction="row" spacing={1} alignItems="center">
                      <Typography variant="body2" sx={{ fontWeight: 500 }}>{c.name}</Typography>
                      {deployment?.environments.some((env) => env.codename === c.codename && env.is_sample) && (
                        <Chip label="Sample" size="small" color="info" variant="outlined" />
                      )}
                    </Stack>
                    <Typography
                      variant="caption"
                      color="text.secondary"
                      sx={{ fontFamily: 'JetBrains Mono, monospace' }}
                    >
                      {c.codename}
                    </Typography>
                  </TableCell>
                  <TableCell>{c.sector ?? '—'}</TableCell>
                  <TableCell>
                    <Chip
                      label={c.status}
                      size="small"
                      color={STATUS_COLOR[c.status] ?? 'default'}
                      variant={c.status === 'archived' ? 'outlined' : 'filled'}
                    />
                  </TableCell>
                  <TableCell sx={{ fontFamily: 'JetBrains Mono, monospace' }}>
                    {c.schema_name}
                  </TableCell>
                  <TableCell>
                    <Typography variant="caption" color="text.secondary">
                      {c.created_at ? new Date(c.created_at).toLocaleString() : '—'}
                    </Typography>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Paper>
      )}

      <CreateDrawer
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        onCreated={() => {
          setCreateOpen(false);
          reload();
        }}
      />

      <EditDrawer
        customer={editing}
        onClose={() => setEditing(null)}
        onSaved={() => {
          // Re-open with the fresh row so any new status / fields are reflected
          // without dropping the drawer (keeps users / features in place).
          reload();
        }}
        onClosed={() => {
          setEditing(null);
          reload();
        }}
      />
    </Box>
  );
}

function CreateDrawer({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: () => void;
}) {
  const [codename, setCodename] = useState('');
  const [name, setName] = useState('');
  const [sector, setSector] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setCodename('');
      setName('');
      setSector('');
      setError(null);
    }
  }, [open]);

  const codenameValid = /^[a-z][a-z0-9_]{1,29}$/.test(codename);

  async function save() {
    setSubmitting(true);
    setError(null);
    try {
      await createCustomer({
        codename,
        name,
        sector: sector || undefined,
      });
      onCreated();
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'create failed');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Drawer
      anchor="right"
      open={open}
      onClose={onClose}
      PaperProps={{ sx: { width: { xs: '100%', md: 480 } } }}
    >
      <Box sx={{ p: 3, display: 'flex', flexDirection: 'column', gap: 2 }}>
        <Stack direction="row" alignItems="center" spacing={1}>
          <Typography variant="h6" sx={{ fontWeight: 700, flex: 1 }}>
            New customer
          </Typography>
          <IconButton onClick={onClose} size="small">
            <CloseRoundedIcon />
          </IconButton>
        </Stack>

        <Alert severity="info" sx={{ '& .MuiAlert-message': { fontSize: '0.85rem' } }}>
          Provisioning creates a dedicated <code>cust_&lt;codename&gt;</code>{' '}
          schema and clones the default Sigma rule pack. This is synchronous
          and may take a few seconds.
        </Alert>

        <TextField
          size="small"
          label="Codename"
          value={codename}
          onChange={(e) => setCodename(e.target.value.toLowerCase())}
          error={codename !== '' && !codenameValid}
          helperText="Lowercase letters, digits, underscore. 2–30 chars. Used as the schema suffix."
          inputProps={{ style: { fontFamily: 'JetBrains Mono, monospace' } }}
        />
        <TextField
          size="small"
          label="Display name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          helperText="Shown in reports, dashboards, the customer switcher."
        />
        <TextField
          size="small"
          select
          label="Sector"
          value={sector}
          onChange={(e) => setSector(e.target.value)}
          helperText="Optional. Drives sector-denominator coverage scoring."
        >
          {SECTOR_OPTIONS.map((o) => (
            <MenuItem key={o.value || '__none'} value={o.value}>
              {o.label}
            </MenuItem>
          ))}
        </TextField>

        {error && <Typography color="error">{error}</Typography>}

        <Stack direction="row" spacing={1.5}>
          <Button
            variant="contained"
            startIcon={submitting ? <CircularProgress size={14} /> : <SaveRoundedIcon />}
            onClick={save}
            disabled={
              submitting || !codenameValid || name.trim().length < 2
            }
          >
            Provision customer
          </Button>
          <Button onClick={onClose} disabled={submitting}>
            Cancel
          </Button>
        </Stack>
      </Box>
    </Drawer>
  );
}

type EditTab = 'overview' | 'profile' | 'users' | 'features';

function EnvironmentPage({
  customer,
  canEdit,
  loading,
  error,
  onSaved,
}: {
  customer?: CustomerOut;
  canEdit: boolean;
  loading: boolean;
  error: string | null;
  onSaved: () => void;
}) {
  const [tab, setTab] = useState<EditTab>('profile');

  return (
    <Stack spacing={3}>
      <Typography variant="h4" sx={{ fontWeight: 700, letterSpacing: '-0.02em' }}>
        Environment
      </Typography>
      {error && <Alert severity="error">{error}</Alert>}
      {loading && !customer && <CircularProgress size={24} />}
      {!loading && !customer && !error && (
        <Alert severity="info">Choose an active environment in Settings → Deployment.</Alert>
      )}
      {customer && (
        <>
          <Tabs
            value={tab}
            onChange={(_, value: EditTab) => setTab(value)}
            sx={{ borderBottom: 1, borderColor: 'divider' }}
          >
            <Tab label="Profile" value="profile" />
            {canEdit && <Tab label="Overview" value="overview" />}
            {canEdit && <Tab label="Users" value="users" />}
            {canEdit && <Tab label="Features" value="features" />}
          </Tabs>
          {tab === 'profile' && <ProfileTab customer={customer} />}
          {tab === 'overview' && canEdit && (
            <OverviewTab customer={customer} onSaved={onSaved} singleEnvironment />
          )}
          {tab === 'users' && canEdit && <UsersTab customer={customer} />}
          {tab === 'features' && canEdit && <FeaturesTab customer={customer} />}
        </>
      )}
    </Stack>
  );
}

function EditDrawer({
  customer,
  onSaved,
  onClosed,
}: {
  customer: CustomerOut | null;
  onClose?: () => void;
  onSaved: () => void;
  onClosed: () => void;
}) {
  const [tab, setTab] = useState<EditTab>('overview');

  useEffect(() => {
    if (customer) setTab('overview');
  }, [customer?.id]);

  if (!customer) {
    return <Drawer anchor="right" open={false} onClose={onClosed} />;
  }

  const archived = customer.status === 'archived';

  // Profile pulls in asset table + linked-detection picker — needs more
  // horizontal room than the other tabs.
  const drawerWidth = tab === 'profile' ? { xs: '100%', md: 960 } : { xs: '100%', md: 640 };

  return (
    <Drawer
      anchor="right"
      open={!!customer}
      onClose={onClosed}
      PaperProps={{ sx: { width: drawerWidth } }}
    >
      <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
        <Box sx={{ p: 3, pb: 1.5 }}>
          <Stack direction="row" alignItems="center" spacing={1}>
            <Box sx={{ flex: 1 }}>
              <Typography variant="h6" sx={{ fontWeight: 700 }}>
                {customer.name}
              </Typography>
              <Typography
                variant="caption"
                color="text.secondary"
                sx={{ fontFamily: 'JetBrains Mono, monospace' }}
              >
                {customer.codename} · {customer.schema_name}
              </Typography>
            </Box>
            <Chip
              label={customer.status}
              size="small"
              color={STATUS_COLOR[customer.status] ?? 'default'}
              variant={archived ? 'outlined' : 'filled'}
            />
            <IconButton onClick={onClosed} size="small">
              <CloseRoundedIcon />
            </IconButton>
          </Stack>
        </Box>
        <Tabs
          value={tab}
          onChange={(_, v: EditTab) => setTab(v)}
          sx={{ px: 3, borderBottom: 1, borderColor: 'divider' }}
        >
          <Tab label="Overview" value="overview" />
          <Tab label="Profile" value="profile" />
          <Tab label="Users" value="users" />
          <Tab label="Features" value="features" />
        </Tabs>
        <Box sx={{ flex: 1, overflowY: 'auto', p: 3 }}>
          {tab === 'overview' && (
            <OverviewTab customer={customer} onSaved={onSaved} />
          )}
          {tab === 'profile' && <ProfileTab customer={customer} />}
          {tab === 'users' && <UsersTab customer={customer} />}
          {tab === 'features' && <FeaturesTab customer={customer} />}
        </Box>
      </Box>
    </Drawer>
  );
}

function OverviewTab({
  customer,
  onSaved,
  singleEnvironment = false,
}: {
  customer: CustomerOut;
  onSaved: () => void;
  singleEnvironment?: boolean;
}) {
  const [name, setName] = useState(customer.name);
  const [sector, setSector] = useState(customer.sector ?? '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setName(customer.name);
    setSector(customer.sector ?? '');
    setError(null);
  }, [customer.id, customer.name, customer.sector]);

  const archived = customer.status === 'archived';
  const status = customer.status as CustomerStatus;

  async function save() {
    setBusy(true);
    setError(null);
    try {
      await patchCustomer(customer.codename, {
        name: name !== customer.name ? name : undefined,
        sector: sector !== (customer.sector ?? '') ? sector || null : undefined,
      });
      onSaved();
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'save failed');
    } finally {
      setBusy(false);
    }
  }

  async function transition(next: CustomerStatus, confirmMsg?: string) {
    if (confirmMsg && !confirm(confirmMsg)) return;
    setBusy(true);
    setError(null);
    try {
      await patchCustomer(customer.codename, { status: next });
      onSaved();
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'status change failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Stack spacing={2}>
      {!singleEnvironment && (
        <Typography variant="caption" color="text.secondary">
          {STATUS_BLURB[status]}
        </Typography>
      )}
      <TextField
        size="small"
        label="Display name"
        value={name}
        onChange={(e) => setName(e.target.value)}
        disabled={archived}
      />
      <TextField
        size="small"
        select
        label="Sector"
        value={sector}
        onChange={(e) => setSector(e.target.value)}
        disabled={archived}
      >
        {SECTOR_OPTIONS.map((o) => (
          <MenuItem key={o.value || '__none'} value={o.value}>
            {o.label}
          </MenuItem>
        ))}
      </TextField>
      {error && <Typography color="error">{error}</Typography>}
      <Stack direction="row" spacing={1.5}>
        <Button
          variant="contained"
          startIcon={busy ? <CircularProgress size={14} /> : <SaveRoundedIcon />}
          onClick={save}
          disabled={
            busy ||
            archived ||
            (name === customer.name && sector === (customer.sector ?? ''))
          }
        >
          Save changes
        </Button>
      </Stack>

      {!singleEnvironment && (
        <>
          <Typography
            variant="overline"
            sx={{ fontWeight: 700, color: 'text.secondary', mt: 2 }}
          >
            Lifecycle
          </Typography>
          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
            {status === 'active' && (
              <Tooltip title="Pause analyst access. Data is preserved.">
                <Button
                  variant="outlined"
                  color="warning"
                  size="small"
                  startIcon={<PauseCircleOutlineRoundedIcon />}
                  onClick={() =>
                    transition(
                      'suspended',
                      `Suspend ${customer.name}? Analysts will lose access until you reactivate.`,
                    )
                  }
                  disabled={busy}
                >
                  Suspend
                </Button>
              </Tooltip>
            )}
            {status === 'suspended' && (
              <Tooltip title="Restore analyst access.">
                <Button
                  variant="outlined"
                  color="success"
                  size="small"
                  startIcon={<PlayCircleOutlineRoundedIcon />}
                  onClick={() => transition('active')}
                  disabled={busy}
                >
                  Reactivate
                </Button>
              </Tooltip>
            )}
            {(status === 'active' || status === 'suspended') && (
              <Tooltip title="Terminal. The tenant becomes read-only. Schema remains for audit.">
                <Button
                  variant="outlined"
                  color="error"
                  size="small"
                  startIcon={<ArchiveRoundedIcon />}
                  onClick={() =>
                    transition(
                      'archived',
                      `Archive ${customer.name}? This is a one-way action. The tenant becomes read-only.`,
                    )
                  }
                  disabled={busy}
                >
                  Archive
                </Button>
              </Tooltip>
            )}
            {status === 'provisioning' && (
              <Typography variant="caption" color="text.secondary">
                Wait for provisioning to complete — status will flip to{' '}
                <strong>active</strong> automatically.
              </Typography>
            )}
            {status === 'archived' && (
              <Typography variant="caption" color="text.secondary">
                Archived tenants are not editable via the UI. Contact ops to
                restore.
              </Typography>
            )}
          </Stack>
        </>
      )}
    </Stack>
  );
}

// ---- Users tab -----------------------------------------------------------

function UsersTab({ customer }: { customer: CustomerOut }) {
  const [users, setUsers] = useState<CustomerUserOut[]>([]);
  const [customRoles, setCustomRoles] = useState<CustomRole[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const [showAdd, setShowAdd] = useState(false);
  const [nEmail, setNEmail] = useState('');
  const [nName, setNName] = useState('');
  const [nPass, setNPass] = useState('');
  const [nCustomRole, setNCustomRole] = useState('');
  const [adding, setAdding] = useState(false);

  const archived = customer.status === 'archived';

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setUsers(await listCustomerUsers(customer.codename));
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'failed to load users');
    } finally {
      setLoading(false);
    }
  }, [customer.codename]);

  useEffect(() => {
    reload();
    listCustomRoles()
      .then(setCustomRoles)
      .catch(() => {});
  }, [reload]);

  async function addUser() {
    setAdding(true);
    setError(null);
    try {
      await createCustomerUser(customer.codename, {
        email: nEmail.trim(),
        password: nPass,
        full_name: nName || undefined,
        custom_role_id: nCustomRole || undefined,
      });
      setShowAdd(false);
      setNEmail('');
      setNName('');
      setNPass('');
      setNCustomRole('');
      reload();
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'failed to create user');
    } finally {
      setAdding(false);
    }
  }

  async function patchUser(
    id: string,
    payload: Parameters<typeof updateCustomerUser>[2],
  ) {
    setBusyId(id);
    setError(null);
    try {
      await updateCustomerUser(customer.codename, id, payload);
      reload();
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'update failed');
    } finally {
      setBusyId(null);
    }
  }

  async function removeUser(id: string, email: string) {
    if (!confirm(`Delete ${email}? They will lose access immediately.`)) return;
    setBusyId(id);
    setError(null);
    try {
      await deleteCustomerUser(customer.codename, id);
      reload();
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'delete failed');
    } finally {
      setBusyId(null);
    }
  }

  return (
    <Stack spacing={2}>
      <Stack direction="row" alignItems="center" spacing={1}>
        <Box sx={{ flex: 1 }}>
          <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
            Customer users
          </Typography>
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>
            Tenant-only accounts pinned to {customer.name}. They cannot reach
            other customers even with the X-Customer header.
          </Typography>
        </Box>
        <Button
          size="small"
          variant="contained"
          startIcon={<AddRoundedIcon />}
          onClick={() => setShowAdd((v) => !v)}
          disabled={archived}
        >
          {showAdd ? 'Cancel' : 'Add user'}
        </Button>
      </Stack>

      {error && <Alert severity="error">{error}</Alert>}

      {showAdd && (
        <Paper variant="outlined" sx={{ p: 2 }}>
          <Stack spacing={1.5}>
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5}>
              <TextField
                size="small"
                label="Email"
                value={nEmail}
                onChange={(e) => setNEmail(e.target.value)}
                sx={{ flex: 1 }}
              />
              <TextField
                size="small"
                label="Full name (optional)"
                value={nName}
                onChange={(e) => setNName(e.target.value)}
                sx={{ flex: 1 }}
              />
            </Stack>
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5}>
              <TextField
                size="small"
                type="password"
                label="Temporary password"
                value={nPass}
                onChange={(e) => setNPass(e.target.value)}
                sx={{ flex: 1 }}
                helperText="At least 8 characters"
              />
              {customRoles.length > 0 && (
                <TextField
                  select
                  size="small"
                  label="Custom role (optional)"
                  value={nCustomRole}
                  onChange={(e) => setNCustomRole(e.target.value)}
                  sx={{ flex: 1 }}
                  helperText="Overrides the built-in customer_user permissions."
                >
                  <MenuItem value="">— none —</MenuItem>
                  {customRoles.map((cr) => (
                    <MenuItem key={cr.id} value={cr.id}>
                      {cr.label}
                    </MenuItem>
                  ))}
                </TextField>
              )}
            </Stack>
            <Box>
              <Button
                variant="contained"
                onClick={addUser}
                disabled={adding || !nEmail || nPass.length < 8}
              >
                {adding ? <CircularProgress size={16} /> : 'Create user'}
              </Button>
            </Box>
          </Stack>
        </Paper>
      )}

      {loading ? (
        <Box sx={{ py: 4, display: 'flex', justifyContent: 'center' }}>
          <CircularProgress />
        </Box>
      ) : users.length === 0 ? (
        <Typography variant="body2" color="text.secondary">
          No customer users yet for this tenant.
        </Typography>
      ) : (
        <Paper variant="outlined" sx={{ overflow: 'hidden' }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Email</TableCell>
                <TableCell sx={{ width: 200 }}>Custom role override</TableCell>
                <TableCell sx={{ width: 90 }}>Active</TableCell>
                <TableCell sx={{ width: 170 }}>Last login</TableCell>
                <TableCell sx={{ width: 60 }} />
              </TableRow>
            </TableHead>
            <TableBody>
              {users.map((u) => (
                <TableRow key={u.id} hover>
                  <TableCell>{u.email}</TableCell>
                  <TableCell>
                    <TextField
                      select
                      size="small"
                      value={u.custom_role_id ?? ''}
                      disabled={busyId === u.id || customRoles.length === 0 || archived}
                      onChange={(e) =>
                        patchUser(u.id, { custom_role_id: e.target.value })
                      }
                      variant="standard"
                      sx={{ minWidth: 180 }}
                    >
                      <MenuItem value="">
                        <em>— none —</em>
                      </MenuItem>
                      {customRoles.map((cr) => (
                        <MenuItem key={cr.id} value={cr.id}>
                          {cr.label}
                        </MenuItem>
                      ))}
                    </TextField>
                  </TableCell>
                  <TableCell>
                    <Switch
                      size="small"
                      checked={u.is_active}
                      disabled={busyId === u.id || archived}
                      onChange={(e) =>
                        patchUser(u.id, { is_active: e.target.checked })
                      }
                    />
                  </TableCell>
                  <TableCell>
                    <Typography variant="caption" color="text.secondary">
                      {u.last_login_at
                        ? new Date(u.last_login_at).toLocaleString()
                        : '—'}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Tooltip title="Delete user">
                      <span>
                        <IconButton
                          size="small"
                          color="error"
                          disabled={busyId === u.id || archived}
                          onClick={() => removeUser(u.id, u.email)}
                        >
                          <DeleteOutlineRoundedIcon fontSize="small" />
                        </IconButton>
                      </span>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Paper>
      )}
    </Stack>
  );
}

// ---- Features tab --------------------------------------------------------

function FeaturesTab({ customer }: { customer: CustomerOut }) {
  const [data, setData] = useState<CustomerFeaturesOut | null>(null);
  const [draft, setDraft] = useState<Record<string, boolean>>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const archived = customer.status === 'archived';

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const d = await getCustomerFeatures(customer.codename);
      setData(d);
      setDraft({ ...d.features });
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'failed to load features');
    } finally {
      setLoading(false);
    }
  }, [customer.codename]);

  useEffect(() => {
    reload();
  }, [reload]);

  const dirty = useMemo(() => {
    if (!data) return false;
    return Object.keys(draft).some((k) => draft[k] !== data.features[k]);
  }, [data, draft]);

  async function save() {
    if (!data) return;
    const changed: Record<string, boolean> = {};
    for (const k of Object.keys(draft)) {
      if (draft[k] !== data.features[k]) changed[k] = draft[k];
    }
    if (Object.keys(changed).length === 0) return;
    setSaving(true);
    setError(null);
    try {
      const updated = await patchCustomerFeatures(customer.codename, changed);
      setData(updated);
      setDraft({ ...updated.features });
      // Tell any open dashboard tabs scoped to this customer to refetch
      // their feature flags so disabled/enabled controls update without
      // a page reload.
      notifyFeaturesChanged(customer.codename);
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'save failed');
    } finally {
      setSaving(false);
    }
  }

  function reset() {
    if (data) setDraft({ ...data.features });
  }

  if (loading) {
    return (
      <Box sx={{ py: 4, display: 'flex', justifyContent: 'center' }}>
        <CircularProgress />
      </Box>
    );
  }
  if (!data) {
    return <Typography color="error">{error ?? 'no features payload'}</Typography>;
  }

  // Group by category for a readable layout.
  const byCategory = new Map<string, CustomerFeatureMeta[]>();
  for (const m of data.catalog) {
    const arr = byCategory.get(m.category) ?? [];
    arr.push(m);
    byCategory.set(m.category, arr);
  }

  return (
    <Stack spacing={2}>
      <Box>
        <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
          Feature toggles
        </Typography>
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>
          Per-customer overrides on top of the platform defaults. Turn off to
          hide / disable a capability for everyone in this tenant.
        </Typography>
      </Box>

      {error && <Alert severity="error">{error}</Alert>}

      {Array.from(byCategory.entries()).map(([cat, metas]) => (
        <Paper key={cat} variant="outlined">
          <Box sx={{ px: 2, py: 1, borderBottom: 1, borderColor: 'divider' }}>
            <Typography variant="caption" sx={{ fontWeight: 700, color: 'text.secondary' }}>
              {cat}
            </Typography>
          </Box>
          <Stack divider={<Box sx={{ borderTop: 1, borderColor: 'divider' }} />}>
            {metas.map((m) => (
              <Stack
                key={m.key}
                direction="row"
                alignItems="center"
                spacing={2}
                sx={{ px: 2, py: 1.25 }}
              >
                <Box sx={{ flex: 1 }}>
                  <Typography variant="body2" sx={{ fontWeight: 500 }}>
                    {m.label}
                    {!m.default && (
                      <Chip
                        label="default off"
                        size="small"
                        variant="outlined"
                        sx={{ ml: 1, height: 18, fontSize: 10 }}
                      />
                    )}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {m.description}
                  </Typography>
                </Box>
                <Switch
                  checked={!!draft[m.key]}
                  disabled={saving || archived}
                  onChange={(e) =>
                    setDraft((prev) => ({ ...prev, [m.key]: e.target.checked }))
                  }
                />
              </Stack>
            ))}
          </Stack>
        </Paper>
      ))}

      <Stack direction="row" spacing={1.5}>
        <Button
          variant="contained"
          startIcon={saving ? <CircularProgress size={14} /> : <SaveRoundedIcon />}
          onClick={save}
          disabled={!dirty || saving || archived}
        >
          Save changes
        </Button>
        <Button onClick={reset} disabled={!dirty || saving}>
          Reset
        </Button>
      </Stack>
    </Stack>
  );
}
