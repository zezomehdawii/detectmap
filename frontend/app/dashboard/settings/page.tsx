'use client';

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'next/navigation';
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
  FormControlLabel,
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
import SaveRoundedIcon from '@mui/icons-material/SaveRounded';
import AutoAwesomeRoundedIcon from '@mui/icons-material/AutoAwesomeRounded';
import LockPersonRoundedIcon from '@mui/icons-material/LockPersonRounded';
import MailOutlineRoundedIcon from '@mui/icons-material/MailOutlineRounded';
import AdminPanelSettingsRoundedIcon from '@mui/icons-material/AdminPanelSettingsRounded';
import AddRoundedIcon from '@mui/icons-material/AddRounded';
import DeleteOutlineRoundedIcon from '@mui/icons-material/DeleteOutlineRounded';
import EditRoundedIcon from '@mui/icons-material/EditRounded';
import LockRoundedIcon from '@mui/icons-material/LockRounded';
import CloseRoundedIcon from '@mui/icons-material/CloseRounded';
import {
  AIConfig,
  AuditEntry,
  BuiltinRole,
  CatalogDiff,
  CatalogSchedule,
  CustomRole,
  LdapConfig,
  MailConfig,
  MSSPBranding,
  LoginHint,
  PermissionMeta,
  SettingsUserOut,
  createCustomRole,
  createSettingsUser,
  deleteCustomRole,
  deleteSettingsUser,
  getAIConfig,
  getCatalogSchedule,
  getLdapConfig,
  getLoginHintSettings,
  getMailConfig,
  getMSSPBranding,
  listAttackDiffs,
  listAudit,
  listBuiltinRoles,
  listCustomRoles,
  listPermissionCatalog,
  listSettingsUsers,
  patchAIConfig,
  patchCatalogSchedule,
  patchLdapConfig,
  patchLoginHintSettings,
  patchMailConfig,
  patchMSSPBranding,
  refreshD3FENDCatalog,
  testAIConfig,
  testLdapConfig,
  testMailConfig,
  updateCustomRole,
  updateSettingsUser,
} from '@/lib/api';
import DeploymentTab from './DeploymentTab';

type TabKey =
  | 'branding'
  | 'deployment'
  | 'catalog'
  | 'ai'
  | 'schedule'
  | 'users'
  | 'roles'
  | 'ldap'
  | 'mail'
  | 'audit';

export default function SettingsPage() {
  const params = useSearchParams();
  const initial = (params.get('tab') as TabKey) || 'branding';
  const [tab, setTab] = useState<TabKey>(initial);

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      <Box>
        <Typography variant="h4" sx={{ fontWeight: 700, letterSpacing: '-0.02em' }}>
          Settings
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Deployment, branding, catalog updates, and user management.
        </Typography>
      </Box>

      <Tabs
        value={tab}
        onChange={(_, v) => setTab(v as TabKey)}
        variant="scrollable"
        scrollButtons="auto"
        sx={{ borderBottom: 1, borderColor: 'divider' }}
      >
        <Tab label="Branding" value="branding" />
        <Tab label="Deployment" value="deployment" />
        <Tab label="AI authoring" value="ai" />
        <Tab label="Active Directory" value="ldap" />
        <Tab label="Mail server" value="mail" />
        <Tab label="Schedule" value="schedule" />
        <Tab label="Catalog diffs" value="catalog" />
        <Tab label="Users" value="users" />
        <Tab label="Roles & permissions" value="roles" />
        <Tab label="Audit log" value="audit" />
      </Tabs>

      {tab === 'branding' && <BrandingTab />}
      {tab === 'deployment' && <DeploymentTab />}
      {tab === 'ai' && <AITab />}
      {tab === 'ldap' && <LdapTab />}
      {tab === 'mail' && <MailTab />}
      {tab === 'schedule' && <ScheduleTab />}
      {tab === 'catalog' && <CatalogTab />}
      {tab === 'users' && <UsersTab onGoToRoles={() => setTab('roles')} />}
      {tab === 'roles' && <RolesTab />}
      {tab === 'audit' && <AuditTab />}
    </Box>
  );
}

function BrandingTab() {
  const [data, setData] = useState<MSSPBranding | null>(null);
  const [displayName, setDisplayName] = useState('');
  const [logoUrl, setLogoUrl] = useState('');
  const [primaryColor, setPrimaryColor] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const reload = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await getMSSPBranding();
      setData(r);
      setDisplayName(String(r.branding?.display_name ?? r.mssp_org_name ?? ''));
      setLogoUrl(String(r.branding?.logo_url ?? ''));
      setPrimaryColor(String(r.branding?.primary_color ?? ''));
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'failed to load branding');
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  async function save() {
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      const r = await patchMSSPBranding({
        display_name: displayName || undefined,
        logo_url: logoUrl || undefined,
        primary_color: primaryColor || undefined,
      });
      setData(r);
      setSaved(true);
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'save failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Stack spacing={2}>
      <Card>
        <CardContent>
          <Typography
            variant="overline"
            sx={{ fontWeight: 700, color: 'text.secondary' }}
          >
            MSSP branding ({data?.mssp_org_name ?? '—'})
          </Typography>
          {error && (
            <Typography color="error" sx={{ mt: 1 }}>
              {error}
            </Typography>
          )}
          <Stack spacing={2} sx={{ mt: 2 }}>
            <TextField
              size="small"
              label="Display name"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              helperText="Used in report titles and the dashboard header."
            />
            <TextField
              size="small"
              label="Logo URL"
              value={logoUrl}
              onChange={(e) => setLogoUrl(e.target.value)}
              helperText="Optional. Embedded in branded PDF exports (planned)."
            />
            <TextField
              size="small"
              label="Primary colour"
              value={primaryColor}
              onChange={(e) => setPrimaryColor(e.target.value)}
              placeholder="#4f46e5"
            />
            <Box>
              <Button
                variant="contained"
                startIcon={busy ? <CircularProgress size={14} /> : <SaveRoundedIcon />}
                onClick={save}
                disabled={busy}
              >
                Save branding
              </Button>
              {saved && (
                <Typography variant="caption" color="text.secondary" sx={{ ml: 2 }}>
                  Saved.
                </Typography>
              )}
            </Box>
          </Stack>
        </CardContent>
      </Card>
      <LoginHintCard />
    </Stack>
  );
}

function LoginHintCard() {
  const [hint, setHint] = useState<LoginHint | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      setHint(await getLoginHintSettings());
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'failed to load sign-in hint');
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  async function toggle(enabled: boolean) {
    setBusy(true);
    setError(null);
    try {
      setHint(await patchLoginHintSettings(enabled));
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'save failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardContent>
        <Typography
          variant="overline"
          sx={{ fontWeight: 700, color: 'text.secondary' }}
        >
          Sign-in page
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
          Show the configured default credentials on the login card so testers
          can sign in. Turn this off once the bootstrap password has been
          rotated.
        </Typography>
        {error && (
          <Typography color="error" sx={{ mt: 1 }}>
            {error}
          </Typography>
        )}
        <Stack spacing={1} sx={{ mt: 2 }}>
          <FormControlLabel
            control={
              <Switch
                checked={Boolean(hint?.enabled)}
                onChange={(e) => toggle(e.target.checked)}
                disabled={busy || !hint}
              />
            }
            label="Show default credentials on the sign-in page"
          />
          {busy && !hint && <CircularProgress size={20} />}
          {hint?.enabled && hint.email && (
            <Typography variant="body2" color="text.secondary">
              Displayed: <Box component="code">{hint.email}</Box>
              {hint.password ? (
                <>
                  {' / '}
                  <Box component="code">{hint.password}</Box>
                </>
              ) : null}
            </Typography>
          )}
        </Stack>
      </CardContent>
    </Card>
  );
}

function CatalogTab() {
  const [diffs, setDiffs] = useState<CatalogDiff[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    listAttackDiffs(15)
      .then(setDiffs)
      .catch((e) =>
        setError(e?.response?.data?.detail ?? 'failed to load ATT&CK diffs'),
      )
      .finally(() => setLoading(false));
  }, []);

  return (
    <Stack spacing={2}>
      <Card>
        <CardContent>
          <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
            ATT&amp;CK release diffs
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 2 }}>
            Per-domain diff snapshots from every catalog ingest. Use this to
            review what changed between MITRE releases.
          </Typography>
          {error && <Typography color="error">{error}</Typography>}
          {loading && (
            <Box sx={{ py: 4, display: 'flex', justifyContent: 'center' }}>
              <CircularProgress />
            </Box>
          )}
          {!loading && diffs.length === 0 && !error && (
            <Typography color="text.secondary">
              No ATT&amp;CK versions ingested yet.
            </Typography>
          )}
          {!loading && diffs.length > 0 && (
            <Paper variant="outlined" sx={{ overflow: 'hidden' }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Ingested</TableCell>
                    <TableCell>Domain</TableCell>
                    <TableCell>Version</TableCell>
                    <TableCell align="right">Added</TableCell>
                    <TableCell align="right">Deprecated</TableCell>
                    <TableCell align="right">Renamed</TableCell>
                    <TableCell align="right">Revoked</TableCell>
                    <TableCell></TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {diffs.map((d, idx) => (
                    <TableRow key={`${d.domain}-${d.version}-${idx}`} hover>
                      <TableCell>
                        <Typography variant="caption">
                          {new Date(d.ingested_at).toLocaleString()}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip label={d.domain} size="small" variant="outlined" />
                      </TableCell>
                      <TableCell sx={{ fontFamily: 'JetBrains Mono, monospace' }}>
                        {d.version}
                      </TableCell>
                      <TableCell align="right">{d.added.length}</TableCell>
                      <TableCell align="right">{d.deprecated.length}</TableCell>
                      <TableCell align="right">{d.renamed.length}</TableCell>
                      <TableCell align="right">{d.revoked.length}</TableCell>
                      <TableCell>
                        {d.is_current && (
                          <Chip label="current" size="small" color="primary" />
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
    </Stack>
  );
}

// ---- AI authoring tab ----------------------------------------------------

function AITab() {
  const [cfg, setCfg] = useState<AIConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [apiKey, setApiKey] = useState('');
  const [model, setModel] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ ok: boolean; text: string } | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      const r = await getAIConfig();
      setCfg(r);
      setModel(r.model);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  async function save() {
    setBusy(true);
    setMsg(null);
    try {
      const r = await patchAIConfig({
        model: model || undefined,
        api_key: apiKey || undefined,
      });
      setCfg(r);
      setApiKey('');
      setMsg('Saved.');
    } catch (e: any) {
      setMsg(e?.response?.data?.detail ?? 'save failed');
    } finally {
      setBusy(false);
    }
  }

  async function clearKey() {
    setBusy(true);
    try {
      const r = await patchAIConfig({ clear_key: true });
      setCfg(r);
      setMsg('API key cleared.');
    } finally {
      setBusy(false);
    }
  }

  async function runTest() {
    setBusy(true);
    setTestResult(null);
    try {
      const r = await testAIConfig({
        api_key: apiKey || undefined,
        model: model || undefined,
      });
      setTestResult({ ok: r.ok, text: r.message });
    } catch (e: any) {
      setTestResult({ ok: false, text: e?.response?.data?.detail ?? 'test failed' });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardContent>
        <Stack direction="row" alignItems="center" spacing={1} mb={2}>
          <AutoAwesomeRoundedIcon color="primary" />
          <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
            AI authoring
          </Typography>
          {cfg?.has_key && (
            <Chip
              size="small"
              label={cfg.key_tail ? `key configured · ${cfg.key_tail}` : 'key configured'}
              color="success"
              variant="outlined"
            />
          )}
        </Stack>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Bring your own Anthropic API key. The key is Fernet-encrypted at
          rest, used only when an analyst clicks <em>Draft with AI</em> on a
          detection, and never returned to the client (only the last four
          characters are displayed). Drafts are validated against pySigma
          before they reach the analyst.
        </Typography>
        {loading ? (
          <CircularProgress size={20} />
        ) : (
          <Stack spacing={2}>
            <TextField
              size="small"
              label="Provider"
              value={cfg?.provider ?? 'anthropic'}
              disabled
              helperText="Anthropic Claude is the only supported provider."
            />
            <TextField
              size="small"
              label="Model"
              value={model}
              onChange={(e) => setModel(e.target.value)}
              placeholder="claude-opus-4-7"
              helperText="Recent Claude model IDs: claude-opus-4-7, claude-sonnet-4-6, claude-haiku-4-5-20251001."
            />
            <TextField
              size="small"
              type="password"
              label={cfg?.has_key ? 'Replace API key' : 'API key'}
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="sk-ant-..."
              autoComplete="off"
            />
            <Stack direction="row" spacing={1}>
              <Button
                variant="contained"
                startIcon={busy ? <CircularProgress size={14} /> : <SaveRoundedIcon />}
                onClick={save}
                disabled={busy}
              >
                Save
              </Button>
              <Button variant="outlined" onClick={runTest} disabled={busy}>
                Test connection
              </Button>
              {cfg?.has_key && (
                <Button color="error" onClick={clearKey} disabled={busy}>
                  Clear key
                </Button>
              )}
              {msg && (
                <Typography variant="caption" sx={{ alignSelf: 'center', color: 'text.secondary' }}>
                  {msg}
                </Typography>
              )}
            </Stack>
            {testResult && (
              <Alert severity={testResult.ok ? 'success' : 'error'}>
                {testResult.text}
              </Alert>
            )}
            {cfg?.last_used_at && (
              <Typography variant="caption" color="text.secondary">
                Last used: {new Date(cfg.last_used_at).toLocaleString()} ·{' '}
                status: {cfg.last_status ?? '—'}
              </Typography>
            )}
          </Stack>
        )}
      </CardContent>
    </Card>
  );
}

// ---- Active Directory (LDAP) tab -----------------------------------------

const LDAP_ROLES = [
  { value: 'mssp_readonly', label: 'MSSP read-only' },
  { value: 'mssp_analyst', label: 'MSSP analyst' },
  { value: 'mssp_admin', label: 'MSSP admin' },
];

function LdapTab() {
  const [cfg, setCfg] = useState<LdapConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ ok: boolean; text: string } | null>(null);

  // editable fields
  const [enabled, setEnabled] = useState(false);
  const [host, setHost] = useState('');
  const [bindDn, setBindDn] = useState('');
  const [bindPassword, setBindPassword] = useState('');
  const [searchBase, setSearchBase] = useState('');
  const [filter, setFilter] = useState('');
  const [emailAttr, setEmailAttr] = useState('');
  const [fullNameAttr, setFullNameAttr] = useState('');
  const [defaultRole, setDefaultRole] = useState('mssp_readonly');
  const [startTls, setStartTls] = useState(false);
  const [verifyCert, setVerifyCert] = useState(true);
  const [groupAttr, setGroupAttr] = useState('memberOf');
  const [mappings, setMappings] = useState<{ group: string; role: string }[]>([]);

  // test creds
  const [testUser, setTestUser] = useState('');
  const [testPass, setTestPass] = useState('');

  const apply = useCallback((r: LdapConfig) => {
    setCfg(r);
    setEnabled(r.enabled);
    setHost(r.host ?? '');
    setBindDn(r.bind_dn ?? '');
    setSearchBase(r.user_search_base ?? '');
    setFilter(r.user_filter);
    setEmailAttr(r.email_attr);
    setFullNameAttr(r.full_name_attr);
    setDefaultRole(r.default_role);
    setStartTls(r.start_tls);
    setVerifyCert(r.verify_cert);
    setGroupAttr(r.group_attr);
    setMappings(Object.entries(r.group_mappings ?? {}).map(([group, role]) => ({ group, role })));
  }, []);

  const reload = useCallback(async () => {
    setLoading(true);
    setMsg(null);
    try {
      apply(await getLdapConfig());
    } catch (e: any) {
      setMsg(e?.response?.data?.detail ?? 'failed to load — super-admin token required.');
    } finally {
      setLoading(false);
    }
  }, [apply]);

  useEffect(() => {
    reload();
  }, [reload]);

  async function save() {
    setBusy(true);
    setMsg(null);
    try {
      const r = await patchLdapConfig({
        enabled,
        host: host || undefined,
        bind_dn: bindDn || undefined,
        bind_password: bindPassword || undefined,
        user_search_base: searchBase || undefined,
        user_filter: filter || undefined,
        email_attr: emailAttr || undefined,
        full_name_attr: fullNameAttr || undefined,
        default_role: defaultRole,
        start_tls: startTls,
        verify_cert: verifyCert,
        group_attr: groupAttr || undefined,
        group_mappings: Object.fromEntries(
          mappings.filter((m) => m.group.trim()).map((m) => [m.group.trim(), m.role]),
        ),
      });
      apply(r);
      setBindPassword('');
      setMsg('Saved.');
    } catch (e: any) {
      setMsg(e?.response?.data?.detail ?? 'save failed');
    } finally {
      setBusy(false);
    }
  }

  async function clearBindPassword() {
    setBusy(true);
    try {
      apply(await patchLdapConfig({ clear_bind_password: true }));
      setBindPassword('');
      setMsg('Service-account password cleared.');
    } finally {
      setBusy(false);
    }
  }

  async function runTest() {
    setBusy(true);
    setTestResult(null);
    try {
      const r = await testLdapConfig({
        username: testUser || undefined,
        password: testPass || undefined,
      });
      setTestResult({ ok: r.ok, text: r.message });
    } catch (e: any) {
      setTestResult({ ok: false, text: e?.response?.data?.detail ?? 'test failed' });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardContent>
        <Stack direction="row" alignItems="center" spacing={1} mb={2}>
          <LockPersonRoundedIcon color="primary" />
          <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
            Active Directory / LDAP
          </Typography>
          {cfg?.enabled && (
            <Chip size="small" label="enabled" color="success" variant="outlined" />
          )}
        </Stack>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Authenticate MSSP staff against your directory. At login the app
          tries local passwords first, then binds to LDAP. A directory user
          with no app account yet is created automatically (just-in-time) at
          the default role below. The service-account password is
          Fernet-encrypted at rest and never returned to the client.
        </Typography>

        <Alert severity="info" icon={false} sx={{ mb: 2 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>
            Setup
          </Typography>
          <Box component="ol" sx={{ m: 0, pl: 2.5, '& li': { mb: 0.25 } }}>
            <li>Set <strong>Host</strong> (use <code>ldaps://</code> for TLS).</li>
            <li>Add a read-only <strong>service account</strong> (bind DN + password) so the app can find users.</li>
            <li>Set the <strong>search base</strong> and a <strong>filter</strong> matching how users log in (e.g. <code>(sAMAccountName=&#123;username&#125;)</code>).</li>
            <li>Pick the <strong>default role</strong> for auto-created users.</li>
            <li><strong>Save</strong>, then <strong>Test</strong> with a real account.</li>
            <li>Turn on <strong>Enable LDAP login</strong>.</li>
          </Box>
        </Alert>

        {loading ? (
          <CircularProgress size={20} />
        ) : (
          <Stack spacing={2}>
            <FormControlLabel
              control={<Switch checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />}
              label="Enable LDAP / Active Directory login"
            />
            <TextField
              size="small"
              label="Host"
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="ldaps://dc.corp.local:636"
              helperText="Use ldaps:// for TLS, or ldap:// with StartTLS below."
            />
            <TextField
              size="small"
              label="Service account bind DN (optional)"
              value={bindDn}
              onChange={(e) => setBindDn(e.target.value)}
              placeholder="CN=svc-detectmap,OU=Service,DC=corp,DC=local"
              helperText="Used to search for users. Leave blank to bind directly with the typed identifier (UPN)."
            />
            <TextField
              size="small"
              type="password"
              label={cfg?.has_bind_password ? 'Replace service-account password' : 'Service-account password'}
              value={bindPassword}
              onChange={(e) => setBindPassword(e.target.value)}
              autoComplete="off"
              placeholder={cfg?.has_bind_password ? `(unchanged · ${cfg.bind_password_tail ?? '••••'})` : undefined}
            />
            <TextField
              size="small"
              label="User search base"
              value={searchBase}
              onChange={(e) => setSearchBase(e.target.value)}
              placeholder="OU=Users,DC=corp,DC=local"
            />
            <TextField
              size="small"
              label="User search filter"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="(sAMAccountName={username})"
              helperText="{username} is replaced with the typed identifier (LDAP-escaped). e.g. (userPrincipalName={username}) or (mail={username})."
            />
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
              <TextField
                size="small"
                label="Email attribute"
                value={emailAttr}
                onChange={(e) => setEmailAttr(e.target.value)}
                placeholder="mail"
                sx={{ flex: 1 }}
              />
              <TextField
                size="small"
                label="Full-name attribute"
                value={fullNameAttr}
                onChange={(e) => setFullNameAttr(e.target.value)}
                placeholder="displayName"
                sx={{ flex: 1 }}
              />
              <TextField
                select
                size="small"
                label="Default role (JIT users)"
                value={defaultRole}
                onChange={(e) => setDefaultRole(e.target.value)}
                sx={{ flex: 1 }}
              >
                {LDAP_ROLES.map((r) => (
                  <MenuItem key={r.value} value={r.value}>
                    {r.label}
                  </MenuItem>
                ))}
              </TextField>
            </Stack>
            <Stack direction="row" spacing={3}>
              <FormControlLabel
                control={<Switch checked={startTls} onChange={(e) => setStartTls(e.target.checked)} />}
                label="StartTLS (for ldap://)"
              />
              <FormControlLabel
                control={<Switch checked={verifyCert} onChange={(e) => setVerifyCert(e.target.checked)} />}
                label="Validate server certificate"
              />
            </Stack>

            <Divider />
            <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
              Group → role mapping
            </Typography>
            <Typography variant="caption" color="text.secondary" sx={{ mt: -1 }}>
              Auto-assign roles from directory group membership. A mapping
              matches if its text appears in any of the user&apos;s groups (full
              DN or a fragment like <code>SOC-Admins</code>). Highest-privilege
              match wins; users in no mapped group get the default role above.
            </Typography>
            <TextField
              size="small"
              label="Group membership attribute"
              value={groupAttr}
              onChange={(e) => setGroupAttr(e.target.value)}
              placeholder="memberOf"
              sx={{ maxWidth: 320 }}
            />
            <Stack spacing={1}>
              {mappings.map((m, i) => (
                <Stack key={i} direction={{ xs: 'column', sm: 'row' }} spacing={1.5} alignItems="center">
                  <TextField
                    size="small"
                    label="Group (DN or fragment)"
                    value={m.group}
                    onChange={(e) =>
                      setMappings((arr) => arr.map((x, j) => (j === i ? { ...x, group: e.target.value } : x)))
                    }
                    sx={{ flex: 2 }}
                  />
                  <TextField
                    select
                    size="small"
                    label="Role"
                    value={m.role}
                    onChange={(e) =>
                      setMappings((arr) => arr.map((x, j) => (j === i ? { ...x, role: e.target.value } : x)))
                    }
                    sx={{ flex: 1, minWidth: 160 }}
                  >
                    {LDAP_ROLES.map((r) => <MenuItem key={r.value} value={r.value}>{r.label}</MenuItem>)}
                  </TextField>
                  <Button color="error" size="small" onClick={() => setMappings((arr) => arr.filter((_, j) => j !== i))}>
                    Remove
                  </Button>
                </Stack>
              ))}
              <Box>
                <Button size="small" onClick={() => setMappings((arr) => [...arr, { group: '', role: 'mssp_readonly' }])}>
                  + Add mapping
                </Button>
              </Box>
            </Stack>

            <Stack direction="row" spacing={1}>
              <Button
                variant="contained"
                startIcon={busy ? <CircularProgress size={14} /> : <SaveRoundedIcon />}
                onClick={save}
                disabled={busy}
              >
                Save
              </Button>
              {cfg?.has_bind_password && (
                <Button color="error" onClick={clearBindPassword} disabled={busy}>
                  Clear service password
                </Button>
              )}
              {msg && (
                <Typography variant="caption" sx={{ alignSelf: 'center', color: 'text.secondary' }}>
                  {msg}
                </Typography>
              )}
            </Stack>

            <Divider />
            <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
              Test connection
            </Typography>
            <Typography variant="caption" color="text.secondary" sx={{ mt: -1 }}>
              Save first, then test. Leave the fields blank to check
              connectivity only, or enter a directory user&apos;s credentials to
              verify a full bind.
            </Typography>
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
              <TextField
                size="small"
                label="Test username"
                value={testUser}
                onChange={(e) => setTestUser(e.target.value)}
                autoComplete="off"
                sx={{ flex: 1 }}
              />
              <TextField
                size="small"
                type="password"
                label="Test password"
                value={testPass}
                onChange={(e) => setTestPass(e.target.value)}
                autoComplete="off"
                sx={{ flex: 1 }}
              />
              <Button variant="outlined" onClick={runTest} disabled={busy}>
                Test
              </Button>
            </Stack>
            {testResult && (
              <Alert severity={testResult.ok ? 'success' : 'error'}>{testResult.text}</Alert>
            )}
          </Stack>
        )}
      </CardContent>
    </Card>
  );
}

// ---- Mail server (SMTP) tab ----------------------------------------------

function MailTab() {
  const [cfg, setCfg] = useState<MailConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ ok: boolean; text: string } | null>(null);

  // editable fields
  const [enabled, setEnabled] = useState(false);
  const [host, setHost] = useState('');
  const [port, setPort] = useState(587);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [fromAddress, setFromAddress] = useState('');
  const [fromName, setFromName] = useState('');
  const [useTls, setUseTls] = useState(true);
  const [useSsl, setUseSsl] = useState(false);

  const [testTo, setTestTo] = useState('');

  const apply = useCallback((r: MailConfig) => {
    setCfg(r);
    setEnabled(r.enabled);
    setHost(r.host ?? '');
    setPort(r.port);
    setUsername(r.username ?? '');
    setFromAddress(r.from_address ?? '');
    setFromName(r.from_name);
    setUseTls(r.use_tls);
    setUseSsl(r.use_ssl);
  }, []);

  const reload = useCallback(async () => {
    setLoading(true);
    setMsg(null);
    try {
      apply(await getMailConfig());
    } catch (e: any) {
      setMsg(e?.response?.data?.detail ?? 'failed to load — super-admin token required.');
    } finally {
      setLoading(false);
    }
  }, [apply]);

  useEffect(() => {
    reload();
  }, [reload]);

  async function save() {
    setBusy(true);
    setMsg(null);
    try {
      const r = await patchMailConfig({
        enabled,
        host: host || undefined,
        port,
        username: username || undefined,
        password: password || undefined,
        from_address: fromAddress || undefined,
        from_name: fromName || undefined,
        use_tls: useTls,
        use_ssl: useSsl,
      });
      apply(r);
      setPassword('');
      setMsg('Saved.');
    } catch (e: any) {
      setMsg(e?.response?.data?.detail ?? 'save failed');
    } finally {
      setBusy(false);
    }
  }

  async function clearPassword() {
    setBusy(true);
    try {
      apply(await patchMailConfig({ clear_password: true }));
      setPassword('');
      setMsg('SMTP password cleared.');
    } finally {
      setBusy(false);
    }
  }

  async function runTest() {
    setBusy(true);
    setTestResult(null);
    try {
      const r = await testMailConfig({ to: testTo || undefined });
      setTestResult({ ok: r.ok, text: r.message });
    } catch (e: any) {
      setTestResult({ ok: false, text: e?.response?.data?.detail ?? 'test failed' });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardContent>
        <Stack direction="row" alignItems="center" spacing={1} mb={2}>
          <MailOutlineRoundedIcon color="primary" />
          <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
            Mail server (SMTP)
          </Typography>
          {cfg?.enabled && (
            <Chip size="small" label="enabled" color="success" variant="outlined" />
          )}
        </Stack>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Outbound email for test messages and (later) report delivery and
          notifications. The SMTP password is Fernet-encrypted at rest and
          never returned to the client.
        </Typography>

        <Alert severity="info" icon={false} sx={{ mb: 2 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>
            Setup
          </Typography>
          <Box component="ol" sx={{ m: 0, pl: 2.5, '& li': { mb: 0.25 } }}>
            <li>Enter your SMTP <strong>host</strong> and <strong>port</strong> (587 for STARTTLS, 465 for SSL).</li>
            <li>Add the <strong>username + password</strong> if your server requires authentication.</li>
            <li>Set the <strong>from address</strong> (and optional display name) recipients will see.</li>
            <li>Pick the encryption: <strong>STARTTLS</strong> (port 587) or <strong>implicit SSL</strong> (port 465).</li>
            <li><strong>Save</strong>, then send a <strong>test email</strong> to confirm.</li>
            <li>Turn on <strong>Enable mail sending</strong>.</li>
          </Box>
        </Alert>

        {loading ? (
          <CircularProgress size={20} />
        ) : (
          <Stack spacing={2}>
            <FormControlLabel
              control={<Switch checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />}
              label="Enable mail sending"
            />
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
              <TextField
                size="small"
                label="SMTP host"
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="smtp.corp.local"
                sx={{ flex: 2 }}
              />
              <TextField
                size="small"
                type="number"
                label="Port"
                value={port}
                onChange={(e) => setPort(Math.max(1, Math.min(65535, Number(e.target.value) || 0)))}
                sx={{ width: 120 }}
              />
            </Stack>
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
              <TextField
                size="small"
                label="Username (optional)"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="off"
                sx={{ flex: 1 }}
              />
              <TextField
                size="small"
                type="password"
                label={cfg?.has_password ? 'Replace password' : 'Password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="off"
                placeholder={cfg?.has_password ? `(unchanged · ${cfg.password_tail ?? '••••'})` : undefined}
                sx={{ flex: 1 }}
              />
            </Stack>
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
              <TextField
                size="small"
                label="From address"
                value={fromAddress}
                onChange={(e) => setFromAddress(e.target.value)}
                placeholder="detectmap@corp.local"
                helperText="Falls back to the username if blank."
                sx={{ flex: 1 }}
              />
              <TextField
                size="small"
                label="From name"
                value={fromName}
                onChange={(e) => setFromName(e.target.value)}
                placeholder="The Detection Map"
                sx={{ flex: 1 }}
              />
            </Stack>
            <Stack direction="row" spacing={3}>
              <FormControlLabel
                control={
                  <Switch
                    checked={useTls}
                    onChange={(e) => {
                      setUseTls(e.target.checked);
                      if (e.target.checked) setUseSsl(false);
                    }}
                  />
                }
                label="STARTTLS (port 587)"
              />
              <FormControlLabel
                control={
                  <Switch
                    checked={useSsl}
                    onChange={(e) => {
                      setUseSsl(e.target.checked);
                      if (e.target.checked) setUseTls(false);
                    }}
                  />
                }
                label="Implicit SSL (port 465)"
              />
            </Stack>

            <Stack direction="row" spacing={1}>
              <Button
                variant="contained"
                startIcon={busy ? <CircularProgress size={14} /> : <SaveRoundedIcon />}
                onClick={save}
                disabled={busy}
              >
                Save
              </Button>
              {cfg?.has_password && (
                <Button color="error" onClick={clearPassword} disabled={busy}>
                  Clear password
                </Button>
              )}
              {msg && (
                <Typography variant="caption" sx={{ alignSelf: 'center', color: 'text.secondary' }}>
                  {msg}
                </Typography>
              )}
            </Stack>

            <Divider />
            <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
              Send test email
            </Typography>
            <Typography variant="caption" color="text.secondary" sx={{ mt: -1 }}>
              Save first, then send. Leave the recipient blank to send to your
              own super-admin address.
            </Typography>
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
              <TextField
                size="small"
                label="Recipient (optional)"
                value={testTo}
                onChange={(e) => setTestTo(e.target.value)}
                autoComplete="off"
                sx={{ flex: 1 }}
              />
              <Button variant="outlined" onClick={runTest} disabled={busy}>
                Send test
              </Button>
            </Stack>
            {testResult && (
              <Alert severity={testResult.ok ? 'success' : 'error'}>{testResult.text}</Alert>
            )}
          </Stack>
        )}
      </CardContent>
    </Card>
  );
}

// ---- Schedule tab --------------------------------------------------------

function ScheduleTab() {
  const [sched, setSched] = useState<CatalogSchedule | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setMsg(null);
    try {
      const r = await getCatalogSchedule();
      setSched(r);
    } catch (e: any) {
      setMsg(e?.response?.data?.detail ?? 'failed to load schedule');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  async function toggle(key: keyof CatalogSchedule, value: boolean) {
    if (!sched) return;
    setBusy(true);
    try {
      const r = await patchCatalogSchedule({ [key]: value } as any);
      setSched(r);
    } catch (e: any) {
      setMsg(e?.response?.data?.detail ?? 'patch failed (super-admin only)');
    } finally {
      setBusy(false);
    }
  }

  async function runD3FENDNow() {
    setBusy(true);
    try {
      await refreshD3FENDCatalog(false);
      setMsg('D3FEND refresh queued.');
    } catch (e: any) {
      setMsg(e?.response?.data?.detail ?? 'queue failed (super-admin only)');
    } finally {
      setBusy(false);
    }
  }

  if (loading) return <CircularProgress />;
  if (!sched) {
    return <Alert severity="info">{msg ?? 'Schedule unavailable (super-admin only).'}</Alert>;
  }

  return (
    <Card>
      <CardContent>
        <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
          Scheduled catalog refresh
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          When enabled, celerybeat fires the corresponding refresh on a
          fixed cadence (daily for ATT&amp;CK and SigmaHQ, weekly for
          D3FEND). The cron strings below are informational — the schedule
          itself is owned by the worker.
        </Typography>
        {msg && (
          <Alert severity="info" sx={{ mb: 2 }}>
            {msg}
          </Alert>
        )}
        <Stack spacing={2}>
          {(
            [
              {
                key: 'attack_refresh_enabled' as const,
                cron: sched.attack_refresh_cron,
                label: 'ATT&CK catalog (Enterprise / ICS / Mobile)',
                cadence: 'daily',
                job: 'attack',
              },
              {
                key: 'sigmahq_refresh_enabled' as const,
                cron: sched.sigmahq_refresh_cron,
                label: 'SigmaHQ public ruleset',
                cadence: 'daily',
                job: 'sigmahq',
              },
              {
                key: 'd3fend_refresh_enabled' as const,
                cron: sched.d3fend_refresh_cron,
                label: 'D3FEND defensive techniques',
                cadence: 'weekly',
                job: 'd3fend',
              },
              {
                key: 'snapshot_refresh_enabled' as const,
                cron: '—',
                label: 'Coverage snapshots (posture trend, all active customers)',
                cadence: 'daily',
                job: 'snapshot',
              },
            ] as const
          ).map((row) => {
            const lastRun = sched.last_runs?.[row.job];
            const statusColor =
              lastRun?.status === 'ok'
                ? 'success'
                : lastRun?.status === 'error'
                  ? 'error'
                  : 'default';
            return (
              <Paper key={row.key} variant="outlined" sx={{ p: 2 }}>
                <Stack direction="row" alignItems="center" spacing={2}>
                  <Box sx={{ flex: 1 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                      {row.label}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      Auto-refresh {row.cadence}. Nominal cron:{' '}
                      <code style={{ fontFamily: 'JetBrains Mono, monospace' }}>
                        {row.cron}
                      </code>
                    </Typography>
                    <Box sx={{ mt: 0.5 }}>
                      {lastRun ? (
                        <Stack direction="row" spacing={1} alignItems="center">
                          <Chip
                            size="small"
                            label={lastRun.status}
                            color={statusColor as any}
                            variant="outlined"
                            sx={{ height: 18, fontSize: '0.6rem', textTransform: 'uppercase' }}
                          />
                          <Typography variant="caption" color="text.secondary">
                            last ran {new Date(lastRun.ran_at).toLocaleString()}
                            {lastRun.detail ? ` · ${lastRun.detail}` : ''}
                          </Typography>
                        </Stack>
                      ) : (
                        <Typography variant="caption" color="text.secondary">
                          never run by the scheduler
                        </Typography>
                      )}
                    </Box>
                  </Box>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={Boolean(sched[row.key])}
                        onChange={(e) => toggle(row.key, e.target.checked)}
                        disabled={busy}
                      />
                    }
                    label={sched[row.key] ? 'On' : 'Off'}
                  />
                </Stack>
              </Paper>
            );
          })}
        </Stack>
        <Divider sx={{ my: 2 }} />
        <Stack direction="row" spacing={1} alignItems="center">
          <Typography variant="body2" color="text.secondary" sx={{ flex: 1 }}>
            Need D3FEND populated right now? Run it on-demand:
          </Typography>
          <Button variant="outlined" onClick={runD3FENDNow} disabled={busy}>
            Refresh D3FEND now
          </Button>
        </Stack>
      </CardContent>
    </Card>
  );
}

// MSSP portal staff only. Customer-pinned (tenant-only) users are managed
// per-customer under the Customers page so the MSSP roster stays tidy.
const USER_ROLES = [
  { value: 'mssp_admin', label: 'MSSP admin' },
  { value: 'mssp_analyst', label: 'MSSP analyst' },
  { value: 'mssp_readonly', label: 'MSSP read-only' },
];

function UsersTab({ onGoToRoles }: { onGoToRoles: () => void }) {
  const [users, setUsers] = useState<SettingsUserOut[]>([]);
  const [customRoles, setCustomRoles] = useState<CustomRole[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  // add-user form (MSSP staff only — customer users live on the Customers page)
  const [showAdd, setShowAdd] = useState(false);
  const [nEmail, setNEmail] = useState('');
  const [nName, setNName] = useState('');
  const [nPass, setNPass] = useState('');
  const [nRole, setNRole] = useState('mssp_readonly');
  const [nCustomRole, setNCustomRole] = useState('');
  const [adding, setAdding] = useState(false);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setUsers(await listSettingsUsers());
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'failed to load users');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    reload();
    listCustomRoles().then(setCustomRoles).catch(() => {});
  }, [reload]);

  async function addUser() {
    setAdding(true);
    setError(null);
    try {
      await createSettingsUser({
        email: nEmail,
        password: nPass,
        role: nRole,
        full_name: nName || undefined,
        custom_role_id: nCustomRole || undefined,
      });
      setShowAdd(false);
      setNEmail(''); setNName(''); setNPass(''); setNRole('mssp_readonly');
      setNCustomRole('');
      reload();
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'failed to create user');
    } finally {
      setAdding(false);
    }
  }

  async function patchUser(id: string, payload: Parameters<typeof updateSettingsUser>[1]) {
    setBusyId(id);
    setError(null);
    try {
      await updateSettingsUser(id, payload);
      reload();
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'update failed');
    } finally {
      setBusyId(null);
    }
  }

  async function removeUser(id: string, email: string) {
    if (!confirm(`Delete ${email}? This cannot be undone.`)) return;
    setBusyId(id);
    try {
      await deleteSettingsUser(id);
      reload();
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'delete failed');
    } finally {
      setBusyId(null);
    }
  }

  return (
    <Card>
      <CardContent>
        <Stack direction="row" alignItems="center" spacing={1} mb={1}>
          <Box sx={{ flex: 1 }}>
            <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
              MSSP staff in this organisation
            </Typography>
            <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>
              Customer-pinned users (tenant access only) are managed under each
              customer on the Customers page.
            </Typography>
          </Box>
          <Button size="small" variant="contained" onClick={() => setShowAdd((v) => !v)}>
            {showAdd ? 'Cancel' : 'Add MSSP user'}
          </Button>
        </Stack>

        {error && <Alert severity="error" sx={{ mb: 1 }}>{error}</Alert>}

        {showAdd && (
          <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
            <Stack spacing={1.5}>
              <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5}>
                <TextField size="small" label="Email" value={nEmail} onChange={(e) => setNEmail(e.target.value)} sx={{ flex: 1 }} />
                <TextField size="small" label="Full name (optional)" value={nName} onChange={(e) => setNName(e.target.value)} sx={{ flex: 1 }} />
              </Stack>
              <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5}>
                <TextField size="small" type="password" label="Temporary password" value={nPass} onChange={(e) => setNPass(e.target.value)} sx={{ flex: 1 }} helperText="At least 8 characters" />
                <TextField select size="small" label="Role" value={nRole} onChange={(e) => setNRole(e.target.value)} sx={{ flex: 1 }}>
                  {USER_ROLES.map((r) => <MenuItem key={r.value} value={r.value}>{r.label}</MenuItem>)}
                </TextField>
              </Stack>
              {customRoles.length > 0 && (
                <TextField
                  select
                  size="small"
                  label="Custom role (optional override)"
                  value={nCustomRole}
                  onChange={(e) => setNCustomRole(e.target.value)}
                  helperText="If set, the user's effective permissions come from this role instead of the built-in role above."
                  sx={{ maxWidth: 360 }}
                >
                  <MenuItem value="">— none —</MenuItem>
                  {customRoles.map((cr) => (
                    <MenuItem key={cr.id} value={cr.id}>
                      {cr.label}
                    </MenuItem>
                  ))}
                </TextField>
              )}
              <Box>
                <Button variant="contained" onClick={addUser} disabled={adding || !nEmail || nPass.length < 8}>
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
        ) : (
          <>
            {customRoles.length === 0 && (
              <Alert
                severity="info"
                sx={{ mb: 2 }}
                action={
                  <Button color="inherit" size="small" onClick={onGoToRoles}>
                    Open Roles &amp; permissions
                  </Button>
                }
              >
                The <strong>custom role override</strong> column is greyed out
                because no custom roles have been defined yet. Built-in roles
                are a fixed permission baseline; create a custom role to grant
                a user a non-standard permission set (e.g. analyst with
                connector management).
              </Alert>
            )}
          <Paper variant="outlined" sx={{ overflow: 'hidden' }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Email</TableCell>
                  <TableCell sx={{ width: 170 }}>Built-in role</TableCell>
                  <TableCell sx={{ width: 200 }}>Custom role override</TableCell>
                  <TableCell sx={{ width: 90 }}>Active</TableCell>
                  <TableCell sx={{ width: 170 }}>Last login</TableCell>
                  <TableCell sx={{ width: 80 }} />
                </TableRow>
              </TableHead>
              <TableBody>
                {users.map((u) => {
                  // The bootstrap-seeded primary admin is locked against
                  // role/custom-role/deactivate/delete edits so the MSSP
                  // org cannot be left without an administrator. Password
                  // resets still work for them via the regular flow.
                  const locked = u.is_primary;
                  const lockTip = 'Primary administrator — locked to prevent the MSSP being left without an admin';
                  return (
                    <TableRow key={u.id} hover>
                      <TableCell>
                        <Stack direction="row" spacing={1} alignItems="center">
                          <span>{u.email}</span>
                          {u.is_primary && (
                            <Tooltip title={lockTip}>
                              <Chip
                                size="small"
                                label="Primary"
                                color="primary"
                                variant="outlined"
                                icon={<LockRoundedIcon sx={{ fontSize: 14 }} />}
                              />
                            </Tooltip>
                          )}
                        </Stack>
                      </TableCell>
                      <TableCell>
                        <Tooltip title={locked ? lockTip : ''} disableHoverListener={!locked}>
                          <span>
                            <TextField
                              select
                              size="small"
                              value={u.role}
                              disabled={busyId === u.id || locked}
                              onChange={(e) => patchUser(u.id, { role: e.target.value })}
                              variant="standard"
                              sx={{ minWidth: 150 }}
                            >
                              {USER_ROLES.map((r) => <MenuItem key={r.value} value={r.value}>{r.label}</MenuItem>)}
                            </TextField>
                          </span>
                        </Tooltip>
                      </TableCell>
                      <TableCell>
                        {(() => {
                          const noCustomRoles = customRoles.length === 0;
                          const overrideTip = locked
                            ? lockTip
                            : noCustomRoles
                              ? 'No custom roles defined yet — create one under Roles & permissions to enable overrides.'
                              : '';
                          return (
                        <Tooltip title={overrideTip} disableHoverListener={!overrideTip}>
                          <span>
                            <TextField
                              select
                              size="small"
                              // Empty string sentinel → backend interprets as "clear override".
                              value={u.custom_role_id ?? ''}
                              disabled={busyId === u.id || noCustomRoles || locked}
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
                          </span>
                        </Tooltip>
                          );
                        })()}
                      </TableCell>
                      <TableCell>
                        <Tooltip title={locked ? lockTip : ''} disableHoverListener={!locked}>
                          <span>
                            <Switch
                              size="small"
                              checked={u.is_active}
                              disabled={busyId === u.id || locked}
                              onChange={(e) => patchUser(u.id, { is_active: e.target.checked })}
                            />
                          </span>
                        </Tooltip>
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption" color="text.secondary">
                          {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : '—'}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Tooltip title={locked ? lockTip : ''} disableHoverListener={!locked}>
                          <span>
                            <Button
                              size="small"
                              color="error"
                              disabled={busyId === u.id || locked}
                              onClick={() => removeUser(u.id, u.email)}
                            >
                              Delete
                            </Button>
                          </span>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </Paper>
          </>
        )}
      </CardContent>
    </Card>
  );
}

// ---- Roles & permissions tab ---------------------------------------------

function RolesTab() {
  const [perms, setPerms] = useState<PermissionMeta[]>([]);
  const [builtin, setBuiltin] = useState<BuiltinRole[]>([]);
  const [custom, setCustom] = useState<CustomRole[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<CustomRole | null>(null);
  const [creating, setCreating] = useState(false);
  const [busy, setBusy] = useState(false);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [p, b, c] = await Promise.all([
        listPermissionCatalog(),
        listBuiltinRoles(),
        listCustomRoles(),
      ]);
      setPerms(p);
      setBuiltin(b);
      setCustom(c);
    } catch (e: any) {
      setError(
        e?.response?.data?.detail ??
          'failed to load roles — you need the manage-users permission for this page.',
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  async function handleDelete(role: CustomRole) {
    if (
      !confirm(
        `Delete custom role "${role.label}"? Any user with this override ` +
          `will revert to their built-in role.`,
      )
    )
      return;
    setBusy(true);
    try {
      await deleteCustomRole(role.id);
      await reload();
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'delete failed');
    } finally {
      setBusy(false);
    }
  }

  const permsByCategory = useMemo(() => {
    const out: Record<string, PermissionMeta[]> = {};
    for (const p of perms) {
      (out[p.category] ??= []).push(p);
    }
    return out;
  }, [perms]);

  return (
    <Stack spacing={2}>
      <Card>
        <CardContent>
          <Stack direction="row" alignItems="center" spacing={1} mb={1}>
            <AdminPanelSettingsRoundedIcon color="primary" />
            <Typography
              variant="overline"
              sx={{ fontWeight: 700, color: 'text.secondary', flex: 1 }}
            >
              Roles &amp; permissions
            </Typography>
            <Button
              size="small"
              variant="contained"
              startIcon={<AddRoundedIcon />}
              onClick={() => setCreating(true)}
              disabled={loading || busy}
            >
              New custom role
            </Button>
          </Stack>
          <Typography variant="body2" color="text.secondary">
            Built-in roles are the safe baseline and cannot be edited.
            Custom roles let you define an arbitrary permission set for
            users in this MSSP organisation; assigning a custom role to a
            user overrides the built-in role&apos;s permissions for them.
          </Typography>
          {error && (
            <Alert severity="error" sx={{ mt: 1.5 }}>
              {error}
            </Alert>
          )}
        </CardContent>
      </Card>

      {loading ? (
        <Box sx={{ py: 4, display: 'flex', justifyContent: 'center' }}>
          <CircularProgress />
        </Box>
      ) : (
        <>
          {/* Custom roles list */}
          {custom.length > 0 && (
            <Card>
              <CardContent>
                <Typography
                  variant="overline"
                  sx={{ fontWeight: 700, color: 'text.secondary' }}
                >
                  Custom roles ({custom.length})
                </Typography>
                <Paper variant="outlined" sx={{ overflow: 'hidden', mt: 1 }}>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Label</TableCell>
                        <TableCell sx={{ width: 180 }}>Key</TableCell>
                        <TableCell sx={{ width: 110 }} align="right">
                          Permissions
                        </TableCell>
                        <TableCell>Description</TableCell>
                        <TableCell sx={{ width: 140 }} />
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {custom.map((cr) => (
                        <TableRow key={cr.id} hover>
                          <TableCell sx={{ fontWeight: 600 }}>{cr.label}</TableCell>
                          <TableCell
                            sx={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.78rem' }}
                          >
                            {cr.key}
                          </TableCell>
                          <TableCell align="right">
                            <Chip
                              size="small"
                              label={cr.permissions.length}
                              variant="outlined"
                            />
                          </TableCell>
                          <TableCell>
                            <Typography variant="caption" color="text.secondary">
                              {cr.description ?? '—'}
                            </Typography>
                          </TableCell>
                          <TableCell align="right">
                            <Stack direction="row" spacing={0.5} justifyContent="flex-end">
                              <IconButton
                                size="small"
                                onClick={() => setEditing(cr)}
                                disabled={busy}
                              >
                                <EditRoundedIcon fontSize="small" />
                              </IconButton>
                              <IconButton
                                size="small"
                                color="error"
                                onClick={() => handleDelete(cr)}
                                disabled={busy}
                              >
                                <DeleteOutlineRoundedIcon fontSize="small" />
                              </IconButton>
                            </Stack>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </Paper>
              </CardContent>
            </Card>
          )}

          {/* Built-in roles — read-only matrix */}
          <Card>
            <CardContent>
              <Stack direction="row" alignItems="center" spacing={1} mb={1}>
                <LockRoundedIcon fontSize="small" color="action" />
                <Typography
                  variant="overline"
                  sx={{ fontWeight: 700, color: 'text.secondary' }}
                >
                  Built-in roles (read-only baseline)
                </Typography>
              </Stack>
              <PermissionMatrix
                roles={builtin.map((b) => ({
                  key: b.key,
                  label: b.label.replace(/_/g, ' '),
                  permissions: new Set(b.permissions),
                  readOnly: true,
                }))}
                permsByCategory={permsByCategory}
              />
            </CardContent>
          </Card>
        </>
      )}

      <RoleEditorDialog
        open={creating || editing != null}
        onClose={() => {
          setCreating(false);
          setEditing(null);
        }}
        onSaved={async () => {
          setCreating(false);
          setEditing(null);
          await reload();
        }}
        permsByCategory={permsByCategory}
        existing={editing}
      />
    </Stack>
  );
}

function PermissionMatrix({
  roles,
  permsByCategory,
}: {
  roles: { key: string; label: string; permissions: Set<string>; readOnly?: boolean }[];
  permsByCategory: Record<string, PermissionMeta[]>;
}) {
  const categories = Object.keys(permsByCategory).sort();
  return (
    <Paper variant="outlined" sx={{ overflow: 'auto', mt: 1 }}>
      <Table size="small" sx={{ minWidth: 720 }}>
        <TableHead>
          <TableRow>
            <TableCell sx={{ width: 280 }}>Permission</TableCell>
            {roles.map((r) => (
              <TableCell
                key={r.key}
                align="center"
                sx={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.7rem' }}
              >
                {r.label}
              </TableCell>
            ))}
          </TableRow>
        </TableHead>
        <TableBody>
          {categories.map((cat) => (
            <React.Fragment key={cat}>
              <TableRow>
                <TableCell
                  colSpan={roles.length + 1}
                  sx={{
                    bgcolor: 'action.hover',
                    fontWeight: 700,
                    fontSize: '0.72rem',
                    textTransform: 'uppercase',
                    letterSpacing: '0.08em',
                    color: 'text.secondary',
                  }}
                >
                  {cat}
                </TableCell>
              </TableRow>
              {permsByCategory[cat].map((p) => (
                <TableRow key={p.key} hover>
                  <TableCell>
                    <Tooltip title={p.description} arrow placement="right">
                      <Box>
                        <Typography variant="body2" sx={{ fontWeight: 500 }}>
                          {p.label}
                        </Typography>
                        <Typography
                          variant="caption"
                          color="text.secondary"
                          sx={{ fontFamily: 'JetBrains Mono, monospace' }}
                        >
                          {p.key}
                        </Typography>
                      </Box>
                    </Tooltip>
                  </TableCell>
                  {roles.map((r) => (
                    <TableCell key={r.key} align="center">
                      {r.permissions.has(p.key) ? (
                        <Box
                          component="span"
                          sx={{
                            display: 'inline-block',
                            width: 14,
                            height: 14,
                            borderRadius: '50%',
                            bgcolor: 'success.main',
                          }}
                        />
                      ) : (
                        <Box
                          component="span"
                          sx={{
                            display: 'inline-block',
                            width: 14,
                            height: 14,
                            borderRadius: '50%',
                            border: 1,
                            borderColor: 'divider',
                          }}
                        />
                      )}
                    </TableCell>
                  ))}
                </TableRow>
              ))}
            </React.Fragment>
          ))}
        </TableBody>
      </Table>
    </Paper>
  );
}

function RoleEditorDialog({
  open,
  onClose,
  onSaved,
  permsByCategory,
  existing,
}: {
  open: boolean;
  onClose: () => void;
  onSaved: () => Promise<void>;
  permsByCategory: Record<string, PermissionMeta[]>;
  existing: CustomRole | null;
}) {
  const [key, setKey] = useState('');
  const [label, setLabel] = useState('');
  const [description, setDescription] = useState('');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    if (existing) {
      setKey(existing.key);
      setLabel(existing.label);
      setDescription(existing.description ?? '');
      setSelected(new Set(existing.permissions));
    } else {
      setKey('');
      setLabel('');
      setDescription('');
      setSelected(new Set());
    }
    setError(null);
  }, [open, existing]);

  const togglePermission = (k: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });
  };

  const toggleCategory = (cat: string) => {
    const catKeys = (permsByCategory[cat] ?? []).map((p) => p.key);
    const allSelected = catKeys.every((k) => selected.has(k));
    setSelected((prev) => {
      const next = new Set(prev);
      if (allSelected) catKeys.forEach((k) => next.delete(k));
      else catKeys.forEach((k) => next.add(k));
      return next;
    });
  };

  async function save() {
    setBusy(true);
    setError(null);
    try {
      if (existing) {
        await updateCustomRole(existing.id, {
          label,
          description,
          permissions: Array.from(selected),
        });
      } else {
        await createCustomRole({
          key,
          label,
          description: description || undefined,
          permissions: Array.from(selected),
        });
      }
      await onSaved();
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'save failed');
    } finally {
      setBusy(false);
    }
  }

  if (!open) return null;
  const categories = Object.keys(permsByCategory).sort();

  return (
    <Drawer
      anchor="right"
      open={open}
      onClose={onClose}
      PaperProps={{ sx: { width: { xs: '100%', md: 520 }, p: 3 } }}
    >
      <Stack direction="row" alignItems="center" spacing={1} mb={2}>
        <Typography
          variant="overline"
          sx={{ fontWeight: 700, color: 'text.secondary', flex: 1 }}
        >
          {existing ? `Edit role · ${existing.key}` : 'New custom role'}
        </Typography>
        <IconButton size="small" onClick={onClose}>
          <CloseRoundedIcon fontSize="small" />
        </IconButton>
      </Stack>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      <Stack spacing={2}>
        <TextField
          size="small"
          label="Key"
          value={key}
          onChange={(e) => setKey(e.target.value)}
          disabled={!!existing}
          helperText="Lowercase, letters/digits/underscores, 2-59 chars. Immutable after creation."
        />
        <TextField
          size="small"
          label="Label"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
        />
        <TextField
          size="small"
          multiline
          minRows={2}
          maxRows={4}
          label="Description (optional)"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />

        <Divider />
        <Stack direction="row" alignItems="baseline" spacing={1}>
          <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
            Permissions
          </Typography>
          <Typography variant="caption" color="text.secondary">
            {selected.size} selected
          </Typography>
        </Stack>

        {categories.map((cat) => {
          const items = permsByCategory[cat] ?? [];
          const allOn = items.every((p) => selected.has(p.key));
          const someOn = items.some((p) => selected.has(p.key));
          return (
            <Box key={cat}>
              <Stack direction="row" alignItems="center" spacing={1} mb={0.5}>
                <Switch
                  size="small"
                  checked={allOn}
                  onChange={() => toggleCategory(cat)}
                  // ts-ignore: indeterminate isn't on Switch but we approximate via opacity.
                  sx={{ opacity: !allOn && someOn ? 0.7 : 1 }}
                />
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: 'text.secondary' }}>
                  {cat}
                </Typography>
              </Stack>
              <Stack spacing={0.5} sx={{ pl: 3 }}>
                {items.map((p) => (
                  <FormControlLabel
                    key={p.key}
                    control={
                      <Switch
                        size="small"
                        checked={selected.has(p.key)}
                        onChange={() => togglePermission(p.key)}
                      />
                    }
                    label={
                      <Box>
                        <Typography variant="body2">{p.label}</Typography>
                        <Typography variant="caption" color="text.secondary">
                          {p.description}
                        </Typography>
                      </Box>
                    }
                  />
                ))}
              </Stack>
            </Box>
          );
        })}

        <Stack direction="row" spacing={1} sx={{ mt: 1 }}>
          <Button
            variant="contained"
            startIcon={busy ? <CircularProgress size={14} /> : <SaveRoundedIcon />}
            onClick={save}
            disabled={busy || !label.trim() || (!existing && !key.trim())}
          >
            {existing ? 'Save changes' : 'Create role'}
          </Button>
          <Button variant="text" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
        </Stack>
      </Stack>
    </Drawer>
  );
}

function AuditTab() {
  const [rows, setRows] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    listAudit(200)
      .then(setRows)
      .catch((e) => setError(e?.response?.data?.detail ?? 'failed to load audit log'))
      .finally(() => setLoading(false));
  }, []);

  return (
    <Card>
      <CardContent>
        <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
          Audit log
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Recent admin and settings changes (configuration, user management).
        </Typography>
        {error && <Alert severity="error" sx={{ mb: 1 }}>{error}</Alert>}
        {loading ? (
          <Box sx={{ py: 4, display: 'flex', justifyContent: 'center' }}>
            <CircularProgress />
          </Box>
        ) : rows.length === 0 ? (
          <Typography variant="body2" color="text.secondary">No audit entries yet.</Typography>
        ) : (
          <Paper variant="outlined" sx={{ overflow: 'hidden' }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ width: 180 }}>When</TableCell>
                  <TableCell sx={{ width: 200 }}>Actor</TableCell>
                  <TableCell sx={{ width: 170 }}>Action</TableCell>
                  <TableCell>Detail</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {rows.map((r) => (
                  <TableRow key={r.id} hover>
                    <TableCell>
                      <Typography variant="caption" color="text.secondary">
                        {r.at ? new Date(r.at).toLocaleString() : '—'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption">{r.actor_email ?? '—'}</Typography>
                      {r.actor_kind === 'superadmin' && (
                        <Chip label="super" size="small" variant="outlined" sx={{ ml: 0.5, height: 16, fontSize: '0.6rem' }} />
                      )}
                    </TableCell>
                    <TableCell>
                      <Chip label={r.action} size="small" variant="outlined" />
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption" color="text.secondary">
                        {[r.target, r.detail].filter(Boolean).join(' · ') || '—'}
                      </Typography>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Paper>
        )}
      </CardContent>
    </Card>
  );
}
