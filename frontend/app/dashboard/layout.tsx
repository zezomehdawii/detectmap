'use client';

import { useEffect, useRef, useState } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  AppBar,
  Avatar,
  Box,
  Breadcrumbs,
  Button,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  Drawer,
  FormControlLabel,
  IconButton,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  ListSubheader,
  Menu,
  MenuItem,
  Stack,
  Switch,
  TextField,
  Toolbar,
  Tooltip,
  Typography,
} from '@mui/material';
import SearchRoundedIcon from '@mui/icons-material/SearchRounded';
import NotificationsActiveRoundedIcon from '@mui/icons-material/NotificationsActiveRounded';
import GridViewRoundedIcon from '@mui/icons-material/GridViewRounded';
import GridOnRoundedIcon from '@mui/icons-material/GridOnRounded';
import FactCheckRoundedIcon from '@mui/icons-material/FactCheckRounded';
import GroupsRoundedIcon from '@mui/icons-material/GroupsRounded';
import ReportProblemRoundedIcon from '@mui/icons-material/ReportProblemRounded';
import StorageRoundedIcon from '@mui/icons-material/StorageRounded';
import ShieldRoundedIcon from '@mui/icons-material/ShieldRounded';
import RuleRoundedIcon from '@mui/icons-material/RuleRounded';
import LibraryBooksRoundedIcon from '@mui/icons-material/LibraryBooksRounded';
import DownloadRoundedIcon from '@mui/icons-material/DownloadRounded';
import HubRoundedIcon from '@mui/icons-material/HubRounded';
import LanRoundedIcon from '@mui/icons-material/LanRounded';
import BusinessCenterRoundedIcon from '@mui/icons-material/BusinessCenterRounded';
import StorefrontRoundedIcon from '@mui/icons-material/StorefrontRounded';
import SettingsRoundedIcon from '@mui/icons-material/SettingsRounded';
import LogoutRoundedIcon from '@mui/icons-material/LogoutRounded';
import SwapHorizRoundedIcon from '@mui/icons-material/SwapHorizRounded';
import LightModeRoundedIcon from '@mui/icons-material/LightModeRounded';
import DarkModeRoundedIcon from '@mui/icons-material/DarkModeRounded';
import ChevronLeftRoundedIcon from '@mui/icons-material/ChevronLeftRounded';
import ChevronRightRoundedIcon from '@mui/icons-material/ChevronRightRounded';
import TuneRoundedIcon from '@mui/icons-material/TuneRounded';

import {
  ACTIVE_CUSTOMER_EVENT,
  clearToken,
  getActiveCustomer,
  getToken,
  hasCustomerSelection,
  setActiveCustomer,
} from '@/lib/auth';
import { FeaturesProvider } from '@/lib/features';
import { DeploymentContext } from '@/lib/deployment';
import {
  PreferencesProvider,
  clearPreferencesCache,
  useUserPrefs,
} from '@/lib/preferences';
import {
  AttackNotification,
  CustomerOut,
  DeploymentSettings,
  MeResponse,
  clearApiCache,
  fetchMe,
  getDeploymentSettings,
  listAttackNotifications,
  listCustomers,
} from '@/lib/api';
import { gradients } from '../theme';
import { useColorMode } from '../ColorModeContext';
import { SearchPalette } from './SearchPalette';
import { AttackNotificationsMenu } from './AttackNotificationsMenu';

const DRAWER_WIDTH = 248;
const DRAWER_WIDTH_COLLAPSED = 64;

type NavItem = { label: string; href: string; icon: React.ReactNode };
type NavGroup = { heading: string; items: NavItem[] };

const NAV: NavGroup[] = [
  {
    heading: 'Operate',
    items: [
      { label: 'Dashboard', href: '/dashboard', icon: <GridViewRoundedIcon fontSize="small" /> },
      { label: 'Coverage Matrix', href: '/dashboard/coverage', icon: <GridOnRoundedIcon fontSize="small" /> },
      { label: 'Verified Coverage', href: '/dashboard/verified', icon: <FactCheckRoundedIcon fontSize="small" /> },
      { label: 'APT Coverage', href: '/dashboard/apt', icon: <GroupsRoundedIcon fontSize="small" /> },
      { label: 'Gap Analysis', href: '/dashboard/gaps', icon: <ReportProblemRoundedIcon fontSize="small" /> },
      { label: 'Collection (CMF)', href: '/dashboard/cmf', icon: <StorageRoundedIcon fontSize="small" /> },
      { label: 'Networks', href: '/dashboard/networks', icon: <LanRoundedIcon fontSize="small" /> },
      { label: 'Posture', href: '/dashboard/posture', icon: <ShieldRoundedIcon fontSize="small" /> },
      { label: 'Snapshot diff', href: '/dashboard/posture/diff', icon: <ShieldRoundedIcon fontSize="small" /> },
    ],
  },
  {
    heading: 'Engineer',
    items: [
      { label: 'Detection Library', href: '/dashboard/detections', icon: <LibraryBooksRoundedIcon fontSize="small" /> },
      { label: 'GRC Crosswalk', href: '/dashboard/grc', icon: <RuleRoundedIcon fontSize="small" /> },
      { label: 'Reports & Export', href: '/dashboard/reports', icon: <DownloadRoundedIcon fontSize="small" /> },
      { label: 'Connectors', href: '/dashboard/connectors', icon: <HubRoundedIcon fontSize="small" /> },
    ],
  },
  {
    heading: 'MSSP',
    items: [
      { label: 'Portfolio', href: '/dashboard/portfolio', icon: <BusinessCenterRoundedIcon fontSize="small" /> },
      { label: 'Compare customers', href: '/dashboard/portfolio/compare', icon: <BusinessCenterRoundedIcon fontSize="small" /> },
      { label: 'Customers', href: '/dashboard/customers', icon: <StorefrontRoundedIcon fontSize="small" /> },
      { label: 'Settings', href: '/dashboard/settings', icon: <SettingsRoundedIcon fontSize="small" /> },
    ],
  },
];

function crumbsFor(pathname: string): string[] {
  const segments = pathname.split('/').filter(Boolean);
  return segments.map((s) => s.replace(/-/g, ' '));
}

export default function AuthedLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const { mode, toggle: toggleColorMode } = useColorMode();

  const [me, setMe] = useState<MeResponse | null>(null);
  const [deployment, setDeployment] = useState<DeploymentSettings | null>(null);
  const [customers, setCustomers] = useState<CustomerOut[]>([]);
  const [activeCodename, setActive] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [custMenuAnchor, setCustMenuAnchor] = useState<HTMLElement | null>(null);
  const [userMenuAnchor, setUserMenuAnchor] = useState<HTMLElement | null>(null);
  const [searchOpen, setSearchOpen] = useState(false);
  const [notifs, setNotifs] = useState<AttackNotification[]>([]);
  const [notifAnchor, setNotifAnchor] = useState<HTMLElement | null>(null);
  const [prefsOpen, setPrefsOpen] = useState(false);
  useEffect(() => {
    if (!getToken()) {
      router.replace('/login');
      return;
    }
    (async () => {
      try {
        const meRes = await fetchMe();
        // Force password rotation when an admin (or the bootstrap
        // script) generated the account's initial password. The
        // change-password screen clears the flag on success; until
        // then, every dashboard mount bounces here.
        if (meRes.must_change_password) {
          router.replace('/change-password');
          return;
        }
        // Customer users have a dedicated portal — keep them out of the
        // MSSP dashboard chrome (their token would 403 on most MSSP
        // endpoints anyway, but we don't want them to see broken nav).
        if (meRes.role === 'customer_user') {
          router.replace('/portal');
          return;
        }
        setMe(meRes);
        const isMssp = meRes.role.startsWith('mssp_');
        if (isMssp) {
          const [settings, list] = await Promise.all([
            getDeploymentSettings().catch(() => null),
            listCustomers().catch(() => null),
          ]);
          setDeployment(settings);
          if (list) setCustomers(list);
          const stored = getActiveCustomer();
          const unavailable = stored && list && !list.some((customer) => customer.codename === stored);
          if (unavailable || !hasCustomerSelection()) {
            // A hidden sample may invalidate the selection. Use the setup workspace
            // if one is available, or return to the portfolio.
            setActiveCustomer(settings?.initial_customer ?? null);
          }
          setActive(getActiveCustomer());
        } else if (meRes.customer_codename) {
          setActive(meRes.customer_codename);
          setActiveCustomer(meRes.customer_codename);
        }
      } catch {
        clearToken();
        router.replace('/login');
      } finally {
        setLoading(false);
      }
    })();
  }, [router]);

  useEffect(() => {
    const handler = (e: Event) => {
      const detail = (e as CustomEvent<string | null>).detail ?? null;
      setActive(detail);
    };
    window.addEventListener(ACTIVE_CUSTOMER_EVENT, handler);
    return () => window.removeEventListener(ACTIVE_CUSTOMER_EVENT, handler);
  }, []);

  // Cmd+K / Ctrl+K opens the global search palette.
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault();
        setSearchOpen((v) => !v);
      } else if (e.key === 'Escape') {
        setSearchOpen(false);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  // Fetch ATT&CK release notifications for the active tenant.
  useEffect(() => {
    if (!activeCodename) {
      setNotifs([]);
      return;
    }
    listAttackNotifications()
      .then(setNotifs)
      .catch(() => setNotifs([]));
  }, [activeCodename]);

  function handleLogout() {
    clearApiCache();
    clearPreferencesCache();
    clearToken();
    router.replace('/login');
  }

  function handleSwitchCustomer(codename: string | null) {
    setActiveCustomer(codename);
    setActive(codename);
    setCustMenuAnchor(null);
    // Refresh current screen so it re-queries with the new tenant header.
    router.refresh();
  }

  if (loading) {
    return (
      <Box sx={{ minHeight: '100vh', display: 'grid', placeItems: 'center' }}>
        <CircularProgress />
      </Box>
    );
  }

  if (!me) return null;

  const isMssp = me.role.startsWith('mssp_');
  const activeEnvironment = deployment?.environments.find((c) => c.codename === activeCodename);
  const activeCustomerName =
    activeEnvironment?.name ??
    customers.find((c) => c.codename === activeCodename)?.name ??
    me?.customer_name ??
    null;
  const switcherLabel = isMssp
    ? activeCodename
      ? activeCustomerName ?? activeCodename
      : 'All customers · portfolio'
    : activeCustomerName ?? 'Select a customer';

  return (
    <PreferencesProvider>
      <ColorModePrefsBridge />
      <Box sx={{ display: 'flex', minHeight: '100vh', bgcolor: 'background.default' }}>
        <SidebarNav pathname={pathname} />

      <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        <AppBar position="sticky" elevation={0}>
          <Toolbar sx={{ gap: 2 }}>
            <Breadcrumbs sx={{ flex: 1, fontSize: '0.875rem', textTransform: 'capitalize' }}>
              {crumbsFor(pathname).map((c, i, arr) => (
                <Typography
                  key={i}
                  color={i === arr.length - 1 ? 'text.primary' : 'text.secondary'}
                  sx={{ fontWeight: i === arr.length - 1 ? 600 : 400 }}
                >
                  {c}
                </Typography>
              ))}
            </Breadcrumbs>

            {activeEnvironment?.is_sample && <Chip label="Sample data" size="small" color="info" variant="outlined" />}

            {isMssp && (
              <>
                <Tooltip title="Switch active customer">
                  <Button
                    size="small"
                    variant="outlined"
                    startIcon={<SwapHorizRoundedIcon fontSize="small" />}
                    onClick={(e) => setCustMenuAnchor(e.currentTarget)}
                    sx={{ textTransform: 'none' }}
                  >
                    {switcherLabel}
                  </Button>
                </Tooltip>
                <Menu
                  anchorEl={custMenuAnchor}
                  open={Boolean(custMenuAnchor)}
                  onClose={() => setCustMenuAnchor(null)}
                >
                  <MenuItem
                    selected={!activeCodename}
                    onClick={() => handleSwitchCustomer(null)}
                  >
                    <Stack>
                      <Typography variant="body2" fontWeight={600}>
                        All customers · portfolio overview
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        Cross-customer roll-up on the dashboard
                      </Typography>
                    </Stack>
                  </MenuItem>
                  <Divider sx={{ my: 0.5 }} />
                  {customers.length === 0 && (
                    <MenuItem disabled>No customers yet</MenuItem>
                  )}
                  {customers.map((c) => (
                    <MenuItem
                      key={c.codename}
                      selected={c.codename === activeCodename}
                      onClick={() => handleSwitchCustomer(c.codename)}
                    >
                      <Stack>
                        <Typography variant="body2" fontWeight={600}>
                          {c.name}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {deployment?.environments.some((item) => item.codename === c.codename && item.is_sample)
                            ? 'Sample data'
                            : `${c.codename} · ${c.sector ?? 'no sector'}`}
                        </Typography>
                      </Stack>
                    </MenuItem>
                  ))}
                </Menu>
              </>
            )}

            <Tooltip title="Search (Ctrl/⌘ + K)">
              <Button
                size="small"
                variant="outlined"
                onClick={() => setSearchOpen(true)}
                startIcon={<SearchRoundedIcon fontSize="small" />}
                endIcon={
                  <Box
                    component="kbd"
                    sx={(t) => ({
                      fontSize: '0.62rem',
                      fontFamily: 'JetBrains Mono, monospace',
                      px: 0.6,
                      py: 0.1,
                      borderRadius: 1,
                      border: `1px solid ${t.palette.divider}`,
                      color: 'text.secondary',
                    })}
                  >
                    ⌘K
                  </Box>
                }
                sx={{ textTransform: 'none' }}
              >
                Search
              </Button>
            </Tooltip>

            {notifs.length > 0 && (
              <Tooltip title="ATT&CK release notifications">
                <IconButton
                  size="small"
                  onClick={(e) => setNotifAnchor(e.currentTarget)}
                  sx={{ position: 'relative' }}
                >
                  <NotificationsActiveRoundedIcon fontSize="small" />
                  <Box
                    sx={{
                      position: 'absolute',
                      top: 4,
                      right: 4,
                      width: 8,
                      height: 8,
                      borderRadius: '50%',
                      bgcolor: 'error.main',
                    }}
                  />
                </IconButton>
              </Tooltip>
            )}

            <Tooltip title={mode === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}>
              <IconButton onClick={toggleColorMode} size="small" aria-label="toggle color mode">
                {mode === 'dark' ? (
                  <LightModeRoundedIcon fontSize="small" />
                ) : (
                  <DarkModeRoundedIcon fontSize="small" />
                )}
              </IconButton>
            </Tooltip>

            <IconButton onClick={(e) => setUserMenuAnchor(e.currentTarget)} size="small">
              <Avatar sx={{ width: 32, height: 32, bgcolor: 'primary.main', color: 'primary.contrastText', fontSize: '0.875rem' }}>
                {me?.email?.slice(0, 1).toUpperCase()}
              </Avatar>
            </IconButton>
            <Menu
              anchorEl={userMenuAnchor}
              open={Boolean(userMenuAnchor)}
              onClose={() => setUserMenuAnchor(null)}
            >
              <MenuItem disabled>
                <Stack>
                  <Typography variant="body2" fontWeight={600}>
                    {me?.email}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {me?.role}
                  </Typography>
                </Stack>
              </MenuItem>
              <Divider />
              <MenuItem
                onClick={() => {
                  setUserMenuAnchor(null);
                  setPrefsOpen(true);
                }}
              >
                <ListItemIcon><TuneRoundedIcon fontSize="small" /></ListItemIcon>
                Preferences
              </MenuItem>
              <Divider />
              <MenuItem onClick={handleLogout}>
                <ListItemIcon><LogoutRoundedIcon fontSize="small" /></ListItemIcon>
                Sign out
              </MenuItem>
            </Menu>
          </Toolbar>
        </AppBar>

        <Box
          component="main"
          key={activeCodename ?? '__no_customer__'}
          sx={{ flex: 1, p: { xs: 2, md: 4 } }}
        >
          <DeploymentContext.Provider value={deployment}>
            <FeaturesProvider>{children}</FeaturesProvider>
          </DeploymentContext.Provider>
        </Box>
      </Box>

      <SearchPalette
        open={searchOpen}
        onClose={() => setSearchOpen(false)}
      />
      <AttackNotificationsMenu
        anchorEl={notifAnchor}
        onClose={() => setNotifAnchor(null)}
        notifications={notifs}
      />
      <PreferencesDialog open={prefsOpen} onClose={() => setPrefsOpen(false)} />
      </Box>
    </PreferencesProvider>
  );
}

function PreferencesDialog({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const { get, set, loading } = useUserPrefs();
  const { mode, setMode } = useColorMode();
  const density = get<string>('density', 'comfortable');
  const collapsed = get<boolean>('sidebar_collapsed', false);
  const defaultDomain = get<string>('default_coverage_domain', 'enterprise');

  return (
    <Dialog open={open} onClose={onClose} maxWidth="xs" fullWidth>
      <DialogTitle sx={{ fontWeight: 700 }}>Your preferences</DialogTitle>
      <DialogContent dividers>
        <Stack spacing={3} sx={{ pt: 1 }}>
          <Box>
            <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
              Appearance
            </Typography>
            <TextField
              select
              size="small"
              fullWidth
              label="Color mode"
              value={mode}
              disabled={loading}
              onChange={(e) => setMode(e.target.value as 'dark' | 'light')}
              sx={{ mt: 1 }}
            >
              <MenuItem value="dark">Dark</MenuItem>
              <MenuItem value="light">Light</MenuItem>
            </TextField>
          </Box>

          <Box>
            <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
              Layout
            </Typography>
            <TextField
              select
              size="small"
              fullWidth
              label="Table density"
              value={density}
              disabled={loading}
              onChange={(e) => set('density', e.target.value)}
              helperText="Compact tables fit more rows on screen."
              sx={{ mt: 1 }}
            >
              <MenuItem value="comfortable">Comfortable</MenuItem>
              <MenuItem value="compact">Compact</MenuItem>
            </TextField>
            <FormControlLabel
              sx={{ mt: 1 }}
              control={
                <Switch
                  size="small"
                  checked={collapsed}
                  disabled={loading}
                  onChange={(e) => set('sidebar_collapsed', e.target.checked)}
                />
              }
              label="Collapse sidebar to icons only"
            />
          </Box>

          <Box>
            <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
              Defaults
            </Typography>
            <TextField
              select
              size="small"
              fullWidth
              label="Default ATT&CK domain"
              value={defaultDomain}
              disabled={loading}
              onChange={(e) => set('default_coverage_domain', e.target.value)}
              helperText="Which ATT&CK domain to open the coverage matrix on."
              sx={{ mt: 1 }}
            >
              <MenuItem value="enterprise">Enterprise</MenuItem>
              <MenuItem value="ics">ICS</MenuItem>
              <MenuItem value="mobile">Mobile</MenuItem>
            </TextField>
          </Box>

          <Typography variant="caption" color="text.secondary">
            Saved to your account — these settings follow you across browsers
            and devices.
          </Typography>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Done</Button>
      </DialogActions>
    </Dialog>
  );
}

function SidebarNav({ pathname }: { pathname: string }) {
  const { get, set } = useUserPrefs();
  const collapsed = !!get<boolean>('sidebar_collapsed', false);
  const width = collapsed ? DRAWER_WIDTH_COLLAPSED : DRAWER_WIDTH;
  const toggle = () => set('sidebar_collapsed', !collapsed);

  return (
    <Drawer
      variant="permanent"
      sx={{
        width,
        flexShrink: 0,
        transition: 'width 160ms ease',
        [`& .MuiDrawer-paper`]: {
          width,
          boxSizing: 'border-box',
          overflowX: 'hidden',
          transition: 'width 160ms ease',
        },
      }}
    >
      <Toolbar sx={{ px: collapsed ? 1.5 : 3, justifyContent: collapsed ? 'center' : 'flex-start' }}>
        {collapsed ? (
          <Typography
            variant="h6"
            sx={{
              background: gradients.cta,
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              fontWeight: 800,
            }}
          >
            DM
          </Typography>
        ) : (
          <Typography
            variant="h6"
            sx={{
              background: gradients.cta,
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              fontWeight: 800,
              letterSpacing: '-0.02em',
            }}
          >
            Detection Map
          </Typography>
        )}
      </Toolbar>
      <Divider sx={{ mx: collapsed ? 1 : 2 }} />
      <Box sx={{ overflowY: 'auto', overflowX: 'hidden', flex: 1, py: 1 }}>
        {NAV.map((group) => (
          <List
            key={group.heading}
            dense
            subheader={
              collapsed ? null : (
                <ListSubheader
                  disableSticky
                  sx={{
                    bgcolor: 'transparent',
                    color: 'text.secondary',
                    fontSize: '0.7rem',
                    fontWeight: 700,
                    letterSpacing: '0.08em',
                    textTransform: 'uppercase',
                    pl: 3,
                  }}
                >
                  {group.heading}
                </ListSubheader>
              )
            }
          >
            {group.items.map((item) => {
              const selected =
                item.href === '/dashboard'
                  ? pathname === '/dashboard'
                  : pathname === item.href ||
                    pathname.startsWith(item.href + '/');
              const button = (
                <ListItemButton
                  key={item.href}
                  component={Link}
                  href={item.href}
                  selected={selected}
                  sx={collapsed ? { justifyContent: 'center', px: 1.5 } : undefined}
                >
                  <ListItemIcon
                    sx={{
                      minWidth: collapsed ? 0 : 32,
                      color: 'text.secondary',
                      justifyContent: 'center',
                    }}
                  >
                    {item.icon}
                  </ListItemIcon>
                  {!collapsed && (
                    <ListItemText
                      primary={item.label}
                      primaryTypographyProps={{ fontSize: '0.875rem', fontWeight: 500 }}
                    />
                  )}
                </ListItemButton>
              );
              return collapsed ? (
                <Tooltip key={item.href} title={item.label} placement="right">
                  {button}
                </Tooltip>
              ) : (
                button
              );
            })}
          </List>
        ))}
      </Box>
      <Divider />
      <Box sx={{ p: 1, display: 'flex', justifyContent: collapsed ? 'center' : 'flex-end' }}>
        <Tooltip title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'} placement="right">
          <IconButton size="small" onClick={toggle}>
            {collapsed ? <ChevronRightRoundedIcon /> : <ChevronLeftRoundedIcon />}
          </IconButton>
        </Tooltip>
      </Box>
    </Drawer>
  );
}

/** Two-way sync between the local ColorModeContext (owned at the root,
 * so SSR + first paint work without auth) and the user's server-persisted
 * `color_mode` preference (loaded only after auth). On mount: server →
 * local. On toggle: local → server. The equality check on both sides
 * prevents the obvious loop. */
function ColorModePrefsBridge() {
  const { mode, setMode } = useColorMode();
  const { preferences, loading, set } = useUserPrefs();
  const serverMode = preferences.color_mode as 'dark' | 'light' | undefined;

  // Single effect, one decision per commit. The previous version split this
  // into two effects (server→local and local→server) that both listed `mode`
  // reactively. On every topbar toggle the server→local effect re-ran, saw
  // `serverMode !== mode`, and called setMode(serverMode) — snapping the
  // toggle straight back. Splitting also let the local→server effect read a
  // stale `mode` during the initial seed and clobber the saved value. One
  // effect with explicit priority (seed → cross-tab adopt → persist) removes
  // both races.
  const seededRef = useRef(false);
  const lastSyncedRef = useRef<'dark' | 'light' | undefined>(undefined);
  useEffect(() => {
    if (loading) return;

    // 1) Initial seed from server (server is source of truth at login).
    if (!seededRef.current) {
      seededRef.current = true;
      if (serverMode === 'dark' || serverMode === 'light') {
        lastSyncedRef.current = serverMode;
        if (serverMode !== mode) setMode(serverMode);
      } else {
        lastSyncedRef.current = mode; // no saved pref → local is the baseline
      }
      return;
    }

    // 2) Genuine external (cross-tab) server change → adopt it locally.
    if (
      (serverMode === 'dark' || serverMode === 'light') &&
      serverMode !== lastSyncedRef.current
    ) {
      lastSyncedRef.current = serverMode;
      if (serverMode !== mode) setMode(serverMode);
      return;
    }

    // 3) Local toggle → persist up to the server (fire-and-forget).
    if ((mode === 'dark' || mode === 'light') && mode !== lastSyncedRef.current) {
      lastSyncedRef.current = mode;
      if (serverMode !== mode) void set('color_mode', mode);
    }
  }, [loading, serverMode, mode, setMode, set]);

  return null;
}
