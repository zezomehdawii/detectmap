'use client';

import { useEffect, useState } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  AppBar,
  Avatar,
  Box,
  Breadcrumbs,
  Chip,
  CircularProgress,
  Divider,
  Drawer,
  IconButton,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  ListSubheader,
  Menu,
  MenuItem,
  Stack,
  Toolbar,
  Tooltip,
  Typography,
} from '@mui/material';
import GridViewRoundedIcon from '@mui/icons-material/GridViewRounded';
import GridOnRoundedIcon from '@mui/icons-material/GridOnRounded';
import GroupsRoundedIcon from '@mui/icons-material/GroupsRounded';
import ReportProblemRoundedIcon from '@mui/icons-material/ReportProblemRounded';
import ShieldRoundedIcon from '@mui/icons-material/ShieldRounded';
import RuleRoundedIcon from '@mui/icons-material/RuleRounded';
import LibraryBooksRoundedIcon from '@mui/icons-material/LibraryBooksRounded';
import DownloadRoundedIcon from '@mui/icons-material/DownloadRounded';
import HubRoundedIcon from '@mui/icons-material/HubRounded';
import LanRoundedIcon from '@mui/icons-material/LanRounded';
import AccountCircleRoundedIcon from '@mui/icons-material/AccountCircleRounded';
import BusinessRoundedIcon from '@mui/icons-material/BusinessRounded';
import LogoutRoundedIcon from '@mui/icons-material/LogoutRounded';
import LightModeRoundedIcon from '@mui/icons-material/LightModeRounded';
import DarkModeRoundedIcon from '@mui/icons-material/DarkModeRounded';

import { clearToken, getToken, setActiveCustomer } from '@/lib/auth';
import { MeResponse, clearApiCache, fetchMe } from '@/lib/api';
import { gradients } from '../theme';
import { useColorMode } from '../ColorModeContext';

const DRAWER_WIDTH = 248;

type NavItem = { label: string; href: string; icon: React.ReactNode };
type NavGroup = { heading: string; items: NavItem[] };

// Portal navigation is intentionally narrower than the MSSP dashboard:
// no Portfolio/Customers/Settings, no customer switcher. Tenancy is
// enforced server-side (customer_user is hard-pinned to their own
// customer in the JWT and denied every MSSP/super-admin permission),
// so this nav is the customer-facing complement to that contract.
const PORTAL_NAV: NavGroup[] = [
  {
    heading: 'Posture',
    items: [
      { label: 'Overview', href: '/portal', icon: <GridViewRoundedIcon fontSize="small" /> },
      { label: 'Collection management', href: '/portal/cmf', icon: <LibraryBooksRoundedIcon fontSize="small" /> },
      { label: 'Networks', href: '/portal/networks', icon: <LanRoundedIcon fontSize="small" /> },
      { label: 'Coverage Matrix', href: '/portal/coverage', icon: <GridOnRoundedIcon fontSize="small" /> },
      { label: 'APT Coverage', href: '/portal/apt', icon: <GroupsRoundedIcon fontSize="small" /> },
      { label: 'Gap Analysis', href: '/portal/gaps', icon: <ReportProblemRoundedIcon fontSize="small" /> },
      { label: 'Posture trend', href: '/portal/posture', icon: <ShieldRoundedIcon fontSize="small" /> },
      { label: 'Snapshot diff', href: '/portal/posture/diff', icon: <ShieldRoundedIcon fontSize="small" /> },
    ],
  },
  {
    heading: 'Detections',
    items: [
      { label: 'Detection library', href: '/portal/detections', icon: <LibraryBooksRoundedIcon fontSize="small" /> },
      { label: 'GRC crosswalk', href: '/portal/grc', icon: <RuleRoundedIcon fontSize="small" /> },
      { label: 'Reports & export', href: '/portal/reports', icon: <DownloadRoundedIcon fontSize="small" /> },
      { label: 'Connectors', href: '/portal/connectors', icon: <HubRoundedIcon fontSize="small" /> },
    ],
  },
  {
    heading: 'Account',
    items: [
      { label: 'Organization', href: '/portal/organization', icon: <BusinessRoundedIcon fontSize="small" /> },
      { label: 'My profile', href: '/portal/profile', icon: <AccountCircleRoundedIcon fontSize="small" /> },
    ],
  },
];

function crumbsFor(pathname: string): string[] {
  const segments = pathname.split('/').filter(Boolean);
  return segments.map((s) => s.replace(/-/g, ' '));
}

export default function PortalLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const { mode, toggle: toggleColorMode } = useColorMode();

  const [me, setMe] = useState<MeResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [userMenuAnchor, setUserMenuAnchor] = useState<HTMLElement | null>(null);

  useEffect(() => {
    if (!getToken()) {
      router.replace('/login');
      return;
    }
    (async () => {
      try {
        const meRes = await fetchMe();
        if (meRes.must_change_password) {
          router.replace('/change-password');
          return;
        }
        // Portal is customer-only. Bounce MSSP/super-admin users back to
        // their dashboard — they have a different surface there.
        if (meRes.role !== 'customer_user') {
          router.replace('/dashboard');
          return;
        }
        // Pin the active customer from the token-derived /me response so
        // every API call carries X-Customer (the backend ignores it for
        // customer users, but we keep it for consistency with the rest of
        // the app's expectations).
        if (meRes.customer_codename) {
          setActiveCustomer(meRes.customer_codename);
        }
        setMe(meRes);
      } catch {
        clearToken();
        router.replace('/login');
      } finally {
        setLoading(false);
      }
    })();
  }, [router]);

  function handleLogout() {
    clearApiCache();
    clearToken();
    router.replace('/login');
  }

  if (loading || !me) {
    return (
      <Box sx={{ minHeight: '100vh', display: 'grid', placeItems: 'center' }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh', bgcolor: 'background.default' }}>
      <Drawer
        variant="permanent"
        sx={{
          width: DRAWER_WIDTH,
          flexShrink: 0,
          [`& .MuiDrawer-paper`]: { width: DRAWER_WIDTH, boxSizing: 'border-box' },
        }}
      >
        <Toolbar sx={{ px: 3, display: 'flex', flexDirection: 'column', alignItems: 'flex-start', py: 1.5 }}>
          <Typography
            variant="h6"
            sx={{
              background: gradients.cta,
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              fontWeight: 800,
              letterSpacing: '-0.02em',
              lineHeight: 1.1,
            }}
          >
            Customer portal
          </Typography>
          {me.customer_name && (
            <Typography variant="caption" color="text.secondary" sx={{ mt: 0.25 }}>
              {me.customer_name}
            </Typography>
          )}
        </Toolbar>
        <Divider sx={{ mx: 2 }} />
        <Box sx={{ overflowY: 'auto', flex: 1, py: 1 }}>
          {PORTAL_NAV.map((group) => (
            <List
              key={group.heading}
              dense
              subheader={
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
              }
            >
              {group.items.map((item) => {
                const selected =
                  item.href === '/portal'
                    ? pathname === '/portal'
                    : pathname === item.href ||
                      pathname.startsWith(item.href + '/');
                return (
                  <ListItemButton
                    key={item.href}
                    component={Link}
                    href={item.href}
                    selected={selected}
                  >
                    <ListItemIcon sx={{ minWidth: 32, color: 'text.secondary' }}>
                      {item.icon}
                    </ListItemIcon>
                    <ListItemText
                      primary={item.label}
                      primaryTypographyProps={{ fontSize: '0.875rem', fontWeight: 500 }}
                    />
                  </ListItemButton>
                );
              })}
            </List>
          ))}
        </Box>
      </Drawer>

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

            <Chip
              size="small"
              label={me.customer_name ?? me.customer_codename ?? 'Tenant'}
              variant="outlined"
              color="primary"
              sx={{ fontWeight: 600 }}
            />

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
                {me.email?.slice(0, 1).toUpperCase()}
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
                    {me.email}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    customer user
                  </Typography>
                </Stack>
              </MenuItem>
              <Divider />
              <MenuItem component={Link} href="/portal/profile" onClick={() => setUserMenuAnchor(null)}>
                <ListItemIcon><AccountCircleRoundedIcon fontSize="small" /></ListItemIcon>
                My profile
              </MenuItem>
              <MenuItem onClick={handleLogout}>
                <ListItemIcon><LogoutRoundedIcon fontSize="small" /></ListItemIcon>
                Sign out
              </MenuItem>
            </Menu>
          </Toolbar>
        </AppBar>

        <Box
          component="main"
          sx={{ flex: 1, p: { xs: 2, md: 4 } }}
        >
          {children}
        </Box>
      </Box>
    </Box>
  );
}
