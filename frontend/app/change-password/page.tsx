'use client';

// Forced password-rotation screen — reached after login when the account
// was created with a generated (bootstrap) password. The screen blocks
// navigation: the user can either rotate the password or sign out.
//
// Once /auth/change-password succeeds the backend clears
// `must_change_password`, so on the next render `/auth/me` reports false
// and the route guard redirects to the dashboard.
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  Stack,
  TextField,
  Typography,
} from '@mui/material';

import { changePassword, fetchMe } from '@/lib/api';
import { clearToken, getToken } from '@/lib/auth';
import { gradients } from '../theme';

const MIN_LEN = 12;

export default function ChangePasswordPage() {
  const router = useRouter();
  const [email, setEmail] = useState<string>('');
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [bootstrapping, setBootstrapping] = useState(true);

  useEffect(() => {
    // Guard: must be logged in. If `must_change_password` is already
    // false (the user navigated here directly without needing the
    // rotation), kick them to the dashboard.
    if (!getToken()) {
      router.replace('/login');
      return;
    }
    (async () => {
      try {
        const me = await fetchMe();
        setEmail(me.email);
        if (!me.must_change_password) {
          router.replace('/dashboard');
          return;
        }
      } catch {
        clearToken();
        router.replace('/login');
        return;
      }
      setBootstrapping(false);
    })();
  }, [router]);

  async function handleSubmit() {
    setError(null);
    if (next.length < MIN_LEN) {
      setError(`New password must be at least ${MIN_LEN} characters.`);
      return;
    }
    if (next !== confirm) {
      setError("New password and confirmation don't match.");
      return;
    }
    if (next === current) {
      setError('Pick something other than the bootstrap password.');
      return;
    }
    setBusy(true);
    try {
      await changePassword({
        current_password: current,
        new_password: next,
      });
      // Server cleared must_change_password — proceed to the dashboard.
      router.replace('/dashboard');
    } catch (e: any) {
      const detail = e?.response?.data?.detail ?? 'change failed';
      setError(typeof detail === 'string' ? detail : 'change failed');
    } finally {
      setBusy(false);
    }
  }

  function signOut() {
    clearToken();
    router.replace('/login');
  }

  if (bootstrapping) {
    return (
      <Box sx={{ minHeight: '100vh', display: 'grid', placeItems: 'center' }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box
      sx={(t) => ({
        minHeight: '100vh',
        display: 'grid',
        placeItems: 'center',
        bgcolor: 'background.default',
        backgroundImage:
          'radial-gradient(1200px 600px at 80% -10%, rgba(155,109,255,0.08), transparent), radial-gradient(900px 500px at -10% 110%, rgba(38,212,238,0.10), transparent)',
        ...t.applyStyles('dark', {
          backgroundImage:
            'radial-gradient(1200px 600px at 80% -10%, rgba(155,109,255,0.18), transparent), radial-gradient(900px 500px at -10% 110%, rgba(38,212,238,0.18), transparent)',
        }),
        px: 2,
      })}
    >
      <Box
        sx={(t) => ({
          width: '100%',
          maxWidth: 460,
          bgcolor: 'background.paper',
          borderRadius: 4,
          p: { xs: 3, sm: 5 },
          boxShadow:
            '0 1px 2px rgba(20,18,35,0.04), 0 24px 64px rgba(20,18,35,0.08)',
          ...t.applyStyles('dark', {
            boxShadow: '0 24px 64px rgba(0,0,0,0.45)',
          }),
          border: '1px solid',
          borderColor: 'divider',
        })}
      >
        <Stack spacing={3}>
          <Box>
            <Typography
              variant="h5"
              sx={{
                background: gradients.cta,
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
                fontWeight: 800,
                letterSpacing: '-0.02em',
                mb: 0.5,
              }}
            >
              Set a new password
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Your account was created with a generated password. Choose a new
              one before continuing.
            </Typography>
          </Box>

          <Typography variant="caption" color="text.secondary">
            Signed in as <strong>{email}</strong>
          </Typography>

          {error && <Alert severity="error">{error}</Alert>}

          <TextField
            label="Current (generated) password"
            type="password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            fullWidth
            autoComplete="current-password"
            disabled={busy}
          />
          <TextField
            label={`New password (≥ ${MIN_LEN} characters)`}
            type="password"
            value={next}
            onChange={(e) => setNext(e.target.value)}
            fullWidth
            autoComplete="new-password"
            disabled={busy}
          />
          <TextField
            label="Confirm new password"
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            fullWidth
            autoComplete="new-password"
            disabled={busy}
            onKeyDown={(e) => {
              if (e.key === 'Enter') handleSubmit();
            }}
          />

          <Stack direction="row" spacing={1.5}>
            <Button
              variant="contained"
              size="large"
              onClick={handleSubmit}
              disabled={busy || !current || !next || !confirm}
              sx={{ flex: 1, py: 1.25 }}
            >
              {busy ? (
                <CircularProgress size={22} color="inherit" />
              ) : (
                'Set new password'
              )}
            </Button>
            <Button onClick={signOut} disabled={busy}>
              Sign out
            </Button>
          </Stack>
        </Stack>
      </Box>
    </Box>
  );
}
