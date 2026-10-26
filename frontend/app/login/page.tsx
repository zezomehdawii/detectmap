'use client';

import { useState } from 'react';
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
import { login, fetchMe, clearApiCache } from '@/lib/api';
import { setToken, setActiveCustomer } from '@/lib/auth';
import { gradients } from '../theme';

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleSubmit() {
    setError(null);
    setBusy(true);
    try {
      const { access_token, must_change_password } = await login(email, password);
      // Drop any cached reads from a previous session in this tab so a new
      // user never sees the prior user's data.
      clearApiCache();
      setToken(access_token);
      // Bootstrap / generated password: force the rotation screen before
      // anything else. The /change-password endpoint clears the flag on
      // success, after which the user lands wherever they would have
      // landed normally.
      if (must_change_password) {
        router.push('/change-password');
        return;
      }
      // For customer users, /auth/me will return their pinned customer; for
      // MSSP users it'll be null and they'll choose one from the dashboard.
      // Customer users land in the dedicated portal; everyone else in the
      // MSSP dashboard.
      let destination = '/dashboard';
      try {
        const me = await fetchMe();
        if (me.customer_codename) setActiveCustomer(me.customer_codename);
        if (me.role === 'customer_user') destination = '/portal';
      } catch {
        /* non-fatal; dashboard will re-fetch and route accordingly */
      }
      router.push(destination);
    } catch (e: any) {
      const detail = e?.response?.data?.detail ?? 'Login failed';
      setError(typeof detail === 'string' ? detail : 'Login failed');
    } finally {
      setBusy(false);
    }
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
          maxWidth: 420,
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
              variant="h4"
              sx={{
                background: gradients.cta,
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
                fontWeight: 800,
                letterSpacing: '-0.025em',
                mb: 0.5,
              }}
            >
              The Detection Map
            </Typography>
            <Typography variant="body2" color="text.secondary">
              ATT&CK coverage for the MSSP that does it all.
            </Typography>
          </Box>

          {error && <Alert severity="error">{error}</Alert>}

          <TextField
            label="Email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            fullWidth
            autoComplete="email"
            disabled={busy}
          />
          <TextField
            label="Password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            fullWidth
            autoComplete="current-password"
            disabled={busy}
            onKeyDown={(e) => {
              if (e.key === 'Enter') handleSubmit();
            }}
          />

          <Button
            variant="contained"
            size="large"
            onClick={handleSubmit}
            disabled={busy || !email || !password}
            sx={{ py: 1.25 }}
          >
            {busy ? <CircularProgress size={22} color="inherit" /> : 'Sign in'}
          </Button>
        </Stack>
      </Box>
    </Box>
  );
}
