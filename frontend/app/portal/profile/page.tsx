'use client';

import { useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Divider,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import SaveRoundedIcon from '@mui/icons-material/SaveRounded';
import { MeResponse, changePassword, fetchMe } from '@/lib/api';

export default function ProfilePage() {
  const [me, setMe] = useState<MeResponse | null>(null);
  const [loading, setLoading] = useState(true);

  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    fetchMe()
      .then(setMe)
      .finally(() => setLoading(false));
  }, []);

  const mismatch = next.length > 0 && confirm.length > 0 && next !== confirm;
  const tooShort = next.length > 0 && next.length < 8;
  const canSubmit =
    !busy && current.length > 0 && next.length >= 8 && next === confirm;

  async function submit() {
    if (!canSubmit) return;
    setBusy(true);
    setMsg(null);
    try {
      await changePassword({ current_password: current, new_password: next });
      setMsg({ ok: true, text: 'Password updated.' });
      setCurrent('');
      setNext('');
      setConfirm('');
    } catch (e: any) {
      setMsg({
        ok: false,
        text:
          e?.response?.data?.detail ??
          'Failed to update password. Check your current password and try again.',
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3, maxWidth: 640 }}>
      <Box>
        <Typography variant="h4" sx={{ fontWeight: 700, letterSpacing: '-0.02em' }}>
          My profile
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Your account details and password.
        </Typography>
      </Box>

      <Card>
        <CardContent>
          <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
            Account
          </Typography>
          {loading ? (
            <Box sx={{ py: 2 }}>
              <CircularProgress size={20} />
            </Box>
          ) : me ? (
            <Stack spacing={1.5} sx={{ mt: 1.5 }}>
              <Stack direction="row" spacing={2} alignItems="center">
                <Typography variant="body2" color="text.secondary" sx={{ width: 120 }}>
                  Email
                </Typography>
                <Typography variant="body2" sx={{ fontWeight: 500 }}>
                  {me.email}
                </Typography>
              </Stack>
              <Stack direction="row" spacing={2} alignItems="center">
                <Typography variant="body2" color="text.secondary" sx={{ width: 120 }}>
                  Role
                </Typography>
                <Chip size="small" label={me.role} variant="outlined" />
              </Stack>
              <Stack direction="row" spacing={2} alignItems="center">
                <Typography variant="body2" color="text.secondary" sx={{ width: 120 }}>
                  Customer
                </Typography>
                <Typography variant="body2" sx={{ fontWeight: 500 }}>
                  {me.customer_name ?? '—'}
                  {me.customer_codename && (
                    <Typography
                      component="span"
                      variant="caption"
                      color="text.secondary"
                      sx={{ ml: 1, fontFamily: 'JetBrains Mono, monospace' }}
                    >
                      {me.customer_codename}
                    </Typography>
                  )}
                </Typography>
              </Stack>
            </Stack>
          ) : (
            <Alert severity="error" sx={{ mt: 1 }}>
              Could not load your profile.
            </Alert>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          <Typography variant="overline" sx={{ fontWeight: 700, color: 'text.secondary' }}>
            Change password
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 2 }}>
            Use at least 8 characters. If your account is managed by Active
            Directory, change your password in the directory instead.
          </Typography>
          <Divider sx={{ mb: 2 }} />

          {msg && (
            <Alert severity={msg.ok ? 'success' : 'error'} sx={{ mb: 2 }}>
              {msg.text}
            </Alert>
          )}

          <Stack spacing={2}>
            <TextField
              size="small"
              type="password"
              label="Current password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              autoComplete="current-password"
              disabled={busy}
            />
            <TextField
              size="small"
              type="password"
              label="New password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
              autoComplete="new-password"
              disabled={busy}
              error={tooShort}
              helperText={tooShort ? 'At least 8 characters' : ' '}
            />
            <TextField
              size="small"
              type="password"
              label="Confirm new password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              autoComplete="new-password"
              disabled={busy}
              error={mismatch}
              helperText={mismatch ? 'Passwords do not match' : ' '}
            />
            <Box>
              <Button
                variant="contained"
                startIcon={busy ? <CircularProgress size={14} /> : <SaveRoundedIcon />}
                onClick={submit}
                disabled={!canSubmit}
              >
                Update password
              </Button>
            </Box>
          </Stack>
        </CardContent>
      </Card>
    </Box>
  );
}
