'use client';

import { useEffect, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  CardContent,
  CircularProgress,
  Divider,
  FormControlLabel,
  MenuItem,
  Stack,
  Switch,
  TextField,
  Typography,
} from '@mui/material';
import SaveRoundedIcon from '@mui/icons-material/SaveRounded';
import {
  apiErrorMessage,
  type DeploymentMode,
  type DeploymentSettings,
  getDeploymentSettings,
  patchDeploymentSettings,
} from '@/lib/api';

export default function DeploymentTab() {
  const [settings, setSettings] = useState<DeploymentSettings | null>(null);
  const [mode, setMode] = useState<DeploymentMode>('multi_tenant');
  const [samples, setSamples] = useState(false);
  const [selection, setSelection] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getDeploymentSettings()
      .then((data) => {
        if (cancelled) return;
        setSettings(data);
        setMode(data.mode);
        setSamples(data.sample_data_enabled);
        setSelection(data.active_customer ?? '');
      })
      .catch((err) => {
        if (!cancelled) setError(apiErrorMessage(err, 'Could not load deployment settings.'));
      });
    return () => { cancelled = true; };
  }, []);

  if (!settings) {
    return error ? <Alert severity="error">{error}</Alert> : <CircularProgress size={24} />;
  }

  const environments = settings.environments.filter((env) => samples || !env.is_sample);
  const selected = environments.some((env) => env.codename === selection)
    ? selection
    : environments.length === 1 ? environments[0].codename : '';
  const selectingEnvironment = mode === 'single' && environments.length > 0;
  const changingEnvironment = selectingEnvironment && Boolean(selected) && selected !== settings.active_customer;
  const requiresSelection = selectingEnvironment && settings.mode !== 'single' && !selected;
  const changed = mode !== settings.mode || samples !== settings.sample_data_enabled || changingEnvironment;
  const readOnly = !settings.can_edit || saving;

  async function save(event: React.FormEvent) {
    event.preventDefault();
    if (!settings || readOnly || !changed || requiresSelection) return;
    setSaving(true);
    setError(null);
    try {
      await patchDeploymentSettings({
        mode: mode !== settings.mode ? mode : undefined,
        sample_data_enabled: samples !== settings.sample_data_enabled ? samples : undefined,
        primary_customer: changingEnvironment ? selected : undefined,
      });
      // Reinitialize the dashboard and tenant-scoped pages with the new context.
      const url = new URL(window.location.href);
      url.searchParams.set('tab', 'deployment');
      window.location.replace(url.toString());
    } catch (err) {
      setError(apiErrorMessage(err, 'Could not save deployment settings.'));
      setSaving(false);
    }
  }

  return (
    <Card component="form" onSubmit={save} sx={{ maxWidth: 720 }}>
      <CardContent>
        <Stack spacing={2.5} alignItems="stretch">
          {!settings.can_edit && (
            <Alert severity="info">An administrator can change these settings.</Alert>
          )}
          {error && <Alert severity="error">{error}</Alert>}
          <TextField
            select
            size="small"
            label="Deployment mode"
            value={mode}
            onChange={(event) => setMode(event.target.value as DeploymentMode)}
            disabled={readOnly}
            helperText={mode === 'single'
              ? 'Open one environment directly. Users assigned to other environments regain access when you switch back to multi-tenant.'
              : 'Manage separate customer environments and view their coverage together in the portfolio.'}
          >
            <MenuItem value="single">Single environment</MenuItem>
            <MenuItem value="multi_tenant">Multi-tenant</MenuItem>
          </TextField>
          {selectingEnvironment && (
            <TextField
              select
              size="small"
              label="Active environment"
              value={selected}
              onChange={(event) => setSelection(event.target.value)}
              disabled={readOnly}
              helperText={requiresSelection ? 'Select the environment that should open in single mode.' : undefined}
              slotProps={{ inputLabel: { shrink: true } }}
            >
              {environments.map((env) => (
                <MenuItem key={env.codename} value={env.codename}>
                  {env.name}{env.is_sample && !/\(sample\)$/i.test(env.name) ? ' (sample)' : ''}
                </MenuItem>
              ))}
            </TextField>
          )}
          <Divider />
          <Stack>
            <FormControlLabel
              control={<Switch checked={samples} onChange={(event) => setSamples(event.target.checked)} disabled={readOnly} />}
              label="Enable sample data"
            />
            <Typography variant="body2" color="text.secondary">
              Show the sample environments and their example records. Turning this off hides the
              sample environments and saves their records for later.
            </Typography>
            {settings.mode === 'single' && mode === 'single' && !samples &&
              settings.environments.some((env) => env.codename === settings.active_customer && env.is_sample) && (
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                Turning off sample data will open a regular environment.
              </Typography>
            )}
          </Stack>
          {settings.can_edit && (
            <Button
              type="submit"
              variant="contained"
              startIcon={saving ? <CircularProgress size={16} color="inherit" /> : <SaveRoundedIcon />}
              disabled={readOnly || !changed || requiresSelection}
              sx={{ alignSelf: 'flex-start' }}
            >
              {saving ? 'Saving…' : 'Save deployment settings'}
            </Button>
          )}
        </Stack>
      </CardContent>
    </Card>
  );
}
