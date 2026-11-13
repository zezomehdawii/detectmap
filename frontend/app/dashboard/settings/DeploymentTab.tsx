'use client';

import { useEffect, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  CardContent,
  CircularProgress,
  FormControlLabel,
  Stack,
  Switch,
  Typography,
} from '@mui/material';
import SaveRoundedIcon from '@mui/icons-material/SaveRounded';
import {
  apiErrorMessage,
  type DeploymentSettings,
  getDeploymentSettings,
  patchDeploymentSettings,
} from '@/lib/api';

export default function DeploymentTab() {
  const [settings, setSettings] = useState<DeploymentSettings | null>(null);
  const [samples, setSamples] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getDeploymentSettings()
      .then((data) => {
        if (cancelled) return;
        setSettings(data);
        setSamples(data.sample_data_enabled);
      })
      .catch((err) => {
        if (!cancelled) setError(apiErrorMessage(err, 'Could not load deployment settings.'));
      });
    return () => { cancelled = true; };
  }, []);

  if (!settings) {
    return error ? <Alert severity="error">{error}</Alert> : <CircularProgress size={24} />;
  }

  const changed = samples !== settings.sample_data_enabled;
  const readOnly = !settings.can_edit || saving;

  async function save(event: React.FormEvent) {
    event.preventDefault();
    if (readOnly || !changed) return;
    setSaving(true);
    setError(null);
    try {
      await patchDeploymentSettings({ sample_data_enabled: samples });
      // Reload the customer list and resolve any hidden workspace selection.
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
          <Stack>
            <FormControlLabel
              control={<Switch checked={samples} onChange={(event) => setSamples(event.target.checked)} disabled={readOnly} />}
              label="Enable sample data"
            />
            <Typography variant="body2" color="text.secondary">
              Add sample customers with example use cases, coverage, assets, and networks.
              Turning this off hides the sample customers and stores their records for later.
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              A fresh setup includes the ATT&CK catalog and an empty customer workspace.
            </Typography>
          </Stack>
          {settings.can_edit && (
            <Button
              type="submit"
              variant="contained"
              startIcon={saving ? <CircularProgress size={16} color="inherit" /> : <SaveRoundedIcon />}
              disabled={readOnly || !changed}
              sx={{ alignSelf: 'flex-start' }}
            >
              {saving ? 'Saving…' : 'Save environment settings'}
            </Button>
          )}
        </Stack>
      </CardContent>
    </Card>
  );
}
