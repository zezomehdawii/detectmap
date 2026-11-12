import { type FormEvent, useEffect, useId, useState } from 'react';
import { Alert, Autocomplete, Box, Button, Dialog, DialogActions, DialogContent, DialogTitle, Stack, TextField } from '@mui/material';
import { listDetections, listNetworkSourceOptions, type NetworkAssignment, setNetworkAssignment } from '@/lib/api';
import { apiErrorMessage } from '@/lib/cmf-utils';

type Option = { id: string; label: string };
const PAGE_SIZE = 100;

async function loadOptions(source: boolean, query: string, page: number, customer: string) {
  if (source) {
    const items = await listNetworkSourceOptions(query, (page - 1) * PAGE_SIZE, PAGE_SIZE, customer);
    return {
      items: items.map((item) => ({
        id: item.id,
        label: `${item.name} · ${item.asset_name}${item.enabled ? '' : ' (disabled)'}`,
      })),
      more: items.length === PAGE_SIZE,
    };
  }
  const result = await listDetections({ q: query, page, page_size: PAGE_SIZE }, customer);
  return {
    items: result.items.map((item) => ({ id: item.id, label: `${item.title} · ${item.sigma_id}` })),
    more: page * PAGE_SIZE < result.total,
  };
}

export default function NetworkAssignmentDialog({
  networkId, customer, kind, assignedIds, onClose, onAssigned,
}: {
  networkId: string;
  customer: string;
  kind: NetworkAssignment;
  assignedIds: string[];
  onClose: () => void;
  onAssigned: () => void;
}) {
  const source = kind === 'data-sources';
  const label = source ? 'Collection source' : 'Detection rule';
  const title = source ? 'Assign collection source' : 'Assign detection rule';
  const titleId = useId();
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState<Option | null>(null);
  const [options, setOptions] = useState<Option[]>([]);
  const [searching, setSearching] = useState(true);
  const [lookupError, setLookupError] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [page, setPage] = useState(1);
  const [more, setMore] = useState(false);

  useEffect(() => {
    let active = true;
    setSearching(true);
    setLookupError(null);
    const timer = window.setTimeout(async () => {
      try {
        const result = await loadOptions(source, query.trim(), page, customer);
        if (!active) return;
        setOptions((old) => page === 1 ? result.items : [...old, ...result.items.filter((item) => !old.some(({ id }) => id === item.id))]);
        setMore(result.more);
      } catch (err) {
        if (active) {
          setLookupError(apiErrorMessage(err, 'Could not load available assignments.'));
        }
      } finally {
        if (active) setSearching(false);
      }
    }, query && page === 1 ? 250 : 0);
    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, [attempt, customer, page, query, source]);

  async function assign(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected) return;
    setSaving(true);
    setSaveError(null);
    try {
      await setNetworkAssignment(networkId, kind, selected.id, true, customer);
      onAssigned();
    } catch (err) {
      setSaveError(apiErrorMessage(err, 'Could not save the assignment.'));
    } finally {
      setSaving(false);
    }
  }

  const available = options.filter((option) => !assignedIds.includes(option.id));
  if (selected && !available.some((option) => option.id === selected.id)) available.unshift(selected);

  return (
    <Dialog open maxWidth="sm" fullWidth aria-labelledby={titleId} onClose={saving ? undefined : onClose}>
      <Box component="form" onSubmit={assign}>
        <DialogTitle id={titleId}>{title}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            {saveError && <Alert severity="error">{saveError}</Alert>}
            {lookupError && (
              <Alert severity="error" action={<Button color="inherit" onClick={() => setAttempt((n) => n + 1)}>Retry</Button>}>
                {lookupError}
              </Alert>
            )}
            <Autocomplete
              options={available}
              getOptionKey={(option) => option.id}
              getOptionLabel={(option) => option.label}
              isOptionEqualToValue={(option, value) => option.id === value.id}
              filterOptions={(items) => items}
              value={selected}
              clearOnBlur={false}
              onChange={(_, value) => setSelected(value)}
              onInputChange={(_, value, reason) => {
                if (reason !== 'input' && reason !== 'clear') return;
                setSelected(null);
                if (value === query) return;
                setQuery(value);
                setPage(1);
                setMore(false);
                setOptions([]);
              }}
              loading={searching}
              disabled={saving}
              noOptionsText={query ? 'No unassigned results match this search.' : 'No unassigned results. Search by name.'}
              renderInput={(params) => (
                <TextField
                  {...params}
                  autoFocus
                  label={label}
                  inputProps={{ ...params.inputProps, maxLength: 200 }}
                  helperText={source ? 'Search by source or asset name.' : 'Search by rule title.'}
                />
              )}
            />
            {more && !lookupError && (
              <Button disabled={searching || saving} onClick={() => setPage((n) => n + 1)} sx={{ alignSelf: 'flex-start' }}>
                Load more results
              </Button>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose} disabled={saving}>Cancel</Button>
          <Button type="submit" variant="contained" disabled={!selected || saving}>Assign</Button>
        </DialogActions>
      </Box>
    </Dialog>
  );
}
