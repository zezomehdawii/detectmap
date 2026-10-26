'use client';

import Link from 'next/link';
import {
  Box,
  Button,
  Chip,
  Divider,
  Menu,
  Stack,
  Typography,
} from '@mui/material';
import OpenInNewRoundedIcon from '@mui/icons-material/OpenInNewRounded';
import { AttackNotification } from '@/lib/api';

export function AttackNotificationsMenu({
  anchorEl,
  onClose,
  notifications,
}: {
  anchorEl: HTMLElement | null;
  onClose: () => void;
  notifications: AttackNotification[];
}) {
  return (
    <Menu
      anchorEl={anchorEl}
      open={Boolean(anchorEl)}
      onClose={onClose}
      PaperProps={{ sx: { width: 420, maxHeight: '70vh' } }}
    >
      <Box sx={{ px: 2, py: 1 }}>
        <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
          ATT&amp;CK release notifications
        </Typography>
        <Typography variant="caption" color="text.secondary">
          Catalog changes affecting techniques you have rules for.
        </Typography>
      </Box>
      <Divider />
      {notifications.length === 0 ? (
        <Box sx={{ p: 2 }}>
          <Typography variant="body2" color="text.secondary">
            No recent ATT&amp;CK changes affect your detections.
          </Typography>
        </Box>
      ) : (
        notifications.map((n) => (
          <Box key={`${n.domain}-${n.version}`} sx={{ px: 2, py: 1.25 }}>
            <Stack direction="row" alignItems="baseline" spacing={1} mb={0.5}>
              <Typography variant="body2" sx={{ fontWeight: 700, flex: 1 }}>
                {n.summary}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {n.ingested_at
                  ? new Date(n.ingested_at).toLocaleDateString()
                  : ''}
              </Typography>
            </Stack>
            <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
              {n.deprecated_in_use.slice(0, 6).map((t) => (
                <Chip
                  key={`d-${t}`}
                  size="small"
                  label={`${t} deprecated`}
                  color="warning"
                  variant="outlined"
                  sx={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.65rem' }}
                />
              ))}
              {n.revoked_in_use.slice(0, 6).map((t) => (
                <Chip
                  key={`r-${t}`}
                  size="small"
                  label={`${t} revoked`}
                  color="error"
                  variant="outlined"
                  sx={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.65rem' }}
                />
              ))}
              {n.renamed_in_use.slice(0, 4).map((r) => (
                <Chip
                  key={`n-${r.technique_id}`}
                  size="small"
                  label={`${r.technique_id} renamed`}
                  variant="outlined"
                  sx={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.65rem' }}
                />
              ))}
            </Stack>
          </Box>
        ))
      )}
      <Divider />
      <Box sx={{ p: 1, display: 'flex', justifyContent: 'flex-end' }}>
        <Button
          size="small"
          component={Link}
          href="/dashboard/settings"
          endIcon={<OpenInNewRoundedIcon fontSize="small" />}
        >
          View full catalog history
        </Button>
      </Box>
    </Menu>
  );
}
