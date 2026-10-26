'use client';

import { Box, Card, CardContent, Chip, Typography } from '@mui/material';
import { gradients } from '../../theme';

export default function ComingSoon({
  title,
  phase,
  blurb,
}: {
  title: string;
  phase: number;
  blurb: string;
}) {
  return (
    <Box sx={{ maxWidth: 720, mx: 'auto', mt: 6 }}>
      <Card>
        <CardContent sx={{ p: { xs: 3, md: 4 } }}>
          <Chip
            label={`Phase ${phase}`}
            size="small"
            sx={{
              mb: 2,
              background: gradients.cta,
              color: 'common.white',
              fontWeight: 700,
            }}
          />
          <Typography variant="h4" sx={{ fontWeight: 700, mb: 1, letterSpacing: '-0.02em' }}>
            {title}
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
            {blurb}
          </Typography>
          <Typography variant="caption" color="text.secondary">
            Placeholder — full implementation lands in phase&nbsp;{phase} of the roadmap.
          </Typography>
        </CardContent>
      </Card>
    </Box>
  );
}
