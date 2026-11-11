'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  Box,
  Chip,
  CircularProgress,
  Dialog,
  DialogContent,
  InputBase,
  Stack,
  Typography,
  alpha,
} from '@mui/material';
import SearchRoundedIcon from '@mui/icons-material/SearchRounded';
import { SearchHit, globalSearch } from '@/lib/api';

const KIND_LABEL: Record<string, string> = {
  technique: 'Technique',
  mitigation: 'Mitigation',
  d3fend: 'D3FEND',
  apt: 'APT group',
  detection: 'Detection',
  customer: 'Customer',
};

const KIND_COLOR: Record<string, string> = {
  technique: '#26d4ee',
  mitigation: '#3ed598',
  d3fend: '#2dd4bf',
  apt: '#ff5a5f',
  detection: '#9b6dff',
  customer: '#f5b54a',
};

const HREF_BY_KIND: Record<string, (id: string) => string> = {
  technique: (id) => `/dashboard/coverage?focus=${id}`,
  mitigation: () => `/dashboard/grc`,
  // D3FEND defensive-technique pages are external (d3fend.mitre.org).
  // The hit's `href` carries the canonical URL — palette will prefer it.
  d3fend: (id) => `https://d3fend.mitre.org/technique/d3f:${id}/`,
  apt: (id) => `/dashboard/apt?group=${id}`,
  detection: (id) => `/dashboard/detections?id=${id}`,
  customer: (codename) => `/dashboard/customers?codename=${codename}`,
};

export function SearchPalette({
  open,
  onClose,
  singleEnvironment,
}: {
  open: boolean;
  onClose: () => void;
  singleEnvironment: boolean;
}) {
  const router = useRouter();
  const [query, setQuery] = useState('');
  const [debounced, setDebounced] = useState('');
  const [hits, setHits] = useState<SearchHit[]>([]);
  const [loading, setLoading] = useState(false);
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement | null>(null);

  // Reset on close, focus on open.
  useEffect(() => {
    if (!open) {
      setQuery('');
      setDebounced('');
      setHits([]);
      setActive(0);
      return;
    }
    setTimeout(() => inputRef.current?.focus(), 0);
  }, [open]);

  useEffect(() => {
    const h = setTimeout(() => setDebounced(query.trim()), 140);
    return () => clearTimeout(h);
  }, [query]);

  useEffect(() => {
    if (debounced.length < 2) {
      setHits([]);
      return;
    }
    let cancelled = false;
    setLoading(true);
    globalSearch(debounced)
      .then((h) => {
        if (!cancelled) {
          setHits(singleEnvironment ? h.filter((hit) => hit.kind !== 'customer') : h);
          setActive(0);
        }
      })
      .catch(() => {
        if (!cancelled) setHits([]);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [debounced, singleEnvironment]);

  function go(hit: SearchHit) {
    const href = hit.href ?? HREF_BY_KIND[hit.kind]?.(hit.id) ?? null;
    if (href) {
      // External links (D3FEND, etc.) open in a new tab so the user
      // doesn't lose their place in the dashboard.
      if (/^https?:\/\//.test(href)) {
        window.open(href, '_blank', 'noopener,noreferrer');
      } else {
        router.push(href);
      }
    }
    onClose();
  }

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActive((a) => Math.min(a + 1, Math.max(0, hits.length - 1)));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActive((a) => Math.max(a - 1, 0));
    } else if (e.key === 'Enter' && hits[active]) {
      e.preventDefault();
      go(hits[active]);
    }
  }

  const grouped = useMemo(() => {
    const groups: Record<string, SearchHit[]> = {};
    for (const h of hits) {
      groups[h.kind] = groups[h.kind] ?? [];
      groups[h.kind].push(h);
    }
    return groups;
  }, [hits]);

  let runningIndex = 0;

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="sm"
      fullWidth
      PaperProps={{
        sx: { borderRadius: 3, overflow: 'hidden', mt: 8, alignSelf: 'flex-start' },
      }}
    >
      <DialogContent sx={{ p: 0 }} onKeyDown={onKeyDown}>
        <Stack
          direction="row"
          alignItems="center"
          spacing={1.5}
          sx={(t) => ({
            px: 2,
            py: 1.5,
            borderBottom: `1px solid ${t.palette.divider}`,
          })}
        >
          <SearchRoundedIcon fontSize="small" color="action" />
          <InputBase
            placeholder={singleEnvironment
              ? 'Search techniques, detections, APTs…'
              : 'Search techniques, detections, APTs, customers…'}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            inputRef={inputRef}
            sx={{ flex: 1, fontSize: '0.95rem' }}
          />
          {loading && <CircularProgress size={16} />}
          <Box
            sx={{
              fontSize: '0.65rem',
              px: 0.75,
              py: 0.25,
              borderRadius: 1,
              border: (t) => `1px solid ${t.palette.divider}`,
              color: 'text.secondary',
              fontFamily: 'JetBrains Mono, monospace',
            }}
          >
            esc
          </Box>
        </Stack>

        <Box sx={{ maxHeight: '60vh', overflowY: 'auto' }}>
          {hits.length === 0 && debounced.length >= 2 && !loading && (
            <Box sx={{ p: 3, textAlign: 'center' }}>
              <Typography variant="body2" color="text.secondary">
                No matches for "{debounced}".
              </Typography>
            </Box>
          )}
          {hits.length === 0 && debounced.length < 2 && (
            <Box sx={{ p: 3, textAlign: 'center' }}>
              <Typography variant="body2" color="text.secondary">
                Type at least two characters. Use ↑ ↓ to navigate, ↵ to open.
              </Typography>
            </Box>
          )}
          {Object.entries(grouped).map(([kind, items]) => (
            <Box key={kind}>
              <Typography
                variant="overline"
                sx={{
                  display: 'block',
                  px: 2,
                  pt: 1.5,
                  pb: 0.5,
                  color: 'text.secondary',
                  fontWeight: 700,
                  letterSpacing: '0.08em',
                  fontSize: '0.65rem',
                }}
              >
                {KIND_LABEL[kind] ?? kind}
              </Typography>
              {items.map((h) => {
                const idx = runningIndex++;
                const isActive = idx === active;
                return (
                  <Box
                    key={`${h.kind}-${h.id}`}
                    onClick={() => go(h)}
                    onMouseEnter={() => setActive(idx)}
                    sx={(t) => ({
                      px: 2,
                      py: 1,
                      cursor: 'pointer',
                      bgcolor: isActive
                        ? alpha(KIND_COLOR[h.kind] ?? t.palette.primary.main, 0.14)
                        : 'transparent',
                      borderLeft: `3px solid ${
                        isActive ? KIND_COLOR[h.kind] ?? t.palette.primary.main : 'transparent'
                      }`,
                      transition: 'background-color 80ms ease',
                    })}
                  >
                    <Stack direction="row" alignItems="center" spacing={1.5}>
                      <Chip
                        size="small"
                        label={KIND_LABEL[h.kind] ?? h.kind}
                        sx={{
                          height: 18,
                          fontSize: '0.62rem',
                          fontWeight: 700,
                          bgcolor: alpha(
                            KIND_COLOR[h.kind] ?? '#999',
                            0.18,
                          ),
                          color: KIND_COLOR[h.kind] ?? 'text.primary',
                          minWidth: 80,
                        }}
                      />
                      <Box sx={{ flex: 1, minWidth: 0 }}>
                        <Typography
                          variant="body2"
                          sx={{
                            fontWeight: 600,
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          {h.label}
                        </Typography>
                        {h.sub && (
                          <Typography
                            variant="caption"
                            color="text.secondary"
                            sx={{
                              display: 'block',
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            {h.sub}
                          </Typography>
                        )}
                      </Box>
                    </Stack>
                  </Box>
                );
              })}
            </Box>
          ))}
        </Box>
      </DialogContent>
    </Dialog>
  );
}
