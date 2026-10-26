'use client';

import { useCallback, useMemo } from 'react';
import { ThemeProvider, useColorScheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import theme, { ColorMode } from './theme';

// localStorage key shared with InitColorSchemeScript in app/layout.tsx so
// the inline script writes/reads the same slot React does.
export const COLOR_MODE_STORAGE_KEY = 'detectmap.colorMode';

interface ColorModeCtx {
  mode: ColorMode;
  toggle: () => void;
  setMode: (m: ColorMode) => void;
}

// Public hook used throughout the app. Backed by MUI's useColorScheme so
// toggling flips the `data-mui-color-scheme` attribute on <html> instead
// of rebuilding the theme — that rebuild was the source of the flicker.
export function useColorMode(): ColorModeCtx {
  const { mode, setMode } = useColorScheme();
  // During SSR / pre-mount mode is undefined. Default to 'dark' so the
  // icon toggle has a definite value to compare against.
  const resolved: ColorMode = mode === 'light' ? 'light' : 'dark';

  const apply = useCallback(
    (m: ColorMode) => {
      setMode(m);
    },
    [setMode],
  );

  return useMemo(
    () => ({
      mode: resolved,
      setMode: apply,
      toggle: () => apply(resolved === 'dark' ? 'light' : 'dark'),
    }),
    [resolved, apply],
  );
}

export default function ColorModeProvider({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <ThemeProvider
      theme={theme}
      defaultMode="dark"
      modeStorageKey={COLOR_MODE_STORAGE_KEY}
    >
      <CssBaseline />
      {children}
    </ThemeProvider>
  );
}
