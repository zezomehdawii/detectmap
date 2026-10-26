'use client';

import { createTheme, alpha, Theme } from '@mui/material/styles';

// Detection Map design tokens.
//
// Visual language inspired by Intel Graphics Software: deep navy surfaces,
// bright cyan accent, flat cards with subtle hairline borders. Light mode
// keeps the same cyan accent on a clean white surface for daytime work.

export type ColorMode = 'light' | 'dark';

// Coverage cell colors — same hues across modes so the matrix legend reads
// consistently.
export const coverage = {
  red: '#ff5a5f',
  amber: '#f5b54a',
  green: '#3ed598',
  blue: '#26d4ee',
  grey: '#7a8497',
  idea: '#6b7591',
  purple: '#9b6dff',
} as const;

export const accent = {
  cyan: '#26d4ee',
  cyanDark: '#0aa9c4',
  cyanLight: '#7ce6f4',
  violet: '#9b6dff',
} as const;

export const gradients = {
  cta: `linear-gradient(135deg, ${accent.cyan} 0%, ${accent.violet} 100%)`,
  ctaHover: `linear-gradient(135deg, ${accent.cyanDark} 0%, #7a4fe0 100%)`,
} as const;

// Per-mode surface palettes. Kept side-by-side so component overrides can
// reference both via `theme.applyStyles('dark', ...)`.
const dark = {
  bgDefault: '#0b1020',
  bgSidebar: '#0d1426',
  bgPaper:   '#161d33',
  bgPaperRaised: '#1c2440',
  text:      '#eef1fa',
  textDim:   '#9aa3b8',
  divider:   alpha('#ffffff', 0.07),
  border:    alpha('#ffffff', 0.08),
  inputBg:   '#0e1426',
};

const light = {
  bgDefault: '#f4f6fb',
  bgSidebar: '#ffffff',
  bgPaper:   '#ffffff',
  bgPaperRaised: '#ffffff',
  text:      '#0b1020',
  textDim:   '#5a6478',
  divider:   alpha('#0b1020', 0.08),
  border:    alpha('#0b1020', 0.08),
  inputBg:   '#ffffff',
};

// Build the theme ONCE. Both color schemes live side-by-side; switching is
// done by flipping the `data-mui-color-scheme` attribute via
// useColorScheme(), not by rebuilding the theme — rebuilding it while
// cssVariables are on causes the visible flicker users see as "blinking".
export function buildTheme(): Theme {
  return createTheme({
    cssVariables: {
      colorSchemeSelector: 'data-mui-color-scheme',
    },
    colorSchemes: {
      light: {
        palette: {
          primary: {
            main: accent.cyan,
            dark: accent.cyanDark,
            light: accent.cyanLight,
            contrastText: '#001119',
          },
          secondary: {
            main: accent.violet,
            dark: '#7a4fe0',
            light: '#c4a8ff',
            contrastText: '#ffffff',
          },
          background: { default: light.bgDefault, paper: light.bgPaper },
          text:       { primary: light.text, secondary: light.textDim },
          divider:    light.divider,
          error:   { main: coverage.red },
          warning: { main: coverage.amber },
          success: { main: coverage.green },
          info:    { main: accent.cyan },
        },
      },
      dark: {
        palette: {
          primary: {
            main: accent.cyan,
            dark: accent.cyanDark,
            light: accent.cyanLight,
            contrastText: '#001119',
          },
          secondary: {
            main: accent.violet,
            dark: '#7a4fe0',
            light: '#c4a8ff',
            contrastText: '#ffffff',
          },
          background: { default: dark.bgDefault, paper: dark.bgPaper },
          text:       { primary: dark.text, secondary: dark.textDim },
          divider:    dark.divider,
          error:   { main: coverage.red },
          warning: { main: coverage.amber },
          success: { main: coverage.green },
          info:    { main: accent.cyan },
        },
      },
    },
    shape: { borderRadius: 12 },
    typography: {
      fontFamily:
        "'Manrope', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
      h1: { fontWeight: 700, letterSpacing: '-0.02em' },
      h2: { fontWeight: 700, letterSpacing: '-0.02em' },
      h3: { fontWeight: 700, letterSpacing: '-0.015em' },
      h4: { fontWeight: 700, letterSpacing: '-0.01em' },
      h5: { fontWeight: 600 },
      h6: { fontWeight: 600 },
      button: { fontWeight: 600, textTransform: 'none', letterSpacing: 0 },
      body1: { fontSize: '0.9375rem' },
    },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            fontFeatureSettings: '"cv11", "ss01"',
          },
          code: {
            fontFamily:
              "'JetBrains Mono', ui-monospace, 'SF Mono', Menlo, monospace",
            fontSize: '0.875em',
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: { backgroundImage: 'none' },
        },
      },
      MuiCard: {
        styleOverrides: {
          root: ({ theme }) => ({
            borderRadius: 16,
            backgroundColor: light.bgPaper,
            border: `1px solid ${light.border}`,
            boxShadow:
              '0 1px 2px rgba(20,18,35,0.04), 0 4px 16px rgba(20,18,35,0.03)',
            ...theme.applyStyles('dark', {
              backgroundColor: dark.bgPaper,
              border: `1px solid ${dark.border}`,
              boxShadow:
                '0 1px 0 rgba(255,255,255,0.02) inset, 0 8px 24px rgba(0,0,0,0.25)',
            }),
          }),
        },
      },
      MuiButton: {
        defaultProps: { disableElevation: true },
        styleOverrides: {
          root: { borderRadius: 10, paddingInline: 18, paddingBlock: 9 },
          containedPrimary: {
            background: gradients.cta,
            color: '#001119',
            '&:hover': { background: gradients.ctaHover },
          },
          outlined: ({ theme }) => ({
            borderColor: light.border,
            ...theme.applyStyles('dark', { borderColor: dark.border }),
          }),
        },
      },
      MuiTextField: {
        defaultProps: { size: 'small', variant: 'outlined' },
      },
      MuiOutlinedInput: {
        styleOverrides: {
          root: ({ theme }) => ({
            borderRadius: 10,
            backgroundColor: light.inputBg,
            ...theme.applyStyles('dark', { backgroundColor: dark.inputBg }),
          }),
          notchedOutline: ({ theme }) => ({
            borderColor: light.border,
            ...theme.applyStyles('dark', { borderColor: dark.border }),
          }),
        },
      },
      MuiAppBar: {
        styleOverrides: {
          root: ({ theme }) => ({
            backgroundColor: light.bgPaper,
            color: light.text,
            boxShadow: 'none',
            borderBottom: `1px solid ${light.border}`,
            backgroundImage: 'none',
            ...theme.applyStyles('dark', {
              backgroundColor: dark.bgPaper,
              color: dark.text,
              borderBottom: `1px solid ${dark.border}`,
            }),
          }),
        },
      },
      MuiDrawer: {
        styleOverrides: {
          paper: ({ theme }) => ({
            backgroundColor: light.bgSidebar,
            borderRight: `1px solid ${light.border}`,
            backgroundImage: 'none',
            ...theme.applyStyles('dark', {
              backgroundColor: dark.bgSidebar,
              borderRight: `1px solid ${dark.border}`,
            }),
          }),
        },
      },
      MuiListItemButton: {
        styleOverrides: {
          root: ({ theme }) => ({
            borderRadius: 10,
            marginInline: 8,
            marginBlock: 2,
            '&.Mui-selected': {
              backgroundColor: alpha(accent.cyan, 0.12),
              color: accent.cyan,
              '& .MuiListItemIcon-root': { color: accent.cyan },
              '&:hover': {
                backgroundColor: alpha(accent.cyan, 0.18),
              },
            },
            ...theme.applyStyles('dark', {
              '&.Mui-selected': {
                backgroundColor: alpha(accent.cyan, 0.16),
                color: accent.cyan,
                '& .MuiListItemIcon-root': { color: accent.cyan },
                '&:hover': {
                  backgroundColor: alpha(accent.cyan, 0.22),
                },
              },
            }),
          }),
        },
      },
      MuiChip: {
        styleOverrides: {
          root: { borderRadius: 8, fontWeight: 600 },
          outlined: ({ theme }) => ({
            borderColor: light.border,
            ...theme.applyStyles('dark', { borderColor: dark.border }),
          }),
        },
      },
      MuiDivider: {
        styleOverrides: {
          root: ({ theme }) => ({
            borderColor: light.divider,
            ...theme.applyStyles('dark', { borderColor: dark.divider }),
          }),
        },
      },
      MuiTableCell: {
        styleOverrides: {
          root: ({ theme }) => ({
            borderBottomColor: light.divider,
            ...theme.applyStyles('dark', { borderBottomColor: dark.divider }),
          }),
          head: {
            color: 'var(--mui-palette-text-secondary)',
            fontWeight: 700,
            textTransform: 'uppercase',
            fontSize: '0.72rem',
            letterSpacing: '0.06em',
          },
        },
      },
      MuiTooltip: {
        styleOverrides: {
          tooltip: ({ theme }) => ({
            backgroundColor: '#0b1020',
            color: '#ffffff',
            border: `1px solid ${light.border}`,
            fontSize: '0.75rem',
            ...theme.applyStyles('dark', {
              backgroundColor: '#1c2440',
              border: `1px solid ${dark.border}`,
            }),
          }),
        },
      },
    },
  });
}

// Backwards-compat default export. Real rendering happens through
// ColorModeProvider; nothing in the app should rebuild the theme on toggle.
const theme = buildTheme();
export default theme;
