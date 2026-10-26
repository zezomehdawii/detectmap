'use client';

import { AppRouterCacheProvider } from '@mui/material-nextjs/v14-appRouter';
import ColorModeProvider from './ColorModeContext';

export default function Providers({ children }: { children: React.ReactNode }) {
  return (
    <AppRouterCacheProvider options={{ enableCssLayer: true }}>
      <ColorModeProvider>{children}</ColorModeProvider>
    </AppRouterCacheProvider>
  );
}
