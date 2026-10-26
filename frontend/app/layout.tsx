import type { Metadata } from 'next';
import InitColorSchemeScript from '@mui/material/InitColorSchemeScript';
import Providers from './providers';
import { COLOR_MODE_STORAGE_KEY } from './ColorModeContext';

export const metadata: Metadata = {
  title: 'The Detection Map',
  description: 'ATT&CK-driven detection coverage for MSSPs',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          rel="preconnect"
          href="https://fonts.gstatic.com"
          crossOrigin=""
        />
        <link
          href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>
        {/* Sets data-mui-color-scheme on <html> before paint so the saved
            mode applies on the first frame — kills the dark/light flash
            and the flicker that used to happen when the React tree took
            over with a rebuilt theme. */}
        <InitColorSchemeScript
          attribute="data-mui-color-scheme"
          defaultMode="dark"
          modeStorageKey={COLOR_MODE_STORAGE_KEY}
        />
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
