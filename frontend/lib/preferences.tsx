'use client';

// Per-user UI preferences, server-backed so they roam across browsers.
//
// First paint reads the localStorage cache (so the theme doesn't flicker
// on cold load); on mount we reconcile against `/auth/me/preferences`
// and overwrite the cache. Writes go to the server first, then the
// cache; the optimistic update happens via the local state so the UI is
// snappy. Sign-out clears the cache via `clearPreferencesCache()`.
//
// Authentication: the provider is mounted inside the authed dashboard
// layout, so by the time it runs there's a token. If GET 401s (token
// just expired), the axios interceptor handles the redirect; we silently
// fall back to defaults here.
import {
  createContext,
  ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';

import {
  PreferenceMeta,
  PreferencesPayload,
  getPreferences,
  patchPreferences,
} from './api';

type PrefValue = string | boolean | number;
type PrefMap = Record<string, PrefValue>;

const CACHE_KEY = 'detectmap.userPrefs';

function readCache(): PrefMap | null {
  if (typeof window === 'undefined') return null;
  try {
    const raw = window.localStorage.getItem(CACHE_KEY);
    return raw ? (JSON.parse(raw) as PrefMap) : null;
  } catch {
    return null;
  }
}

function writeCache(map: PrefMap): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(CACHE_KEY, JSON.stringify(map));
  } catch {
    /* storage disabled / quota — not fatal */
  }
}

export function clearPreferencesCache(): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.removeItem(CACHE_KEY);
  } catch {
    /* not fatal */
  }
}

// Hardcoded fallback defaults — used only when the server is unreachable
// AND no cache exists. The real defaults come from the server catalog.
const FALLBACK_DEFAULTS: PrefMap = {
  color_mode: 'dark',
  density: 'comfortable',
  sidebar_collapsed: false,
  default_coverage_domain: 'enterprise',
};

interface PreferencesContextValue {
  loading: boolean;
  catalog: PreferenceMeta[];
  preferences: PrefMap;
  get: <T extends PrefValue = PrefValue>(key: string, fallback?: T) => T;
  set: (key: string, value: PrefValue) => Promise<void>;
  setMany: (patch: PrefMap) => Promise<void>;
}

const Ctx = createContext<PreferencesContextValue>({
  loading: false,
  catalog: [],
  preferences: FALLBACK_DEFAULTS,
  get: <T extends PrefValue = PrefValue>(_k: string, fallback?: T) =>
    (fallback ?? '') as T,
  set: async () => {},
  setMany: async () => {},
});

export function PreferencesProvider({ children }: { children: ReactNode }) {
  // Seed from the cache for an instant first paint. The server response
  // overwrites this on mount.
  const [prefs, setPrefs] = useState<PrefMap>(
    () => readCache() ?? FALLBACK_DEFAULTS,
  );
  const [catalog, setCatalog] = useState<PreferenceMeta[]>([]);
  const [loading, setLoading] = useState(true);

  const apply = useCallback((payload: PreferencesPayload) => {
    setCatalog(payload.catalog);
    setPrefs(payload.preferences);
    writeCache(payload.preferences);
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const p = await getPreferences();
        if (!cancelled) apply(p);
      } catch {
        // Auth interceptor handles 401s; for everything else we keep
        // the cached / fallback state. Better than blocking the page.
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [apply]);

  const set = useCallback(
    async (key: string, value: PrefValue) => {
      // Optimistic local update so the UI responds immediately.
      const next = { ...prefs, [key]: value };
      setPrefs(next);
      writeCache(next);
      try {
        const payload = await patchPreferences({ [key]: value });
        apply(payload);
      } catch {
        // On failure, refetch to reconcile rather than guessing what the
        // server actually persisted.
        try {
          apply(await getPreferences());
        } catch {
          /* keep optimistic state */
        }
      }
    },
    [prefs, apply],
  );

  const setMany = useCallback(
    async (patch: PrefMap) => {
      const next = { ...prefs, ...patch };
      setPrefs(next);
      writeCache(next);
      try {
        const payload = await patchPreferences(patch);
        apply(payload);
      } catch {
        try {
          apply(await getPreferences());
        } catch {
          /* keep optimistic state */
        }
      }
    },
    [prefs, apply],
  );

  const get = useCallback(
    <T extends PrefValue = PrefValue>(key: string, fallback?: T): T => {
      const v = prefs[key];
      if (v === undefined) return (fallback ?? FALLBACK_DEFAULTS[key]) as T;
      return v as T;
    },
    [prefs],
  );

  const value = useMemo(
    () => ({ loading, catalog, preferences: prefs, get, set, setMany }),
    [loading, catalog, prefs, get, set, setMany],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useUserPrefs(): PreferencesContextValue {
  return useContext(Ctx);
}
