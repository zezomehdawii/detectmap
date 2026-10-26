'use client';

// Per-customer feature flags — UI side.
//
// The backend serves `/customers/{codename}/features` returning a merged
// `{key: bool}` map (defaults + overrides). This provider fetches it once
// per active customer, refetches on customer switch, and exposes a
// synchronous `isEnabled(key)` for components to gate their UI.
//
// Strategy when no customer is in context (MSSP-wide pages): treat every
// flag as enabled — those pages don't talk to a tenant so per-tenant
// gating is meaningless. The server is the source of truth either way;
// this hook is for UX, not security.
import { createContext, ReactNode, useCallback, useContext, useEffect, useState } from 'react';

import { ACTIVE_CUSTOMER_EVENT, getActiveCustomer } from './auth';
import { getCustomerFeatures } from './api';

// Dispatched by the Customers page after an admin saves a feature toggle,
// so the FeaturesProvider can refetch without a page navigation. Detail
// is the codename that changed; the provider ignores it if it doesn't
// match the active customer.
export const FEATURES_CHANGED_EVENT = 'detectmap:customer-features-changed';

export function notifyFeaturesChanged(codename: string): void {
  if (typeof window === 'undefined') return;
  window.dispatchEvent(
    new CustomEvent(FEATURES_CHANGED_EVENT, { detail: codename }),
  );
}

type FeatureMap = Record<string, boolean>;

interface FeaturesContextValue {
  loading: boolean;
  customer: string | null;
  features: FeatureMap;
  // Returns true when no customer is active (MSSP-wide pages), the feature
  // map is still loading, or the flag is set true. Returns false only when
  // the flag is explicitly false for the active customer.
  isEnabled: (key: string) => boolean;
  // Force a refetch (e.g. after admin toggles a flag in the customer drawer).
  refresh: () => Promise<void>;
}

const FeaturesContext = createContext<FeaturesContextValue>({
  loading: false,
  customer: null,
  features: {},
  isEnabled: () => true,
  refresh: async () => {},
});

export function FeaturesProvider({ children }: { children: ReactNode }) {
  const [customer, setCustomer] = useState<string | null>(null);
  const [features, setFeatures] = useState<FeatureMap>({});
  const [loading, setLoading] = useState(false);

  const load = useCallback(async (codename: string | null) => {
    if (!codename) {
      setFeatures({});
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const data = await getCustomerFeatures(codename);
      setFeatures(data.features);
    } catch {
      // Permission errors / 404s leave the map empty → isEnabled() returns
      // true (UI degrades open). Server still enforces; this is UX only.
      setFeatures({});
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const initial = getActiveCustomer();
    setCustomer(initial);
    load(initial);
    const onSwitch = (e: Event) => {
      const next = (e as CustomEvent<string | null>).detail ?? null;
      setCustomer(next);
      load(next);
    };
    const onChanged = (e: Event) => {
      const changed = (e as CustomEvent<string | null>).detail ?? null;
      // Refetch only when the saved customer is the one this provider is
      // currently scoped to — otherwise the admin is editing some other
      // tenant and our cache is unaffected.
      if (changed && changed === getActiveCustomer()) {
        load(changed);
      }
    };
    window.addEventListener(ACTIVE_CUSTOMER_EVENT, onSwitch);
    window.addEventListener(FEATURES_CHANGED_EVENT, onChanged);
    return () => {
      window.removeEventListener(ACTIVE_CUSTOMER_EVENT, onSwitch);
      window.removeEventListener(FEATURES_CHANGED_EVENT, onChanged);
    };
  }, [load]);

  const isEnabled = useCallback(
    (key: string) => {
      if (!customer) return true;
      if (loading) return true;
      const v = features[key];
      // Unknown keys default to enabled — the backend catalog may grow
      // ahead of the UI; better to show the control than hide a feature
      // we forgot to mirror here.
      return v === undefined ? true : v;
    },
    [customer, loading, features],
  );

  const refresh = useCallback(() => load(customer), [customer, load]);

  return (
    <FeaturesContext.Provider
      value={{ loading, customer, features, isEnabled, refresh }}
    >
      {children}
    </FeaturesContext.Provider>
  );
}

export function useFeatures(): FeaturesContextValue {
  return useContext(FeaturesContext);
}

// Convenience wrapper: hides children when the named feature is off and
// optionally renders a small "disabled for this tenant" notice.
export function FeatureGate({
  feature,
  children,
  fallback = null,
}: {
  feature: string;
  children: ReactNode;
  fallback?: ReactNode;
}) {
  const { isEnabled } = useFeatures();
  if (!isEnabled(feature)) return <>{fallback}</>;
  return <>{children}</>;
}
