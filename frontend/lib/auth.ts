// Auth + active-customer storage.
//
// Stored in sessionStorage (not localStorage) so that closing the tab/window
// forces a fresh login the next time the user comes back. This is the
// stronger default for an MSSP analyst tool — the alternative (token in
// localStorage) survives reboot and lets a stolen workstation reach tenant
// data without re-authenticating. Multi-tab use: each tab keeps its own
// session, which is fine and arguably desirable in MSSP workflows where
// analysts pivot between customer contexts.
//
// In a future iteration tokens move to HttpOnly cookies issued by the
// backend; for now sessionStorage keeps the foundation moving without
// inventing infra.

const TOKEN_KEY = 'detectmap.token';
const CUSTOMER_KEY = 'detectmap.customer';

// One-time sweep of any legacy localStorage entries from older builds, so
// the new sessionStorage-only flow isn't shadowed by a stale persistent
// token. Safe to call on every read; localStorage.removeItem on a missing
// key is a no-op.
function _purgeLegacyLocalStorage(): void {
  try {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(CUSTOMER_KEY);
  } catch {
    /* private-mode / disabled storage — nothing to clean */
  }
}

export function getToken(): string | null {
  if (typeof window === 'undefined') return null;
  _purgeLegacyLocalStorage();
  return sessionStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  if (typeof window === 'undefined') return;
  _purgeLegacyLocalStorage();
  sessionStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  if (typeof window === 'undefined') return;
  _purgeLegacyLocalStorage();
  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(CUSTOMER_KEY);
}

export function getActiveCustomer(): string | null {
  if (typeof window === 'undefined') return null;
  return sessionStorage.getItem(CUSTOMER_KEY);
}

export const ACTIVE_CUSTOMER_EVENT = 'detectmap:active-customer-changed';

export function setActiveCustomer(codename: string | null): void {
  if (typeof window === 'undefined') return;
  if (codename) sessionStorage.setItem(CUSTOMER_KEY, codename);
  else sessionStorage.removeItem(CUSTOMER_KEY);
  window.dispatchEvent(
    new CustomEvent(ACTIVE_CUSTOMER_EVENT, { detail: codename }),
  );
}
