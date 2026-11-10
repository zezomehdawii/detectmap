/** Shared collection-form behavior for the dashboard and customer portal. */
export function splitAttackDataSource(raw: string | null | undefined) {
  const value = (raw ?? '').trim();
  const colon = value.indexOf(':');
  return {
    attack_data_source: (colon < 0 ? value : value.slice(0, colon)).trim() || null,
    attack_data_component: colon < 0 ? null : value.slice(colon + 1).trim() || null,
  };
}

export function formatAttackDataSource(source?: string | null, component?: string | null): string {
  if (!source) return '';
  // Read old combined values without displaying the component twice.
  const normalized = splitAttackDataSource(source);
  const part = normalized.attack_data_component ?? component?.trim();
  return part ? `${normalized.attack_data_source}: ${part}` : normalized.attack_data_source ?? '';
}

export function validRetention(value: number | null | undefined): boolean {
  return value == null || (Number.isInteger(value) && value >= 0);
}

/** FastAPI detail may be a string, validation array, or object. */
export function apiErrorMessage(error: unknown, fallback = 'Request failed.'): string {
  const e = error as { response?: { data?: { detail?: unknown } }; message?: unknown } | null;
  const detail = e?.response?.data?.detail;
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) {
    const messages = detail.map((entry) => {
      if (typeof entry === 'string') return entry;
      if (entry && typeof entry === 'object') {
        const item = entry as { loc?: unknown[]; msg?: unknown };
        const field = item.loc?.filter((part) => part !== 'body').join('.');
        return typeof item.msg === 'string' ? `${field ? `${field}: ` : ''}${item.msg}` : '';
      }
      return '';
    }).filter(Boolean);
    if (messages.length) return messages.join('; ');
  }
  if (detail && typeof detail === 'object' && 'message' in detail && typeof detail.message === 'string') {
    return detail.message;
  }
  return fallback;
}
