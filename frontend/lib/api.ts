import axios, { AxiosAdapter, AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import {
  ACTIVE_CUSTOMER_EVENT,
  clearToken,
  getActiveCustomer,
  getToken,
} from './auth';

const baseURL =
  process.env.NEXT_PUBLIC_API_BASE ?? 'http://localhost:8000';

// ---- short-lived GET cache ------------------------------------------------
// Pages fetch their data client-side on mount, so navigating away and back
// re-fires the same GETs and shows a spinner each time. A small in-memory
// TTL cache makes a revisit (within the window) instant. Implemented as an
// axios adapter so every GET benefits with no call-site changes.
//
// Invalidation: any non-GET (mutation) clears the whole cache, a customer
// switch clears it, and the TTL bounds staleness. Task-status polling
// (`/refresh/{id}`) and blob downloads are never cached.
const CACHE_TTL_MS = 20_000;
const _getCache = new Map<string, { ts: number; res: AxiosResponse }>();

export function clearApiCache(): void {
  _getCache.clear();
}

function _cacheKey(config: InternalAxiosRequestConfig): string {
  const cust = (config.headers?.['X-Customer'] as string) ?? '';
  return [config.url ?? '', JSON.stringify(config.params ?? {}), cust].join('|');
}

const _baseAdapter = axios.getAdapter(axios.defaults.adapter);

const _cachingAdapter: AxiosAdapter = async (config) => {
  const method = (config.method ?? 'get').toLowerCase();
  const url = config.url ?? '';
  const cacheable =
    method === 'get' &&
    !config.responseType && // skip blob / stream downloads
    !url.includes('/refresh/'); // skip task-status polling

  if (!cacheable) {
    const res = await _baseAdapter(config);
    if (method !== 'get') _getCache.clear(); // a mutation invalidates reads
    return res;
  }

  const key = _cacheKey(config);
  const hit = _getCache.get(key);
  if (hit && Date.now() - hit.ts < CACHE_TTL_MS) {
    return hit.res;
  }
  const res = await _baseAdapter(config);
  _getCache.set(key, { ts: Date.now(), res });
  return res;
};

// Switching the active customer must drop cached tenant-scoped reads even
// though the key already includes X-Customer (keeps memory bounded + fresh).
if (typeof window !== 'undefined') {
  window.addEventListener(ACTIVE_CUSTOMER_EVENT, () => _getCache.clear());
}

export const api = axios.create({
  baseURL,
  timeout: 30000,
  adapter: _cachingAdapter,
});

api.interceptors.request.use((config) => {
  const token = getToken();
  if (token) {
    config.headers = config.headers ?? {};
    config.headers.Authorization = `Bearer ${token}`;
  }
  // Per-call X-Customer override wins. Pages that operate on an
  // arbitrary customer (e.g. the customer-drawer profile) set the header
  // explicitly; everything else falls back to the active customer
  // from the topbar switcher.
  if (!config.headers?.['X-Customer']) {
    const customer = getActiveCustomer();
    if (customer) {
      config.headers = config.headers ?? {};
      config.headers['X-Customer'] = customer;
    }
  }
  return config;
});

api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err?.response?.status === 401 && typeof window !== 'undefined') {
      clearToken();
      // Wipe the cached user-preferences blob so the next user doesn't
      // see the previous user's color mode flash on first paint. Done
      // by-key here to avoid a circular import with lib/preferences.tsx.
      try {
        window.localStorage.removeItem('detectmap.userPrefs');
      } catch {
        /* not fatal */
      }
      // Avoid a redirect loop if we're already on /login.
      if (!window.location.pathname.startsWith('/login')) {
        window.location.href = '/login';
      }
    }
    return Promise.reject(err);
  },
);

// ---- typed endpoints ----
export interface MeResponse {
  user_id: string;
  email: string;
  role: string;
  customer_codename: string | null;
  customer_name: string | null;
  mssp_org_id: string | null;
  must_change_password: boolean;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  // True when the account was created with a generated password and
  // the user hasn't yet rotated it. The login page reads this to
  // route into the change-password screen instead of the dashboard.
  must_change_password: boolean;
}

export interface CustomerOut {
  id: string;
  codename: string;
  name: string;
  sector: string | null;
  status: string;
  schema_name: string;
  created_at?: string | null;
}

export type CustomerStatus = 'provisioning' | 'active' | 'suspended' | 'archived';

export async function login(
  email: string,
  password: string,
): Promise<LoginResponse> {
  const { data } = await api.post<LoginResponse>('/auth/login', {
    email,
    password,
  });
  return data;
}

export async function fetchMe(): Promise<MeResponse> {
  const { data } = await api.get<MeResponse>('/auth/me');
  return data;
}

export async function changePassword(payload: {
  current_password: string;
  new_password: string;
}): Promise<void> {
  await api.post('/auth/change-password', payload);
}

// ---- per-user preferences -------------------------------------------------

export interface PreferenceMeta {
  key: string;
  label: string;
  description: string;
  default: string | boolean | number;
  choices: string[];
  value_type: string;
}

export interface PreferencesPayload {
  catalog: PreferenceMeta[];
  // Effective state — server merges defaults with the user's overrides.
  preferences: Record<string, string | boolean | number>;
}

export async function getPreferences(): Promise<PreferencesPayload> {
  const { data } = await api.get<PreferencesPayload>('/auth/me/preferences');
  return data;
}

export async function patchPreferences(
  prefs: Record<string, string | boolean | number>,
): Promise<PreferencesPayload> {
  const { data } = await api.patch<PreferencesPayload>(
    '/auth/me/preferences',
    { preferences: prefs },
  );
  return data;
}

export async function listCustomers(): Promise<CustomerOut[]> {
  const { data } = await api.get<CustomerOut[]>('/customers');
  return data;
}

export async function createCustomer(payload: {
  codename: string;
  name: string;
  sector?: string;
}): Promise<CustomerOut> {
  const { data } = await api.post<CustomerOut>('/customers', payload);
  return data;
}

export async function patchCustomer(
  codename: string,
  payload: {
    name?: string;
    sector?: string | null;
    status?: CustomerStatus;
  },
): Promise<CustomerOut> {
  const { data } = await api.patch<CustomerOut>(
    `/customers/${encodeURIComponent(codename)}`,
    payload,
  );
  return data;
}

// ---- customer profile: assets + contacts + asset↔detection linkage --------
//
// All scoped to the active tenant via the X-Customer header.

export interface AssetCoverageSummary {
  linked_detections: number;
  deployed_detections: number;
  techniques_covered: number;
}

export interface AssetOut {
  id: string;
  name: string;
  kind: string;
  hostname: string | null;
  ip_address: string | null;
  os: string | null;
  environment: string;
  location: string | null;
  owner: string | null;
  business_function: string | null;
  cmf_category: string | null;
  criticality: string;
  data_classification: string | null;
  compliance_scope: string[];
  status: string;
  tags: string[];
  notes: string | null;
  external_id: string | null;
  created_by_email: string | null;
  updated_by_email: string | null;
  created_at: string | null;
  updated_at: string | null;
  coverage: AssetCoverageSummary;
  data_source_count: number;
}

// ---- Collection Management Framework: per-asset data sources -------------

export interface AssetDataSourceOut {
  id: string;
  asset_id: string;
  name: string;
  attack_data_source: string | null;
  attack_data_component: string | null;
  log_source: string | null;
  description: string | null;
  storage_connector_id: string | null;
  storage_location: string | null;
  retention_days: number | null;
  device_completeness_q: number | null;
  data_field_completeness_q: number | null;
  timeliness_q: number | null;
  consistency_q: number | null;
  retention_q: number | null;
  enabled: boolean;
  notes: string | null;
  created_by_email: string | null;
  updated_by_email: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export type AssetDataSourceInput = Partial<
  Omit<AssetDataSourceOut, 'id' | 'asset_id' | 'created_by_email' | 'updated_by_email' | 'created_at' | 'updated_at'>
> & { name: string };

export interface AssetImportResult {
  created: number;
  updated: number;
  data_sources_added: number;
  errors: { row: number; name?: string; error: unknown }[];
}

export interface AssetDetectionRef {
  detection_id: string;
  sigma_id: string;
  title: string;
  detection_status: string;
  source: string;
  techniques: string[];
}

export interface AssetLinkResult {
  linked: number;
  unlinked: number;
  total: number;
}

export interface AssetFilters {
  kind?: string;
  criticality?: string;
  environment?: string;
  status?: string;
  q?: string;
}

// Helper: build axios config with an optional X-Customer override.
function _cust(customer?: string): { headers?: Record<string, string> } {
  return customer ? { headers: { 'X-Customer': customer } } : {};
}

export async function listAssets(
  filters: AssetFilters = {},
  customer?: string,
): Promise<AssetOut[]> {
  const { data } = await api.get<AssetOut[]>('/assets', {
    params: filters,
    ..._cust(customer),
  });
  return data;
}

export async function createAsset(
  payload: Partial<AssetOut> & { name: string; kind: string },
  customer?: string,
): Promise<AssetOut> {
  const { data } = await api.post<AssetOut>('/assets', payload, _cust(customer));
  return data;
}

export async function getAsset(
  id: string,
  customer?: string,
): Promise<AssetOut> {
  const { data } = await api.get<AssetOut>(`/assets/${id}`, _cust(customer));
  return data;
}

export async function updateAsset(
  id: string,
  payload: Partial<AssetOut>,
  customer?: string,
): Promise<AssetOut> {
  const { data } = await api.patch<AssetOut>(`/assets/${id}`, payload, _cust(customer));
  return data;
}

export async function deleteAsset(id: string, customer?: string): Promise<void> {
  await api.delete(`/assets/${id}`, _cust(customer));
}

export async function listAssetDetections(
  id: string,
  customer?: string,
): Promise<AssetDetectionRef[]> {
  const { data } = await api.get<AssetDetectionRef[]>(
    `/assets/${id}/detections`,
    _cust(customer),
  );
  return data;
}

export async function replaceAssetDetections(
  id: string,
  detectionIds: string[],
  customer?: string,
): Promise<AssetLinkResult> {
  const { data } = await api.put<AssetLinkResult>(
    `/assets/${id}/detections`,
    { detection_ids: detectionIds },
    _cust(customer),
  );
  return data;
}

export async function listAssetDataSources(
  assetId: string,
  customer?: string,
): Promise<AssetDataSourceOut[]> {
  const { data } = await api.get<AssetDataSourceOut[]>(
    `/assets/${assetId}/data-sources`,
    _cust(customer),
  );
  return data;
}

export async function createAssetDataSource(
  assetId: string,
  payload: AssetDataSourceInput,
  customer?: string,
): Promise<AssetDataSourceOut> {
  const { data } = await api.post<AssetDataSourceOut>(
    `/assets/${assetId}/data-sources`,
    payload,
    _cust(customer),
  );
  return data;
}

export async function updateAssetDataSource(
  assetId: string,
  dsId: string,
  payload: Partial<AssetDataSourceInput>,
  customer?: string,
): Promise<AssetDataSourceOut> {
  const { data } = await api.patch<AssetDataSourceOut>(
    `/assets/${assetId}/data-sources/${dsId}`,
    payload,
    _cust(customer),
  );
  return data;
}

export async function deleteAssetDataSource(
  assetId: string,
  dsId: string,
  customer?: string,
): Promise<void> {
  await api.delete(`/assets/${assetId}/data-sources/${dsId}`, _cust(customer));
}

/** Bulk-import assets + their collection sources. Dedupe is by external_id. */
export async function importAssets(
  rows: (Partial<AssetOut> & { name: string; kind: string; data_sources?: AssetDataSourceInput[] })[],
  customer?: string,
): Promise<AssetImportResult> {
  const { data } = await api.post<AssetImportResult>(
    '/assets/import',
    { rows },
    _cust(customer),
  );
  return data;
}

export interface ContactOut {
  id: string;
  name: string;
  role: string | null;
  email: string | null;
  phone: string | null;
  office_address: string | null;
  is_primary: boolean;
  notes: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export async function listContacts(customer?: string): Promise<ContactOut[]> {
  const { data } = await api.get<ContactOut[]>('/contacts', _cust(customer));
  return data;
}

export async function createContact(
  payload: {
    name: string;
    role?: string;
    email?: string;
    phone?: string;
    office_address?: string;
    is_primary?: boolean;
    notes?: string;
  },
  customer?: string,
): Promise<ContactOut> {
  const { data } = await api.post<ContactOut>('/contacts', payload, _cust(customer));
  return data;
}

export async function updateContact(
  id: string,
  payload: Partial<ContactOut>,
  customer?: string,
): Promise<ContactOut> {
  const { data } = await api.patch<ContactOut>(`/contacts/${id}`, payload, _cust(customer));
  return data;
}

export async function deleteContact(id: string, customer?: string): Promise<void> {
  await api.delete(`/contacts/${id}`, _cust(customer));
}

// ---- diagrams (Stage 2 of the customer profile) --------------------------

export interface DiagramOut {
  id: string;
  title: string;
  description: string | null;
  filename: string;
  mime_type: string;
  size_bytes: number;
  kind: 'image' | 'pdf' | 'binary';
  is_primary: boolean;
  uploaded_by_email: string | null;
  uploaded_at: string | null;
  updated_at: string | null;
}

export async function listDiagrams(
  customer?: string,
): Promise<DiagramOut[]> {
  const { data } = await api.get<DiagramOut[]>('/diagrams', _cust(customer));
  return data;
}

export async function uploadDiagram(
  payload: {
    file: File;
    title: string;
    description?: string;
    is_primary?: boolean;
  },
  customer?: string,
): Promise<DiagramOut> {
  const form = new FormData();
  form.append('file', payload.file);
  form.append('title', payload.title);
  if (payload.description) form.append('description', payload.description);
  if (payload.is_primary) form.append('is_primary', 'true');
  // axios sets the multipart boundary header automatically when the body
  // is a FormData instance — don't override Content-Type.
  const { data } = await api.post<DiagramOut>('/diagrams', form, _cust(customer));
  return data;
}

export async function updateDiagram(
  id: string,
  payload: { title?: string; description?: string | null; is_primary?: boolean },
  customer?: string,
): Promise<DiagramOut> {
  const { data } = await api.patch<DiagramOut>(`/diagrams/${id}`, payload, _cust(customer));
  return data;
}

export async function deleteDiagram(id: string, customer?: string): Promise<void> {
  await api.delete(`/diagrams/${id}`, _cust(customer));
}

/** Fetch the diagram bytes as a blob URL — caller is responsible for
 * `URL.revokeObjectURL` to avoid leaks. Used for inline image / PDF
 * previews where a plain `<img src>` can't carry the bearer token. */
export async function fetchDiagramBlobUrl(
  id: string,
  customer?: string,
): Promise<string> {
  const { data } = await api.get<Blob>(`/diagrams/${id}/file`, {
    responseType: 'blob',
    ..._cust(customer),
  });
  return URL.createObjectURL(data);
}

/** Trigger a browser download for binary diagrams (Packet Tracer, Visio, …). */
export async function downloadDiagramFile(
  d: { id: string; filename: string },
  customer?: string,
): Promise<void> {
  const url = await fetchDiagramBlobUrl(d.id, customer);
  const a = document.createElement('a');
  a.href = url;
  a.download = d.filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  // Hold the URL alive briefly so the click triggers; revoke after.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// Enum vocab used by the Profile UI (kept in lockstep with assets.py).
export const ASSET_KINDS = [
  'server', 'workstation', 'network_device', 'cloud_resource',
  'database', 'application', 'container', 'mobile_device',
  'iot_ot', 'other',
] as const;
export const ASSET_ENVIRONMENTS = ['production', 'staging', 'development', 'dr'] as const;
export const ASSET_CRITICALITIES = ['low', 'medium', 'high', 'critical'] as const;
export const ASSET_DATA_CLASSIFICATIONS = [
  'public', 'internal', 'confidential', 'restricted',
] as const;
export const ASSET_STATUSES = [
  'active', 'decommissioned', 'planned', 'maintenance',
] as const;
export const ASSET_COMPLIANCE_FRAMEWORKS = [
  'pci', 'hipaa', 'sox', 'gdpr',
  'nca_ecc', 'nca_cscc', 'nca_ccc_csp', 'nca_ccc_cst', 'nca_otcc',
  'iso_27001', 'nist_csf', 'nist_800_53',
] as const;
// CMF functional grouping — kept in lockstep with _CMF_CATEGORIES in assets.py.
export const CMF_CATEGORIES = [
  'endpoint', 'network', 'identity', 'cloud', 'application',
  'email', 'saas', 'ot', 'physical', 'other',
] as const;

// ---- ATT&CK data-source vocabulary (CMF picker source) -------------------

export interface DataSourceVocabItem {
  raw: string;
  data_source: string;
  data_component: string | null;
  technique_count: number;
}

export async function listAttackDataSourceVocab(
  domain?: string,
): Promise<DataSourceVocabItem[]> {
  const { data } = await api.get<{ items: DataSourceVocabItem[]; total: number }>(
    '/catalog/attack/data-sources',
    { params: domain ? { domain } : {} },
  );
  return data.items;
}

// ---- CMF visibility + guidance (/cmf/*) -----------------------------------

export type VisibilityStateValue =
  | 'visible'
  | 'partial'
  | 'not_collected'
  | 'no_data_source'
  | 'out_of_scope';

export interface VisibilityCell {
  technique_id: string;
  name: string;
  parent_technique_id: string | null;
  is_subtechnique: boolean;
  tactics: string[];
  state: VisibilityStateValue;
  required: string[];
  missing: string[];
  quality_avg: number | null;
}

export interface VisibilityMatrix {
  domain: string;
  denominator_kind: string;
  denominator_ref: string | null;
  technique_count: number;
  tactics: string[];
  by_tactic: Record<string, VisibilityCell[]>;
}

export interface VisibilityScore {
  domain: string;
  denominator_kind: string;
  denominator_ref: string | null;
  denominator_size: number;
  assessable_count: number;
  visible_count: number;
  partial_count: number;
  not_collected_count: number;
  no_data_source_count: number;
  visibility_pct: number;
  visible_pct: number;
  quality_avg: number;
  visibility_grade: string;
  quality_grade: string;
  state_counts: Record<string, number>;
}

export interface DataSourceRecommendation {
  raw: string;
  data_source: string;
  data_component: string | null;
  touches: number;
  unlocks: number;
  sample_technique_ids: string[];
}

export interface CmfOverview {
  domain: string;
  denominator_kind: string;
  denominator_ref: string | null;
  asset_count: number;
  assets_by_category: Record<string, number>;
  data_source_count: number;
  enabled_data_source_count: number;
  distinct_attack_sources: number;
  scored_source_count: number;
  unscored_source_count: number;
  score: VisibilityScore;
  top_recommendations: DataSourceRecommendation[];
}

export interface CmfQuery {
  domain?: string;
  denominator?: string;
  ref?: string;
}

function _cmfParams(q: CmfQuery = {}): Record<string, string> {
  const p: Record<string, string> = {
    domain: q.domain ?? 'enterprise',
    denominator: q.denominator ?? 'full',
  };
  if (q.ref) p.ref = q.ref;
  return p;
}

export async function getCmfOverview(q: CmfQuery = {}): Promise<CmfOverview> {
  const { data } = await api.get<CmfOverview>('/cmf/overview', { params: _cmfParams(q) });
  return data;
}

export async function getCmfVisibilityMatrix(q: CmfQuery = {}): Promise<VisibilityMatrix> {
  const { data } = await api.get<VisibilityMatrix>('/cmf/visibility/matrix', {
    params: _cmfParams(q),
  });
  return data;
}

export async function getCmfVisibilityScore(q: CmfQuery = {}): Promise<VisibilityScore> {
  const { data } = await api.get<VisibilityScore>('/cmf/visibility/score', {
    params: _cmfParams(q),
  });
  return data;
}

export async function getCmfRecommendations(
  q: CmfQuery = {},
  limit = 25,
): Promise<DataSourceRecommendation[]> {
  const { data } = await api.get<DataSourceRecommendation[]>(
    '/cmf/visibility/recommendations',
    { params: { ..._cmfParams(q), limit: String(limit) } },
  );
  return data;
}

// ---- CMF lifecycle: requirements + collection plan ------------------------

export const CMF_DRIVERS = [
  'ttx', 'risk_management', 'threat_modeling', 'threat_intel',
  'incident', 'compliance', 'other',
] as const;
export const CMF_PRIORITIES = ['low', 'medium', 'high', 'critical'] as const;
export const CMF_REQUIREMENT_STATUSES = [
  'proposed', 'active', 'satisfied', 'archived',
] as const;
export const CMF_PLAN_STATUSES = [
  'proposed', 'approved', 'in_progress', 'collected', 'validated', 'deferred',
] as const;

export interface CmfRequirement {
  id: string;
  title: string;
  description: string | null;
  driver: string;
  priority: string;
  status: string;
  attack_technique_ids: string[];
  apt_group_id: string | null;
  plan_item_count: number;
  author_email: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export type CmfRequirementInput = Partial<
  Pick<
    CmfRequirement,
    'title' | 'description' | 'driver' | 'priority' | 'status' | 'attack_technique_ids' | 'apt_group_id'
  >
>;

export interface CmfPlanItem {
  id: string;
  data_source: string;
  title: string | null;
  rationale: string | null;
  requirement_id: string | null;
  requirement_title: string | null;
  target_asset_id: string | null;
  target_asset_name: string | null;
  priority: string;
  status: string;
  assigned_to: string | null;
  due_date: string | null;
  technique_count: number;
  source_kind: string;
  notes: string | null;
  author_email: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export type CmfPlanItemInput = Partial<
  Pick<
    CmfPlanItem,
    | 'data_source'
    | 'title'
    | 'rationale'
    | 'requirement_id'
    | 'target_asset_id'
    | 'priority'
    | 'status'
    | 'assigned_to'
    | 'due_date'
    | 'notes'
  >
>;

export interface SeedFromGapsResult {
  created: number;
  skipped: number;
  items: CmfPlanItem[];
}

export async function listCmfRequirements(): Promise<CmfRequirement[]> {
  const { data } = await api.get<CmfRequirement[]>('/cmf/requirements');
  return data;
}

export async function createCmfRequirement(
  payload: CmfRequirementInput,
): Promise<CmfRequirement> {
  const { data } = await api.post<CmfRequirement>('/cmf/requirements', payload);
  return data;
}

export async function updateCmfRequirement(
  id: string,
  payload: CmfRequirementInput,
): Promise<CmfRequirement> {
  const { data } = await api.patch<CmfRequirement>(`/cmf/requirements/${id}`, payload);
  return data;
}

export async function deleteCmfRequirement(id: string): Promise<void> {
  await api.delete(`/cmf/requirements/${id}`);
}

export async function listCmfPlan(status?: string): Promise<CmfPlanItem[]> {
  const { data } = await api.get<CmfPlanItem[]>('/cmf/plan', {
    params: status ? { status } : {},
  });
  return data;
}

export async function createCmfPlanItem(payload: CmfPlanItemInput): Promise<CmfPlanItem> {
  const { data } = await api.post<CmfPlanItem>('/cmf/plan', payload);
  return data;
}

export async function updateCmfPlanItem(
  id: string,
  payload: CmfPlanItemInput,
): Promise<CmfPlanItem> {
  const { data } = await api.patch<CmfPlanItem>(`/cmf/plan/${id}`, payload);
  return data;
}

export async function deleteCmfPlanItem(id: string): Promise<void> {
  await api.delete(`/cmf/plan/${id}`);
}

export async function seedCmfPlanFromGaps(
  q: CmfQuery = {},
  limit = 15,
): Promise<SeedFromGapsResult> {
  const { data } = await api.post<SeedFromGapsResult>('/cmf/plan/seed-from-gaps', {
    domain: q.domain ?? 'enterprise',
    denominator: q.denominator ?? 'full',
    ref: q.ref ?? null,
    limit,
  });
  return data;
}

// ---- per-customer users + features ----------------------------------------

export interface CustomerUserOut {
  id: string;
  email: string;
  role: string;
  customer_id: string;
  custom_role_id: string | null;
  custom_role_label: string | null;
  is_active: boolean;
  last_login_at: string | null;
}

export async function listCustomerUsers(
  codename: string,
): Promise<CustomerUserOut[]> {
  const { data } = await api.get<CustomerUserOut[]>(
    `/customers/${encodeURIComponent(codename)}/users`,
  );
  return data;
}

export async function createCustomerUser(
  codename: string,
  payload: {
    email: string;
    password: string;
    full_name?: string;
    custom_role_id?: string | null;
  },
): Promise<CustomerUserOut> {
  const { data } = await api.post<CustomerUserOut>(
    `/customers/${encodeURIComponent(codename)}/users`,
    payload,
  );
  return data;
}

export async function updateCustomerUser(
  codename: string,
  userId: string,
  payload: {
    full_name?: string;
    is_active?: boolean;
    password?: string;
    // Empty string clears the override and reverts to the built-in role.
    custom_role_id?: string | null;
  },
): Promise<CustomerUserOut> {
  const { data } = await api.patch<CustomerUserOut>(
    `/customers/${encodeURIComponent(codename)}/users/${userId}`,
    payload,
  );
  return data;
}

export async function deleteCustomerUser(
  codename: string,
  userId: string,
): Promise<void> {
  await api.delete(`/customers/${encodeURIComponent(codename)}/users/${userId}`);
}

export interface CustomerFeatureMeta {
  key: string;
  label: string;
  description: string;
  default: boolean;
  category: string;
}

export interface CustomerFeaturesOut {
  codename: string;
  catalog: CustomerFeatureMeta[];
  features: Record<string, boolean>;
}

export async function getCustomerFeatures(
  codename: string,
): Promise<CustomerFeaturesOut> {
  const { data } = await api.get<CustomerFeaturesOut>(
    `/customers/${encodeURIComponent(codename)}/features`,
  );
  return data;
}

export async function patchCustomerFeatures(
  codename: string,
  features: Record<string, boolean>,
): Promise<CustomerFeaturesOut> {
  const { data } = await api.patch<CustomerFeaturesOut>(
    `/customers/${encodeURIComponent(codename)}/features`,
    { features },
  );
  return data;
}

// ---- detections ----
export interface DetectionListItem {
  id: string;
  sigma_id: string;
  title: string;
  description: string | null;
  detection_status: string;
  source: string;
  level: string | null;
  score_breadth: number;
  score_depth: number;
  upstream_global_id: string | null;
  tags: string[];
  techniques: string[];
}

export interface DetectionDetail extends DetectionListItem {
  sigma_status: string | null;
  author: string | null;
  sigma_references: string[];
  logsource: Record<string, unknown>;
  detection: Record<string, unknown>;
  falsepositives: string[];
  raw_yaml: string | null;
}

export interface PaginatedDetections {
  items: DetectionListItem[];
  total: number;
  page: number;
  page_size: number;
}

export interface DetectionFilters {
  status?: string;
  source?: string;
  technique_id?: string;
  level?: string;
  q?: string;
  page?: number;
  page_size?: number;
}

export async function listDetections(
  filters: DetectionFilters = {},
  customer?: string,
): Promise<PaginatedDetections> {
  const params: Record<string, string | number | boolean> = {};
  for (const [k, v] of Object.entries(filters)) {
    if (v !== undefined && v !== null && v !== '') params[k] = v as any;
  }
  const { data } = await api.get<PaginatedDetections>('/detections', {
    params,
    ..._cust(customer),
  });
  return data;
}

export async function getDetection(id: string): Promise<DetectionDetail> {
  const { data } = await api.get<DetectionDetail>(`/detections/${id}`);
  return data;
}

export async function patchDetection(
  id: string,
  patch: Partial<{
    detection_status: string;
    level: string;
    score_breadth: number;
    score_depth: number;
    raw_yaml: string;
    title: string;
    description: string;
    tags: string[];
  }>,
): Promise<DetectionDetail> {
  const { data } = await api.patch<DetectionDetail>(`/detections/${id}`, patch);
  return data;
}

export async function createDetection(payload: {
  raw_yaml: string;
  detection_status?: string;
  score_breadth?: number;
  score_depth?: number;
}): Promise<DetectionDetail> {
  const { data } = await api.post<DetectionDetail>('/detections', payload);
  return data;
}

export interface BulkResult {
  updated: number;
  skipped: number;
}

export async function bulkDetectionStatus(
  ids: string[],
  detection_status: string,
): Promise<BulkResult> {
  const { data } = await api.post<BulkResult>('/detections/bulk-status', {
    ids,
    detection_status,
  });
  return data;
}

export async function bulkDeleteDetections(ids: string[]): Promise<BulkResult> {
  const { data } = await api.post<BulkResult>('/detections/bulk-delete', { ids });
  return data;
}

// ---- coverage ----
export type CoverageCellState =
  | 'deployed'
  | 'in_progress'
  | 'idea'
  | 'gap'
  | 'not_applicable'
  | 'out_of_scope';

export interface CoverageCell {
  technique_id: string;
  name: string;
  parent_technique_id: string | null;
  is_subtechnique: boolean;
  tactics: string[];
  state: CoverageCellState;
  detection_count: number;
  max_depth: number;
  deployed_count: number;
}

export interface CoverageMatrix {
  domain: string;
  denominator_kind: 'full' | 'sector' | 'apt';
  denominator_ref: string | null;
  technique_count: number;
  tactics: string[];
  by_tactic: Record<string, CoverageCell[]>;
}

export interface CoverageScore {
  domain: string;
  denominator_kind: 'full' | 'sector' | 'apt';
  denominator_ref: string | null;
  denominator_size: number;
  covered_count: number;
  deployed_count: number;
  breadth_pct: number;
  depth_avg: number;
  breadth_grade: string;
  depth_grade: string;
  posture_grade: string;
  state_counts: Record<string, number>;
}

export interface CoverageSnapshot {
  id: string;
  taken_at: string;
  denominator_kind: string;
  denominator_ref: string | null;
  breadth_score: string;
  depth_score: string;
  posture_grade: string;
  payload: Record<string, unknown>;
  notes: string | null;
}

export interface SectorProfileSummary {
  sector: string;
  label: string;
  description: string | null;
  technique_count: number;
}

export interface APTGroup {
  group_id: string;
  name: string;
  aliases: string[];
  description: string | null;
}

export interface CoverageQuery {
  domain?: string;
  denominator?: 'full' | 'sector' | 'apt';
  ref?: string;
}

export async function getCoverageMatrix(
  query: CoverageQuery = {},
): Promise<CoverageMatrix> {
  const { data } = await api.get<CoverageMatrix>('/coverage/matrix', { params: query });
  return data;
}

export async function getCoverageScore(
  query: CoverageQuery = {},
): Promise<CoverageScore> {
  const { data } = await api.get<CoverageScore>('/coverage/score', { params: query });
  return data;
}

export async function listSectorProfiles(): Promise<SectorProfileSummary[]> {
  const { data } = await api.get<SectorProfileSummary[]>('/coverage/sectors');
  return data;
}

export async function listAPTGroups(q?: string): Promise<APTGroup[]> {
  const { data } = await api.get<APTGroup[]>('/coverage/groups', {
    params: { q, limit: 50 },
  });
  return data;
}

export async function createCoverageSnapshot(payload: {
  domain?: string;
  denominator_kind: 'full' | 'sector' | 'apt';
  denominator_ref?: string | null;
  notes?: string;
}): Promise<CoverageSnapshot> {
  const { data } = await api.post<CoverageSnapshot>('/coverage/snapshots', payload);
  return data;
}

export async function listCoverageSnapshots(): Promise<CoverageSnapshot[]> {
  const { data } = await api.get<CoverageSnapshot[]>('/coverage/snapshots');
  return data;
}

export async function deleteCoverageSnapshot(id: string): Promise<void> {
  await api.delete(`/coverage/snapshots/${id}`);
}

export async function updateCoverageSnapshotNotes(
  id: string,
  notes: string | null,
): Promise<CoverageSnapshot> {
  const { data } = await api.patch<CoverageSnapshot>(`/coverage/snapshots/${id}`, { notes });
  return data;
}

// ---- deployed SIEM use-case overlay (from connectors) ----
export interface SiemUseCaseRef {
  id: string;
  name: string;
  connector_label: string;
  connector_kind: string;
  severity: string | null;
  enabled: boolean;
}

export interface SiemOverlay {
  technique_ids: string[];
  use_case_count: number;
  by_technique: Record<string, SiemUseCaseRef[]>;
}

export async function getSiemOverlay(): Promise<SiemOverlay> {
  const { data } = await api.get<SiemOverlay>('/coverage/siem-overlay');
  return data;
}

// ---- technique detail ----
export interface MitigationRef {
  mitigation_id: string;
  name: string;
  description: string | null;
  url: string | null;
}

export interface APTUsage {
  group_id: string;
  name: string;
  via: string[]; // "direct" | "software:<sid>:<sname>"
}

export interface DetectionRef {
  id: string;
  sigma_id: string;
  title: string;
  detection_status: string;
  source: string;
  score_breadth: number;
  score_depth: number;
  level: string | null;
  upstream_global_id: string | null;
}

export interface TechniqueNote {
  body: string;
  author_email: string | null;
  updated_at: string;
}

export interface TechniqueDetail {
  technique_id: string;
  domain: string;
  name: string;
  description: string | null;
  is_subtechnique: boolean;
  parent_technique_id: string | null;
  tactics: string[];
  platforms: string[];
  data_sources: string[];
  deprecated: boolean;
  revoked: boolean;
  url: string | null;
  mitigations: MitigationRef[];
  apt_groups: APTUsage[];
  detections: DetectionRef[];
  d3fend: D3FENDDefense[];
  note: TechniqueNote | null;
}

export async function getTechniqueDetail(
  technique_id: string,
  domain = 'enterprise',
): Promise<TechniqueDetail> {
  const { data } = await api.get<TechniqueDetail>(
    `/coverage/techniques/${encodeURIComponent(technique_id)}`,
    { params: { domain } },
  );
  return data;
}

export async function upsertTechniqueNote(
  technique_id: string,
  body: string,
): Promise<TechniqueNote> {
  const { data } = await api.put<TechniqueNote>(
    `/coverage/techniques/${encodeURIComponent(technique_id)}/note`,
    { body },
  );
  return data;
}

export async function deleteTechniqueNote(technique_id: string): Promise<void> {
  await api.delete(
    `/coverage/techniques/${encodeURIComponent(technique_id)}/note`,
  );
}

// ---- matrix delta ----
export type DeltaChange =
  | 'improved'
  | 'regressed'
  | 'unchanged'
  | 'new'
  | 'removed';

export interface MatrixDeltaCell {
  technique_id: string;
  previous_state: string | null;
  previous_depth: number | null;
  current_state: string;
  current_depth: number;
  change: DeltaChange;
}

export interface MatrixDelta {
  snapshot_id: string;
  snapshot_taken_at: string;
  domain: string;
  denominator_kind: string;
  denominator_ref: string | null;
  summary: Record<DeltaChange, number>;
  cells: MatrixDeltaCell[];
}

export async function getMatrixDelta(
  snapshot_id: string,
  query: CoverageQuery = {},
): Promise<MatrixDelta> {
  const { data } = await api.get<MatrixDelta>('/coverage/matrix-delta', {
    params: { snapshot_id, ...query },
  });
  return data;
}

// ---- apt ----
export interface APTListItem {
  group_id: string;
  name: string;
  aliases: string[];
  description: string | null;
  deprecated: boolean;
  revoked: boolean;
}

export interface PaginatedAPT {
  items: APTListItem[];
  total: number;
  page: number;
  page_size: number;
}

export interface GroupBreakdownTechnique {
  technique_id: string;
  name: string;
  tactics: string[];
  is_subtechnique: boolean;
  parent_technique_id: string | null;
  state: CoverageCellState;
  detection_count: number;
  max_depth: number;
  sources: string[];
}

export interface GroupBreakdown {
  group_id: string;
  name: string;
  aliases: string[];
  description: string | null;
  technique_count: number;
  covered_count: number;
  deployed_count: number;
  breadth_pct: number;
  breadth_grade: string;
  depth_grade: string;
  posture_grade: string;
  by_tactic: Record<string, GroupBreakdownTechnique[]>;
}

export async function listAPTPaginated(
  q: string | undefined,
  page = 1,
  page_size = 50,
): Promise<PaginatedAPT> {
  const { data } = await api.get<PaginatedAPT>('/apt/groups', {
    params: { q, page, page_size },
  });
  return data;
}

export async function getAPTGroup(group_id: string): Promise<GroupBreakdown> {
  const { data } = await api.get<GroupBreakdown>(`/apt/groups/${group_id}`);
  return data;
}

// ---- gaps ----
export interface GapEntry {
  technique_id: string;
  name: string;
  tactics: string[];
  is_subtechnique: boolean;
  parent_technique_id: string | null;
  apt_count: number;
  direct_group_count: number;
  software_group_count: number;
  sample_groups: { group_id: string; name: string }[];
  detection_count: number;
  comment_count: number;
  is_ignored: boolean;
}

export interface GapTop {
  domain: string;
  denominator_kind: string;
  denominator_ref: string | null;
  items: GapEntry[];
}

export async function getTopGaps(
  denominator: 'full' | 'sector' | 'apt' = 'full',
  ref?: string,
  limit = 25,
  includeIgnored = false,
): Promise<GapTop> {
  const { data } = await api.get<GapTop>('/gaps/top', {
    params: { denominator, ref, limit, include_ignored: includeIgnored },
  });
  return data;
}

export interface GapComment {
  id: string;
  technique_id: string;
  domain: string;
  body: string;
  author_email: string | null;
  created_at: string;
}

export interface GapIgnoreRecord {
  id: string;
  technique_id: string;
  domain: string;
  reason: string;
  author_email: string | null;
  ignored_until: string | null;
  created_at: string;
}

export interface GapAPTRef {
  group_id: string;
  name: string;
  via: 'direct' | 'software';
}

export interface GapDetail {
  technique_id: string;
  domain: string;
  name: string;
  description: string | null;
  url: string | null;
  tactics: string[];
  platforms: string[];
  is_subtechnique: boolean;
  parent_technique_id: string | null;
  deprecated: boolean;
  revoked: boolean;
  detection_count: number;
  apt_groups: GapAPTRef[];
  comments: GapComment[];
  ignore: GapIgnoreRecord | null;
}

export async function getGapDetail(
  technique_id: string,
  domain = 'enterprise',
): Promise<GapDetail> {
  const { data } = await api.get<GapDetail>(
    `/gaps/${encodeURIComponent(technique_id)}`,
    { params: { domain } },
  );
  return data;
}

export async function addGapComment(
  technique_id: string,
  body: string,
  domain = 'enterprise',
): Promise<GapComment> {
  const { data } = await api.post<GapComment>(
    `/gaps/${encodeURIComponent(technique_id)}/comments`,
    { body, domain },
  );
  return data;
}

export async function deleteGapComment(comment_id: string): Promise<void> {
  await api.delete(`/gaps/comments/${encodeURIComponent(comment_id)}`);
}

export async function ignoreGap(
  technique_id: string,
  reason: string,
  options: { domain?: string; ignored_until?: string | null } = {},
): Promise<GapIgnoreRecord> {
  const { data } = await api.post<GapIgnoreRecord>(
    `/gaps/${encodeURIComponent(technique_id)}/ignore`,
    {
      reason,
      domain: options.domain ?? 'enterprise',
      ignored_until: options.ignored_until ?? null,
    },
  );
  return data;
}

export async function unignoreGap(
  technique_id: string,
  domain = 'enterprise',
): Promise<void> {
  await api.delete(`/gaps/${encodeURIComponent(technique_id)}/ignore`, {
    params: { domain },
  });
}

// ---- posture trend ----
export interface PosturePoint {
  id: string;
  taken_at: string;
  breadth_pct: number;
  depth_avg: number;
  breadth_grade: string;
  depth_grade: string;
  posture_grade: string;
  covered_count: number;
  denominator_size: number;
  deployed_count: number;
  denominator_kind: string;
  denominator_ref: string | null;
}

export interface PostureTrend {
  domain: string;
  denominator_kind: string | null;
  denominator_ref: string | null;
  points: PosturePoint[];
}

export async function getPostureTrend(
  denominator?: 'full' | 'sector' | 'apt',
  ref?: string,
): Promise<PostureTrend> {
  const { data } = await api.get<PostureTrend>('/posture/trend', {
    params: { denominator, ref },
  });
  return data;
}

// ---- reports ----
export type SigmaBackend = 'splunk' | 'elastic' | 'sentinel';

export interface SigmaConvertResult {
  detection_id: string;
  sigma_id: string;
  title: string;
  queries: string[];
  error: string | null;
}

export interface SigmaConvertResponse {
  backend: string;
  results: SigmaConvertResult[];
  total: number;
  converted: number;
  failed: number;
}

/** Builds an absolute URL to a streaming-download report endpoint. The browser
 *  will hit it directly; we attach `Authorization` via a one-shot fetch+blob
 *  instead of relying on cookies (we run a Bearer-token JWT scheme). */
export async function downloadReport(path: string, filename: string): Promise<void> {
  const res = await api.get(path, { responseType: 'blob' });
  const ct = res.headers['content-type'];
  const blob = new Blob([res.data], {
    type: typeof ct === 'string' ? ct : 'application/octet-stream',
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export async function convertSigma(
  backend: SigmaBackend,
  detection_ids?: string[],
): Promise<SigmaConvertResponse> {
  const { data } = await api.post<SigmaConvertResponse>('/reports/sigma-convert', {
    backend,
    detection_ids,
  });
  return data;
}

// ---- grc ----
export type ControlState =
  | 'unmapped'
  | 'gap'
  | 'idea'
  | 'in_progress'
  | 'partial'
  | 'deployed';

export interface GRCFrameworkSummary {
  key: string;
  label: string;
  version: string | null;
  description: string | null;
  control_count: number;
  technique_mapping_count: number;
  mitigation_mapping_count: number;
}

export interface GRCControl {
  id: string;
  control_id: string;
  parent_control_id: string | null;
  family: string | null;
  name: string;
  description: string | null;
  sort_order: number;
  technique_count: number;
  mapped_techniques: string[];
  seeded_count: number;
  user_count: number;
  state: ControlState;
  deployed_count: number;
  in_progress_count: number;
  idea_count: number;
  gap_count: number;
  d3fend_count: number;
}

export interface GRCControlD3FEND {
  d3fend_id: string;
  name: string;
  relations: string[];
  via_techniques: string[];
}

export interface GRCFrameworkCoverage {
  framework_key: string;
  framework_label: string;
  framework_version: string | null;
  counts_by_state: Record<string, number>;
  controls: GRCControl[];
}

export interface GRCMapping {
  id: string;
  control_id: string;
  domain: string;
  target_kind: 'technique' | 'mitigation';
  target_id: string;
  source: 'seeded' | 'user';
  rationale: string | null;
  author: string | null;
}

export async function listGRCFrameworks(): Promise<GRCFrameworkSummary[]> {
  const { data } = await api.get<GRCFrameworkSummary[]>('/grc/frameworks');
  return data;
}

export async function getGRCFrameworkCoverage(
  key: string,
): Promise<GRCFrameworkCoverage> {
  const { data } = await api.get<GRCFrameworkCoverage>(
    `/grc/frameworks/${encodeURIComponent(key)}/controls`,
  );
  return data;
}

export interface GRCFrameworkTechniques {
  framework_key: string;
  technique_ids: string[];
}

export async function getGRCFrameworkTechniques(
  key: string,
): Promise<GRCFrameworkTechniques> {
  const { data } = await api.get<GRCFrameworkTechniques>(
    `/grc/frameworks/${encodeURIComponent(key)}/techniques`,
  );
  return data;
}

export interface GRCScorecardRow {
  key: string;
  label: string;
  version: string | null;
  total_controls: number;
  counts_by_state: Record<string, number>;
  deployed_pct: number;
  addressed_pct: number;
  weighted_pct: number;
}

export async function getGRCScorecard(): Promise<GRCScorecardRow[]> {
  const { data } = await api.get<GRCScorecardRow[]>('/grc/scorecard');
  return data;
}

export async function listGRCMappings(controlUuid: string): Promise<GRCMapping[]> {
  const { data } = await api.get<GRCMapping[]>(
    `/grc/controls/${encodeURIComponent(controlUuid)}/mappings`,
  );
  return data;
}

export async function listGRCControlD3FEND(
  controlUuid: string,
): Promise<GRCControlD3FEND[]> {
  const { data } = await api.get<GRCControlD3FEND[]>(
    `/grc/controls/${encodeURIComponent(controlUuid)}/d3fend`,
  );
  return data;
}

export async function upsertGRCMapping(payload: {
  control_id: string;
  target_kind: 'technique' | 'mitigation';
  target_id: string;
  rationale?: string;
  domain?: string;
}): Promise<GRCMapping> {
  const { data } = await api.post<GRCMapping>('/grc/mappings', payload);
  return data;
}

export async function deleteGRCMapping(
  mapping_id: string,
  target_kind: 'technique' | 'mitigation',
): Promise<void> {
  await api.delete(`/grc/mappings/${mapping_id}`, { params: { target_kind } });
}

// ---- connectors ----
export type ConnectorKind = 'splunk' | 'sentinel' | 'elastic' | 'logrhythm';

export interface ConnectorOut {
  id: string;
  kind: ConnectorKind;
  label: string;
  description: string | null;
  status: string;
  last_test_at: string | null;
  last_test_message: string | null;
  config: Record<string, unknown>;
  secret_fields: Record<string, string>;
  created_at: string;
  updated_at: string;
}

export async function listConnectors(): Promise<ConnectorOut[]> {
  const { data } = await api.get<ConnectorOut[]>('/connectors');
  return data;
}

export async function createConnector(payload: {
  kind: ConnectorKind;
  label: string;
  description?: string;
  config: Record<string, unknown>;
}): Promise<ConnectorOut> {
  const { data } = await api.post<ConnectorOut>('/connectors', payload);
  return data;
}

export async function patchConnector(
  id: string,
  payload: {
    label?: string;
    description?: string;
    config?: Record<string, unknown>;
    clear_secrets?: string[];
  },
): Promise<ConnectorOut> {
  const { data } = await api.patch<ConnectorOut>(`/connectors/${id}`, payload);
  return data;
}

export async function deleteConnector(id: string): Promise<void> {
  await api.delete(`/connectors/${id}`);
}

export interface ConnectorTestOut {
  status: string;
  message: string;
  last_test_at: string;
}

export async function testConnector(id: string): Promise<ConnectorTestOut> {
  const { data } = await api.post<ConnectorTestOut>(`/connectors/${id}/test`);
  return data;
}

// ---- deployed use-cases (rules running in the customer's SIEM) ----
export interface DeployedUseCase {
  id: string;
  connector_id: string;
  import_source: 'api' | 'csv';
  external_id: string;
  name: string;
  description: string | null;
  severity: string | null;
  enabled: boolean;
  query: string | null;
  technique_ids: string[];
  synced_at: string | null;
}

export interface UseCaseImportSummary {
  imported: number;
  created: number;
  updated: number;
  technique_count: number;
  source: 'api' | 'csv';
}

export async function listUseCases(connectorId: string): Promise<DeployedUseCase[]> {
  const { data } = await api.get<DeployedUseCase[]>(`/connectors/${connectorId}/use-cases`);
  return data;
}

export async function syncUseCases(connectorId: string): Promise<UseCaseImportSummary> {
  const { data } = await api.post<UseCaseImportSummary>(
    `/connectors/${connectorId}/use-cases/sync`,
  );
  return data;
}

export async function importUseCasesCsv(
  connectorId: string,
  file: File,
): Promise<UseCaseImportSummary> {
  const form = new FormData();
  form.append('file', file);
  const { data } = await api.post<UseCaseImportSummary>(
    `/connectors/${connectorId}/use-cases/import`,
    form,
  );
  return data;
}

export async function deleteUseCase(connectorId: string, useCaseId: string): Promise<void> {
  await api.delete(`/connectors/${connectorId}/use-cases/${useCaseId}`);
}

// ---- portfolio ----
export interface PortfolioCustomerRow {
  id: string;
  codename: string;
  name: string;
  sector: string | null;
  status: string;
  denominator_size: number;
  covered_count: number;
  deployed_count: number;
  breadth_pct: number;
  breadth_grade: string;
  depth_grade: string;
  posture_grade: string;
  state_counts: Record<string, number>;
  error?: string | null;
}

export interface PortfolioOverview {
  mssp_org_id: string;
  denominator_kind: string;
  denominator_ref: string | null;
  customer_count: number;
  posture_distribution: Record<string, number>;
  customers: PortfolioCustomerRow[];
}

export async function getPortfolioOverview(
  denominator: 'full' | 'sector' | 'apt' = 'full',
  ref?: string,
): Promise<PortfolioOverview> {
  const { data } = await api.get<PortfolioOverview>('/portfolio/overview', {
    params: { denominator, ref },
  });
  return data;
}

// ---- settings ----
export interface MSSPBranding {
  mssp_org_id: string;
  mssp_org_name: string;
  branding: Record<string, unknown>;
}

export interface CustomerBranding {
  customer_id: string;
  codename: string;
  name: string;
  branding: Record<string, unknown>;
}

export interface SettingsUserOut {
  id: string;
  email: string;
  role: string;
  customer_id: string | null;
  custom_role_id: string | null;
  custom_role_label: string | null;
  is_active: boolean;
  last_login_at: string | null;
  is_primary: boolean;
}

export interface CatalogDiff {
  domain: string;
  version: string;
  ingested_at: string;
  is_current: boolean;
  added: string[];
  removed: string[];
  deprecated: string[];
  revived: string[];
  revoked: string[];
  renamed: { technique_id: string; old_name: string; new_name: string }[];
}

export async function getMSSPBranding(): Promise<MSSPBranding> {
  const { data } = await api.get<MSSPBranding>('/settings/mssp/branding');
  return data;
}

export async function patchMSSPBranding(payload: {
  display_name?: string;
  logo_url?: string;
  primary_color?: string;
  extra?: Record<string, unknown>;
}): Promise<MSSPBranding> {
  const { data } = await api.patch<MSSPBranding>('/settings/mssp/branding', payload);
  return data;
}

export async function getCustomerBranding(): Promise<CustomerBranding> {
  const { data } = await api.get<CustomerBranding>('/settings/customer/branding');
  return data;
}

export async function patchCustomerBranding(payload: {
  display_name?: string;
  logo_url?: string;
  primary_color?: string;
  extra?: Record<string, unknown>;
}): Promise<CustomerBranding> {
  const { data } = await api.patch<CustomerBranding>(
    '/settings/customer/branding',
    payload,
  );
  return data;
}

export async function listSettingsUsers(): Promise<SettingsUserOut[]> {
  const { data } = await api.get<SettingsUserOut[]>('/settings/users');
  return data;
}

export async function createSettingsUser(payload: {
  email: string;
  password: string;
  role: string;
  full_name?: string;
  customer_id?: string | null;
  custom_role_id?: string | null;
}): Promise<SettingsUserOut> {
  const { data } = await api.post<SettingsUserOut>('/settings/users', payload);
  return data;
}

export async function updateSettingsUser(
  id: string,
  payload: {
    role?: string;
    full_name?: string;
    is_active?: boolean;
    customer_id?: string | null;
    password?: string;
    // Pass "" to clear the override and revert to the built-in role.
    custom_role_id?: string | null;
  },
): Promise<SettingsUserOut> {
  const { data } = await api.patch<SettingsUserOut>(`/settings/users/${id}`, payload);
  return data;
}

export async function deleteSettingsUser(id: string): Promise<void> {
  await api.delete(`/settings/users/${id}`);
}

// ---- roles & permissions ------------------------------------------------

export interface PermissionMeta {
  key: string;
  category: string;
  label: string;
  description: string;
}

export interface BuiltinRole {
  key: string;
  label: string;
  is_builtin: boolean;
  permissions: string[];
}

export interface CustomRole {
  id: string;
  mssp_org_id: string;
  key: string;
  label: string;
  description: string | null;
  permissions: string[];
  is_builtin: boolean;
  created_at: string;
  updated_at: string;
}

export async function listPermissionCatalog(): Promise<PermissionMeta[]> {
  const { data } = await api.get<PermissionMeta[]>('/roles/permissions');
  return data;
}

export async function listBuiltinRoles(): Promise<BuiltinRole[]> {
  const { data } = await api.get<BuiltinRole[]>('/roles/builtin');
  return data;
}

export async function listCustomRoles(): Promise<CustomRole[]> {
  const { data } = await api.get<CustomRole[]>('/roles');
  return data;
}

export async function createCustomRole(payload: {
  key: string;
  label: string;
  description?: string;
  permissions: string[];
}): Promise<CustomRole> {
  const { data } = await api.post<CustomRole>('/roles', payload);
  return data;
}

export async function updateCustomRole(
  id: string,
  payload: {
    label?: string;
    description?: string;
    permissions?: string[];
  },
): Promise<CustomRole> {
  const { data } = await api.patch<CustomRole>(`/roles/${id}`, payload);
  return data;
}

export async function deleteCustomRole(id: string): Promise<void> {
  await api.delete(`/roles/${id}`);
}

// ---- audit log ----
export interface AuditEntry {
  id: string;
  actor_email: string | null;
  actor_kind: string;
  action: string;
  target: string | null;
  detail: string | null;
  at: string;
}

export async function listAudit(limit = 100): Promise<AuditEntry[]> {
  const { data } = await api.get<AuditEntry[]>('/settings/audit', { params: { limit } });
  return data;
}

export async function listAttackDiffs(limit = 25): Promise<CatalogDiff[]> {
  const { data } = await api.get<CatalogDiff[]>('/settings/attack-diffs', {
    params: { limit },
  });
  return data;
}

// ---- global search ----
export interface SearchHit {
  kind: 'technique' | 'mitigation' | 'apt' | 'detection' | 'customer';
  id: string;
  label: string;
  sub: string | null;
  href: string | null;
}

export async function globalSearch(q: string): Promise<SearchHit[]> {
  if (q.trim().length < 2) return [];
  const { data } = await api.get<{ query: string; hits: SearchHit[] }>(
    '/search',
    { params: { q } },
  );
  return data.hits;
}

// ---- saved views ----
export interface SavedView {
  id: string;
  name: string;
  kind: string;
  payload: Record<string, unknown>;
  author_email: string | null;
  updated_at: string;
}

export async function listSavedViews(kind?: string): Promise<SavedView[]> {
  const { data } = await api.get<SavedView[]>('/views', {
    params: kind ? { kind } : {},
  });
  return data;
}

export async function saveView(payload: {
  name: string;
  kind: string;
  payload: Record<string, unknown>;
}): Promise<SavedView> {
  const { data } = await api.post<SavedView>('/views', payload);
  return data;
}

export async function deleteSavedView(id: string): Promise<void> {
  await api.delete(`/views/${id}`);
}

// ---- custom denominator ----
export interface CustomDenominatorSpec {
  sectors?: string[];
  apt_groups?: string[];
  platforms?: string[];
  operator?: 'union' | 'intersection';
}

export interface CustomDenominatorResult {
  technique_count: number;
  technique_ids: string[];
  sectors: string[];
  apt_groups: string[];
  platforms: string[];
  operator: string;
}

export async function computeCustomDenominator(
  spec: CustomDenominatorSpec,
): Promise<CustomDenominatorResult> {
  const { data } = await api.post<CustomDenominatorResult>(
    '/coverage/denominator/custom',
    spec,
  );
  return data;
}

export async function getCustomCoverageMatrix(
  spec: CustomDenominatorSpec,
): Promise<CoverageMatrix> {
  const { data } = await api.post<CoverageMatrix>(
    '/coverage/matrix-custom',
    spec,
  );
  return data;
}

export async function getCustomCoverageScore(
  spec: CustomDenominatorSpec,
): Promise<CoverageScore> {
  const { data } = await api.post<CoverageScore>(
    '/coverage/score-custom',
    spec,
  );
  return data;
}

// ---- detection outcomes (effectiveness loop) ----
export type OutcomeKind = 'tp' | 'fp' | 'unsure';

export interface DetectionOutcomeRow {
  id: string;
  detection_id: string;
  kind: OutcomeKind;
  summary: string | null;
  reference_url: string | null;
  author_email: string | null;
  observed_at: string;
}

export interface DetectionEffectiveness {
  total: number;
  tp: number;
  fp: number;
  unsure: number;
  precision: number;
}

export async function listDetectionOutcomes(
  detection_id: string,
): Promise<DetectionOutcomeRow[]> {
  const { data } = await api.get<DetectionOutcomeRow[]>(
    `/detections/${detection_id}/outcomes`,
  );
  return data;
}

export async function createDetectionOutcome(
  detection_id: string,
  payload: { kind: OutcomeKind; summary?: string; reference_url?: string },
): Promise<DetectionOutcomeRow> {
  const { data } = await api.post<DetectionOutcomeRow>(
    `/detections/${detection_id}/outcomes`,
    payload,
  );
  return data;
}

export async function deleteDetectionOutcome(id: string): Promise<void> {
  await api.delete(`/detections/outcomes/${id}`);
}

export async function getDetectionEffectiveness(
  detection_id: string,
): Promise<DetectionEffectiveness> {
  const { data } = await api.get<DetectionEffectiveness>(
    `/detections/${detection_id}/effectiveness`,
  );
  return data;
}

// ---- detection event samples (unit tests) ----
export interface DetectionSample {
  id: string;
  detection_id: string;
  label: string;
  kind: 'positive' | 'negative';
  event: Record<string, unknown>;
  expected_match: boolean;
  last_run_at: string | null;
  last_run_pass: boolean | null;
  last_run_message: string | null;
  author_email: string | null;
}

export interface SampleRunResult {
  sample_id: string;
  matched: boolean | null;
  passed: boolean | null;
  message: string;
}

export async function listDetectionSamples(
  detection_id: string,
): Promise<DetectionSample[]> {
  const { data } = await api.get<DetectionSample[]>(
    `/detections/${detection_id}/samples`,
  );
  return data;
}

export async function upsertDetectionSample(
  detection_id: string,
  payload: {
    label: string;
    kind: 'positive' | 'negative';
    event: Record<string, unknown>;
    expected_match?: boolean;
  },
): Promise<DetectionSample> {
  const { data } = await api.post<DetectionSample>(
    `/detections/${detection_id}/samples`,
    payload,
  );
  return data;
}

export async function deleteDetectionSample(id: string): Promise<void> {
  await api.delete(`/detections/samples/${id}`);
}

export async function runDetectionSamples(
  detection_id: string,
): Promise<SampleRunResult[]> {
  const { data } = await api.post<SampleRunResult[]>(
    `/detections/${detection_id}/samples/run`,
  );
  return data;
}

// ---- cross-customer promotion ----
export interface PromotionSuggestion {
  detection_id: string;
  sigma_id: string;
  title: string;
  detection_status: string;
  source: string;
  source_customer_codename: string;
  source_customer_name: string;
  same_sector: boolean;
  techniques: string[];
}

export async function listRulePromotions(): Promise<PromotionSuggestion[]> {
  const { data } = await api.get<PromotionSuggestion[]>(
    '/detections/suggestions',
  );
  return data;
}

export interface PromoteResult {
  id: string;
  sigma_id: string;
  title: string;
  source_customer_codename: string;
  technique_count: number;
}

export async function promoteSuggestion(
  source_codename: string,
  source_detection_id: string,
): Promise<PromoteResult> {
  const { data } = await api.post<PromoteResult>('/detections/promote', {
    source_codename,
    source_detection_id,
  });
  return data;
}

// ---- portfolio compare ----
export interface CompareCustomer {
  codename: string;
  name: string;
  sector: string | null;
  denominator_size: number;
  covered_count: number;
  deployed_count: number;
  breadth_pct: number;
  depth_avg: number;
  breadth_grade: string;
  depth_grade: string;
  posture_grade: string;
  state_counts: Record<string, number>;
  error?: string | null;
}

export interface PortfolioCompare {
  denominator_kind: string;
  denominator_ref: string | null;
  customers: CompareCustomer[];
  best_breadth: string | null;
  worst_breadth: string | null;
}

export async function comparePortfolio(
  codenames: string[],
  query: { denominator?: string; ref?: string } = {},
): Promise<PortfolioCompare> {
  const { data } = await api.get<PortfolioCompare>('/portfolio/compare', {
    params: { customers: codenames.join(','), ...query },
  });
  return data;
}

// ---- ATT&CK notifications ----
export interface AttackNotification {
  domain: string;
  version: string;
  ingested_at: string;
  deprecated_in_use: string[];
  revoked_in_use: string[];
  renamed_in_use: { technique_id: string; old_name: string; new_name: string }[];
  added: string[];
  summary: string;
}

export async function listAttackNotifications(): Promise<AttackNotification[]> {
  const { data } = await api.get<AttackNotification[]>(
    '/settings/attack-notifications',
  );
  return data;
}

// ---- AI-assisted Sigma authoring -----------------------------------------

export interface AIConfig {
  provider: string;
  model: string;
  has_key: boolean;
  key_tail: string | null;
  last_used_at: string | null;
  last_status: string | null;
}

export interface AIConfigPatch {
  provider?: string;
  model?: string;
  api_key?: string;
  clear_key?: boolean;
}

export interface AITestResponse {
  ok: boolean;
  message: string;
  model: string | null;
}

export async function getAIConfig(): Promise<AIConfig> {
  const { data } = await api.get<AIConfig>('/settings/ai-config');
  return data;
}

export async function patchAIConfig(payload: AIConfigPatch): Promise<AIConfig> {
  const { data } = await api.patch<AIConfig>('/settings/ai-config', payload);
  return data;
}

export async function testAIConfig(
  payload: { api_key?: string; model?: string } = {},
): Promise<AITestResponse> {
  const { data } = await api.post<AITestResponse>(
    '/settings/ai-config/test',
    payload,
  );
  return data;
}

export interface AIDraftBrief {
  intent?: string;
  techniques?: string[];
  log_source_product?: string | null;
  log_source_category?: string | null;
  log_source_service?: string | null;
  severity?: string;
  fp_notes?: string;
  reference_urls?: string[];
}

export interface AIDraftResult {
  yaml: string;
  parsed: Record<string, unknown>;
  attempts: number;
  warnings: string[];
}

export async function aiDraftDetection(
  brief: AIDraftBrief,
): Promise<AIDraftResult> {
  const { data } = await api.post<AIDraftResult>('/detections/ai-draft', brief);
  return data;
}

// ---- Catalog schedule settings (super-admin only on the backend) ----------

export interface ScheduledJobRun {
  job: string;
  ran_at: string;
  status: string; // ok | skipped | error
  detail: string | null;
}

export interface CatalogSchedule {
  attack_refresh_enabled: boolean;
  attack_refresh_cron: string;
  sigmahq_refresh_enabled: boolean;
  sigmahq_refresh_cron: string;
  d3fend_refresh_enabled: boolean;
  d3fend_refresh_cron: string;
  snapshot_refresh_enabled: boolean;
  updated_at: string;
  last_runs: Record<string, ScheduledJobRun>;
}

export type CatalogSchedulePatch = Partial<
  Pick<
    CatalogSchedule,
    | 'attack_refresh_enabled'
    | 'attack_refresh_cron'
    | 'sigmahq_refresh_enabled'
    | 'sigmahq_refresh_cron'
    | 'd3fend_refresh_enabled'
    | 'd3fend_refresh_cron'
    | 'snapshot_refresh_enabled'
  >
>;

export async function getCatalogSchedule(): Promise<CatalogSchedule> {
  const { data } = await api.get<CatalogSchedule>('/settings/catalog');
  return data;
}

export async function patchCatalogSchedule(
  payload: CatalogSchedulePatch,
): Promise<CatalogSchedule> {
  const { data } = await api.patch<CatalogSchedule>(
    '/settings/catalog',
    payload,
  );
  return data;
}

// ---- LDAP / Active Directory auth config (super-admin only) --------------

export interface LdapConfig {
  enabled: boolean;
  host: string | null;
  bind_dn: string | null;
  has_bind_password: boolean;
  bind_password_tail: string | null;
  user_search_base: string | null;
  user_filter: string;
  email_attr: string;
  full_name_attr: string;
  default_role: string;
  start_tls: boolean;
  verify_cert: boolean;
  group_attr: string;
  group_mappings: Record<string, string>;
  updated_at: string;
}

export interface LdapConfigPatch {
  enabled?: boolean;
  host?: string;
  bind_dn?: string;
  bind_password?: string;
  clear_bind_password?: boolean;
  user_search_base?: string;
  user_filter?: string;
  email_attr?: string;
  full_name_attr?: string;
  default_role?: string;
  start_tls?: boolean;
  verify_cert?: boolean;
  group_attr?: string;
  group_mappings?: Record<string, string>;
}

export async function getLdapConfig(): Promise<LdapConfig> {
  const { data } = await api.get<LdapConfig>('/settings/ldap-config');
  return data;
}

export async function patchLdapConfig(payload: LdapConfigPatch): Promise<LdapConfig> {
  const { data } = await api.patch<LdapConfig>('/settings/ldap-config', payload);
  return data;
}

export interface LdapTestResponse {
  ok: boolean;
  message: string;
}

export async function testLdapConfig(
  payload: { username?: string; password?: string } = {},
): Promise<LdapTestResponse> {
  const { data } = await api.post<LdapTestResponse>('/settings/ldap-config/test', payload);
  return data;
}

// ---- Outbound mail / SMTP ------------------------------------------------

export interface MailConfig {
  enabled: boolean;
  host: string | null;
  port: number;
  username: string | null;
  has_password: boolean;
  password_tail: string | null;
  from_address: string | null;
  from_name: string;
  use_tls: boolean;
  use_ssl: boolean;
  updated_at: string;
}

export interface MailConfigPatch {
  enabled?: boolean;
  host?: string;
  port?: number;
  username?: string;
  password?: string;
  clear_password?: boolean;
  from_address?: string;
  from_name?: string;
  use_tls?: boolean;
  use_ssl?: boolean;
}

export async function getMailConfig(): Promise<MailConfig> {
  const { data } = await api.get<MailConfig>('/settings/mail-config');
  return data;
}

export async function patchMailConfig(payload: MailConfigPatch): Promise<MailConfig> {
  const { data } = await api.patch<MailConfig>('/settings/mail-config', payload);
  return data;
}

export async function testMailConfig(
  payload: { to?: string } = {},
): Promise<{ ok: boolean; message: string }> {
  const { data } = await api.post<{ ok: boolean; message: string }>(
    '/settings/mail-config/test',
    payload,
  );
  return data;
}

// ---- D3FEND --------------------------------------------------------------

export interface D3FENDTechniqueRow {
  d3fend_id: string;
  name: string;
  definition: string | null;
  parent_d3fend_id: string | null;
  kind: string | null;
  url: string | null;
}

export interface D3FENDDefense {
  d3fend_id: string;
  name: string;
  relation: string | null;
  url: string | null;
}

export async function listD3FENDTechniques(
  q?: string,
): Promise<D3FENDTechniqueRow[]> {
  const { data } = await api.get<D3FENDTechniqueRow[]>(
    '/catalog/d3fend/techniques',
    { params: q ? { q } : {} },
  );
  return data;
}

export async function refreshD3FENDCatalog(force = false): Promise<{ task_id: string }> {
  const { data } = await api.post<{ task_id: string }>(
    '/catalog/d3fend/refresh',
    { force },
  );
  return data;
}
