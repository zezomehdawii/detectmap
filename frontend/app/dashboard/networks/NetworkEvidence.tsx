import { useEffect, useId, useState } from 'react';
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Divider,
  IconButton,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material';
import AddRoundedIcon from '@mui/icons-material/AddRounded';
import ExpandMoreRoundedIcon from '@mui/icons-material/ExpandMoreRounded';
import LinkOffRoundedIcon from '@mui/icons-material/LinkOffRounded';
import {
  getNetworkCoverage,
  type NetworkAssetEvidence,
  type NetworkAssignment,
  type NetworkCoverage,
  type NetworkOut,
  type NetworkRuleEvidence,
  type NetworkSourceEvidence,
  setNetworkAssignment,
} from '@/lib/api';
import { apiErrorMessage } from '@/lib/cmf-utils';
import NetworkAssignmentDialog from './NetworkAssignmentDialog';

const monitoringLabels = {
  no_sources: 'No active scoped sources',
  configured: 'Scoped sources configured',
  partially_validated: 'Some scoped sources validated',
  validated: 'Scoped sources validated',
} as const satisfies Record<NetworkCoverage['monitoring_status'], string>;

const detectionLabels = {
  no_rules: 'No rules assigned',
  mapped: 'Rules assigned',
  partially_supported: 'Some deployment evidence',
  supported: 'Rules have deployment evidence',
} as const satisfies Record<NonNullable<NetworkCoverage['detection_status']>, string>;

const ruleLabels = {
  mapped: { text: 'Assigned', color: 'default' },
  enabled_without_source: { text: 'Enabled SIEM rule · source unlinked', color: 'warning' },
  enabled_with_source: { text: 'Enabled SIEM rule and configured source', color: 'info' },
  enabled_with_validated_source: { text: 'Enabled SIEM rule and validated source', color: 'success' },
} as const satisfies Record<NonNullable<NetworkRuleEvidence['evidence_status']>, { text: string; color: string }>;

type RemoveAssignment = (id: string) => void;

function formatDate(value: string): string {
  return new Date(value).toLocaleString();
}

function SourcesTable({ sources, showConnectors, onRemove, removing }: {
  sources: NetworkSourceEvidence[];
  showConnectors: boolean;
  onRemove?: RemoveAssignment;
  removing?: boolean;
}) {
  if (sources.length === 0) {
    return <Typography variant="body2" color="text.secondary">No collection sources recorded for this scope.</Typography>;
  }
  return (
    <TableContainer>
      <Table size="small" aria-label="Collection sources" sx={{ minWidth: 380 }}>
        <TableHead>
          <TableRow>
            <TableCell>Source / asset</TableCell>
            <TableCell>Collection status</TableCell>
            {showConnectors && <TableCell>Connector</TableCell>}
            {onRemove && <TableCell align="right">Actions</TableCell>}
          </TableRow>
        </TableHead>
        <TableBody>
          {sources.map((source) => {
            const decommissioned = source.asset_status === 'decommissioned';
            const active = source.enabled && !decommissioned;
            const status = active ? (source.validated_at ? 'Validated' : 'Configured') : 'Inactive';
            return (
              <TableRow key={source.id}>
                <TableCell sx={{ overflowWrap: 'anywhere' }}>
                  {source.name}
                  <Typography variant="caption" display="block" color="text.secondary">
                    {source.asset_name}{decommissioned && ' · decommissioned'}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Chip
                    size="small"
                    variant="outlined"
                    color={status === 'Validated' ? 'success' : 'default'}
                    label={status}
                  />
                  {active && source.validated_at && (
                    <Typography variant="caption" display="block" color="text.secondary">
                      Record updated {formatDate(source.validated_at)}
                    </Typography>
                  )}
                </TableCell>
                {showConnectors && (
                  <TableCell sx={{ overflowWrap: 'anywhere' }}>
                    {source.connector_label ?? '—'}
                    {source.storage_location && (
                      <Typography variant="caption" display="block" color="text.secondary">{source.storage_location}</Typography>
                    )}
                  </TableCell>
                )}
                {onRemove && (
                  <TableCell align="right">
                    <IconButton
                      aria-label={`Unassign collection source ${source.name}`}
                      size="small"
                      onClick={() => onRemove(source.id)}
                      disabled={removing}
                    >
                      <LinkOffRoundedIcon fontSize="small" />
                    </IconButton>
                  </TableCell>
                )}
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </TableContainer>
  );
}

function RulesTable({ rules, sources, showDeployments, onRemove, removing }: {
  rules: NetworkRuleEvidence[];
  sources: NetworkSourceEvidence[];
  showDeployments: boolean;
  onRemove?: RemoveAssignment;
  removing?: boolean;
}) {
  if (rules.length === 0) {
    return <Typography variant="body2" color="text.secondary">No detection rules recorded for this scope.</Typography>;
  }
  const names = new Map(sources.map((source) => [source.id, source.name]));
  return (
    <TableContainer>
      <Table size="small" aria-label="Detection rules" sx={{ minWidth: showDeployments ? 540 : 300 }}>
        <TableHead>
          <TableRow>
            <TableCell>Rule</TableCell>
            <TableCell>Evidence</TableCell>
            {showDeployments && <TableCell>Confirmed SIEM matches</TableCell>}
            {onRemove && <TableCell align="right">Actions</TableCell>}
          </TableRow>
        </TableHead>
        <TableBody>
          {rules.map((rule) => {
            const evidence = ruleLabels[rule.evidence_status ?? 'mapped'];
            return (
              <TableRow key={rule.id} sx={{ '& > td': { verticalAlign: 'top' } }}>
                <TableCell sx={{ overflowWrap: 'anywhere' }}>
                  {rule.title}
                  <Typography variant="caption" display="block" color="text.secondary">
                    Library status · {rule.status.replaceAll('_', ' ')}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Chip
                    label={evidence.text}
                    color={evidence.color}
                    variant="outlined"
                    size="small"
                    sx={{ height: 'auto', '& .MuiChip-label': { whiteSpace: 'normal', py: 0.25 } }}
                  />
                </TableCell>
                {showDeployments && (
                  <TableCell sx={{ overflowWrap: 'anywhere' }}>
                    {!rule.deployments.length && 'No confirmed match'}
                    <Stack spacing={0.75} divider={<Divider flexItem />}>
                      {rule.deployments.map((deployment) => {
                        const sharedSources = deployment.source_ids.map((id) => names.get(id)).filter(Boolean);
                        return (
                          <Box key={deployment.id}>
                            {deployment.name}
                            <Typography variant="caption" color="text.secondary" display="block">
                              {deployment.enabled ? 'Enabled' : 'Disabled'}{deployment.connector_label && ` · ${deployment.connector_label}`}
                            </Typography>
                            {deployment.synced_at && (
                              <Typography variant="caption" color="text.secondary" display="block">
                                {deployment.import_source === 'csv' ? 'CSV import' : 'SIEM sync'} · {formatDate(deployment.synced_at)}
                              </Typography>
                            )}
                            {deployment.confirmed_at && (
                              <Typography variant="caption" color="text.secondary" display="block">
                                Match updated {formatDate(deployment.confirmed_at)}
                              </Typography>
                            )}
                            {sharedSources.length > 0 && (
                              <Typography variant="caption" color="text.secondary" display="block">
                                Shared connector · {sharedSources.join(', ')}
                              </Typography>
                            )}
                          </Box>
                        );
                      })}
                    </Stack>
                  </TableCell>
                )}
                {onRemove && (
                  <TableCell align="right">
                    <IconButton
                      aria-label={`Unassign detection rule ${rule.title}`}
                      size="small"
                      onClick={() => onRemove(rule.id)}
                      disabled={removing}
                    >
                      <LinkOffRoundedIcon fontSize="small" />
                    </IconButton>
                  </TableCell>
                )}
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </TableContainer>
  );
}

function AssetEvidence({ asset, showRules, showDeployments }: {
  asset: NetworkAssetEvidence;
  showRules: boolean;
  showDeployments: boolean;
}) {
  const id = useId();
  const hasConfiguredSource = asset.status !== 'decommissioned' && asset.data_sources.some((source) => source.enabled);
  const hasValidatedSource = hasConfiguredSource && asset.data_sources.some((source) => source.enabled && source.validated_at);
  return (
    <Accordion disableGutters variant="outlined" slotProps={{ transition: { unmountOnExit: true } }}>
      <AccordionSummary expandIcon={<ExpandMoreRoundedIcon />} id={`${id}-header`} aria-controls={`${id}-details`}>
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} alignItems={{ sm: 'center' }} sx={{ flex: 1, pr: 1, minWidth: 0 }}>
          <Box sx={{ flex: 1, overflowWrap: 'anywhere' }}>
            <Typography variant="subtitle2">{asset.name}</Typography>
            <Typography variant="caption" color="text.secondary">
              <Box component="span" sx={{ fontFamily: 'monospace' }}>{asset.ip_address}</Box> · {asset.kind.replaceAll('_', ' ')} · {asset.status}
            </Typography>
          </Box>
          <Chip
            size="small"
            variant="outlined"
            color={hasValidatedSource ? 'success' : 'default'}
            label={hasValidatedSource ? 'Validated source' : hasConfiguredSource ? 'Configured source' : 'No active source'}
            sx={{ alignSelf: { xs: 'flex-start', sm: 'center' } }}
          />
        </Stack>
      </AccordionSummary>
      <AccordionDetails>
        <Stack spacing={2}>
          <SourcesTable sources={asset.data_sources} showConnectors={showDeployments} />
          {showRules && <RulesTable rules={asset.rules} sources={asset.data_sources} showDeployments={showDeployments} />}
        </Stack>
      </AccordionDetails>
    </Accordion>
  );
}

type EvidenceResult = { revision: number; assignmentVersion: number } & (
  { data: NetworkCoverage; error?: never } | { error: string; data?: never }
);

export default function NetworkEvidence({ network, customer, canWrite, revision }: {
  network: NetworkOut;
  customer: string;
  canWrite: boolean;
  revision: number;
}) {
  const [result, setResult] = useState<EvidenceResult | null>(null);
  const [assignment, setAssignment] = useState<NetworkAssignment | null>(null);
  const [assignmentVersion, setAssignmentVersion] = useState(0);
  const [removing, setRemoving] = useState(false);
  const [assignmentError, setAssignmentError] = useState<string | null>(null);
  const current = result?.revision === revision && result.assignmentVersion === assignmentVersion ? result : null;

  useEffect(() => {
    let active = true;
    getNetworkCoverage(network.id, customer).then((data) => {
      if (active) setResult({ data, revision, assignmentVersion });
    }).catch((err) => {
      if (active) setResult({ error: apiErrorMessage(err, 'Could not load network coverage.'), revision, assignmentVersion });
    });
    return () => { active = false; };
  }, [assignmentVersion, customer, network.id, revision]);

  async function unassign(kind: NetworkAssignment, id: string) {
    setRemoving(true);
    setAssignmentError(null);
    try {
      await setNetworkAssignment(network.id, kind, id, false, customer);
      setAssignmentVersion((value) => value + 1);
    } catch (err) {
      setAssignmentError(apiErrorMessage(err, 'Could not remove the assignment.'));
    } finally {
      setRemoving(false);
    }
  }

  if (!current) return <CircularProgress size={24} aria-label="Loading network coverage" />;
  if (current.error) return <Alert severity="error">{current.error}</Alert>;
  const data = current.data;
  if (!data) return null;
  return (
    <Stack spacing={2}>
      {assignmentError && <Alert severity="error" onClose={() => setAssignmentError(null)}>{assignmentError}</Alert>}
      <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 270px), 1fr))', gap: 2 }}>
        <Card variant="outlined">
          <CardContent>
            <Typography component="h3" variant="subtitle1" fontWeight={700}>Network monitoring</Typography>
            <Chip
              size="small"
              variant="outlined"
              color={data.monitoring_status === 'validated' ? 'success' : data.monitoring_status === 'no_sources' ? 'default' : 'info'}
              label={monitoringLabels[data.monitoring_status]}
              sx={{ mt: 1 }}
            />
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              Based on enabled collection sources assigned to this subnet and their recorded CMF validation.
            </Typography>
          </CardContent>
        </Card>
        <Card variant="outlined">
          <CardContent>
            <Typography component="h3" variant="subtitle1" fontWeight={700}>Network detection</Typography>
            <Chip
              size="small"
              variant="outlined"
              color={data.detection_status === 'supported' ? 'success' : data.detection_status === 'partially_supported' ? 'info' : 'default'}
              label={data.detection_status ? detectionLabels[data.detection_status] : 'Deployment evidence unavailable'}
              sx={{ mt: 1 }}
            />
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              Deployment evidence links confirmed SIEM rules to assigned sources using a shared connector. Review rule scope in the SIEM.
            </Typography>
          </CardContent>
        </Card>
      </Box>
      <Card variant="outlined">
        <CardContent>
          <Stack spacing={1.5}>
            <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" alignItems={{ sm: 'center' }} spacing={1}>
              <Typography component="h3" variant="h6">Scoped collection sources ({data.data_sources.length})</Typography>
              {canWrite && (
                <Button startIcon={<AddRoundedIcon />} disabled={removing} onClick={() => setAssignment('data-sources')} sx={{ alignSelf: 'flex-start' }}>
                  Assign collection source
                </Button>
              )}
            </Stack>
            <SourcesTable
              sources={data.data_sources}
              showConnectors={data.connector_evidence_available}
              onRemove={canWrite ? (id) => void unassign('data-sources', id) : undefined}
              removing={removing}
            />
          </Stack>
        </CardContent>
      </Card>
      {data.detection_evidence_available && (
        <Card variant="outlined">
          <CardContent>
            <Stack spacing={1.5}>
              <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" alignItems={{ sm: 'center' }} spacing={1}>
                <Typography component="h3" variant="h6">Scoped detection rules ({data.rules.length})</Typography>
                {canWrite && (
                  <Button startIcon={<AddRoundedIcon />} disabled={removing} onClick={() => setAssignment('detections')} sx={{ alignSelf: 'flex-start' }}>
                    Assign detection rule
                  </Button>
                )}
              </Stack>
              <RulesTable
                rules={data.rules}
                sources={data.data_sources}
                showDeployments={data.connector_evidence_available}
                onRemove={canWrite ? (id) => void unassign('detections', id) : undefined}
                removing={removing}
              />
            </Stack>
          </CardContent>
        </Card>
      )}
      <Card variant="outlined">
        <CardContent>
          <Stack spacing={1.5}>
            <Box>
              <Typography component="h3" variant="h6">Assets in the subnet ({data.assets.length})</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                Based on each asset’s primary IP. {data.monitored_asset_count} with enabled collection sources · {data.validated_asset_count} with validated sources.
              </Typography>
            </Box>
            {data.assets.length === 0 && <Typography variant="body2" color="text.secondary">No registered primary IPs match this subnet.</Typography>}
            <Box>
              {data.assets.map((asset) => (
                <AssetEvidence
                  key={asset.id}
                  asset={asset}
                  showRules={data.detection_evidence_available}
                  showDeployments={data.connector_evidence_available}
                />
              ))}
            </Box>
          </Stack>
        </CardContent>
      </Card>
      {assignment && (
        <NetworkAssignmentDialog
          networkId={network.id}
          customer={customer}
          kind={assignment}
          assignedIds={(assignment === 'data-sources' ? data.data_sources : data.rules).map((item) => item.id)}
          onClose={() => setAssignment(null)}
          onAssigned={() => {
            setAssignment(null);
            setAssignmentError(null);
            setAssignmentVersion((value) => value + 1);
          }}
        />
      )}
    </Stack>
  );
}
