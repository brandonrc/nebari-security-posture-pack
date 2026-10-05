import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Lock, Save, Undo2 } from 'lucide-react';
import { type ReactNode, useState } from 'react';
import { api } from '@/api/client';
import { qk, useReportTypes, useScanners, useSettings } from '@/api/queries';
import type { Baseline, ControlsEngineSettings, ProvenanceSettings, ScannerName, ScapContentVersion, ScapSettings, Settings, UpdateLevel } from '@/api/types';
import { BASELINES, SCANNERS } from '@/api/types';
import { SimpleSelect } from '@/components/simple-select';
import { CardsSkeleton, ErrorAlert, PageHeader, errorMessage } from '@/components/page';
import { SCANNER_LABEL } from '@/components/posture';
import { TagInput } from '@/components/tag-input';
import { SourceBadge } from '@/components/stig';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Textarea } from '@/components/ui/textarea';
import { formatAge } from '@/lib/format';
import { toast } from '@/components/ui/toast';

const DNS_LABEL = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
const SLA_KEYS = ['critical', 'high', 'medium', 'low'] as const;

function Row({ id, label, hint, children }: { id?: string; label: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <div className="grid gap-2 md:grid-cols-[minmax(0,260px)_1fr] md:gap-6">
      <div>
        <Label htmlFor={id}>{label}</Label>
        {hint ? <p className="mt-0.5 text-muted-foreground text-xs">{hint}</p> : null}
      </div>
      <div className="min-w-0">{children}</div>
    </div>
  );
}

function NumberInput({ id, value, onChange, min, max, suffix }: { id: string; value: number; onChange: (n: number) => void; min: number; max: number; suffix?: string }) {
  const invalid = !Number.isFinite(value) || value < min || value > max;
  return (
    <div className="flex items-center gap-2">
      <div className="w-32">
        <Input id={id} type="number" inputMode="numeric" min={min} max={max} value={Number.isFinite(value) ? value : ''} aria-invalid={invalid || undefined} onChange={(e) => onChange(e.target.value === '' ? Number.NaN : Number(e.target.value))} />
      </div>
      {suffix ? <span className="text-muted-foreground text-sm">{suffix}</span> : null}
      {invalid ? <span className="text-destructive-foreground text-xs">{min}–{max}</span> : null}
    </div>
  );
}


function Toggle({ checked, onChange, label, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean }) {
  return (
    <label className="flex items-center gap-2 text-sm">
      <Switch checked={checked} onCheckedChange={onChange} aria-label={label} disabled={disabled} />
      {label}
    </label>
  );
}

const UPDATE_LEVELS: Array<{ value: UpdateLevel; label: string }> = [
  { value: 'patch', label: 'Patch (x.y.Z)' },
  { value: 'minor', label: 'Minor (x.Y.z)' },
  { value: 'major', label: 'Major (X.y.z)' },
];

const DEFAULT_PROVENANCE: ProvenanceSettings = {
  verifySignatures: true,
  cosignPublicKey: '',
  cosignCertificateIdentityRegexp: '',
  cosignCertificateOidcIssuerRegexp: '',
  checkSbom: true,
  checkProvenance: true,
  checkUpdates: true,
  updateLevel: 'patch',
  skipPrerelease: true,
  helmReleases: true,
};
const DEFAULT_CONTROLS: ControlsEngineSettings = { enabled: true, baseline: 'moderate', adminSubjects: [] };
const DEFAULT_SCAP: ScapSettings = { sources: [], preferDisa: true, timeoutSeconds: 900 };
const SCAP_TIMEOUT = { min: 60, max: 24 * 3600 };

/** Edit form: every section filled in, except §14 `scap`, which stays absent on APIs without it. */
type Form = Required<Omit<Settings, 'scap'>> & Pick<Settings, 'scap'>;

/** The SCAP section shows when the API knows about it (`scap` or `scanners.scap` present). */
const hasScap = (s: Pick<Settings, 'scap' | 'scanners'>) => s.scap !== undefined || s.scanners.scap !== undefined;

function normalise(s: Settings): Form {
  const p = s.provenance;
  const c = s.controlsEngine;
  return {
    ...s,
    ...(hasScap(s) ? { scap: { ...DEFAULT_SCAP, ...s.scap, sources: Array.isArray(s.scap?.sources) ? s.scap.sources : [] } } : {}),
    provenance: { ...DEFAULT_PROVENANCE, ...p },
    controlsEngine: { ...DEFAULT_CONTROLS, ...c, adminSubjects: c?.adminSubjects ?? [] },
    systemName: s.systemName ?? '',
    organization: s.organization ?? '',
    remediationSlaDays: s.remediationSlaDays ?? { critical: 15, high: 30, medium: 90, low: 180 },
    reports: s.reports ?? { autoGenerate: [] },
  };
}

export function SettingsPage() {
  const { data, error, isLoading, refetch } = useSettings();
  const reportTypes = useReportTypes();
  const queryClient = useQueryClient();
  const [form, setForm] = useState<Form | null>(() => (data ? normalise(data) : null));
  const [source, setSource] = useState(data);
  // key vs keyless is implied by cosignPublicKey; keep the user's pick while the key is still empty
  const [keyModeChoice, setKeyMode] = useState<boolean | null>(null);
  const keyMode = keyModeChoice ?? Boolean(form?.provenance.cosignPublicKey);
  // re-seed the form whenever fresh server data arrives (load or after save)
  if (data !== source) {
    setSource(data);
    setForm(data ? normalise(data) : null);
    setKeyMode(null);
  }

  const save = useMutation({
    mutationFn: (settings: Settings) => api.saveSettings(settings),
    onSuccess: (saved) => {
      queryClient.setQueryData(qk.settings, saved);
      toast.add({ title: 'Settings saved', description: 'The worker picks up changes on its next scheduler tick.', type: 'success' });
    },
    onError: (e) => toast.add({ title: 'Could not save settings', description: errorMessage(e), type: 'error' }),
  });

  const set = <K extends keyof Settings>(key: K, value: Settings[K]) => setForm((f) => (f ? { ...f, [key]: value } : f));
  const dirty = form && data ? JSON.stringify(form) !== JSON.stringify(normalise(data)) : false;
  const valid =
    form !== null &&
    form.scanIntervalHours >= 1 &&
    form.scanIntervalHours <= 168 &&
    form.rescanAfterHours >= 0 &&
    form.rescanAfterHours <= 720 &&
    form.parallelism >= 1 &&
    form.parallelism <= 16 &&
    SLA_KEYS.every((k) => form.remediationSlaDays[k] >= 1) &&
    SCANNERS.some((s) => form.scanners[s]) &&
    (!form.scap || (form.scap.timeoutSeconds >= SCAP_TIMEOUT.min && form.scap.timeoutSeconds <= SCAP_TIMEOUT.max)) &&
    (!form.provenance.verifySignatures || !keyMode || Boolean(form.provenance.cosignPublicKey.trim()));
  const prov = form?.provenance;
  const setProv = (patch: Partial<ProvenanceSettings>) => form && set('provenance', { ...form.provenance, ...patch });
  const setCtl = (patch: Partial<ControlsEngineSettings>) => form && set('controlsEngine', { ...form.controlsEngine, ...patch });
  const setScap = (patch: Partial<ScapSettings>) => form && set('scap', { ...DEFAULT_SCAP, ...form.scap, ...patch });
  const scapOn = form ? hasScap(form) : false;
  const scanners = useScanners(scapOn);
  const contentVersions = scanners.data?.find((s) => s.name === 'scap')?.contentVersions ?? [];

  return (
    <>
      <PageHeader title="Settings" description="Scan schedule, scanners, supply-chain checks, control evidence and compliance reporting. Stored in the database; Helm values provide defaults." />
      {error ? <ErrorAlert error={error} onRetry={() => void refetch()} /> : null}
      {isLoading || (!form && !error) ? <CardsSkeleton count={2} className="xl:grid-cols-2" /> : null}
      {form ? (
        <form
          className="flex flex-col gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (valid) save.mutate(form);
          }}
        >
          <Card>
            <CardHeader>
              <CardTitle>Scanning</CardTitle>
              <CardDescription>How often the worker inventories the cluster and which images get rescanned.</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-5">
              <Row id="interval" label="Scan interval" hint="Scheduled full inventory + scan.">
                <NumberInput id="interval" value={form.scanIntervalHours} min={1} max={168} suffix="hours" onChange={(n) => set('scanIntervalHours', n)} />
              </Row>
              <Row id="rescan" label="Rescan after" hint="Unchanged digests are rescanned once their last scan is older than this.">
                <NumberInput id="rescan" value={form.rescanAfterHours} min={0} max={720} suffix="hours" onChange={(n) => set('rescanAfterHours', n)} />
              </Row>
              <Row id="parallelism" label="Parallelism" hint="Images scanned concurrently (each by all enabled scanners).">
                <NumberInput id="parallelism" value={form.parallelism} min={1} max={16} suffix="images" onChange={(n) => set('parallelism', n)} />
              </Row>
              <Row label="Excluded namespaces" hint="Not inventoried or scored. kube-system is scanned by default.">
                <TagInput
                  ariaLabel="Add excluded namespace"
                  placeholder="namespace, then Enter"
                  value={form.excludedNamespaces}
                  onChange={(v) => set('excludedNamespaces', v)}
                  validate={(t) => (DNS_LABEL.test(t) && t.length <= 63 ? null : 'Must be a valid namespace name (RFC 1123 label)')}
                />
              </Row>
              <Row label="Scanners" hint="At least one scanner must stay enabled. Consensus weighting uses the scanners that succeed.">
                <div className="flex flex-wrap gap-6">
                  {SCANNERS.map((s: ScannerName) => (
                    <label key={s} className="flex items-center gap-2 text-sm">
                      <Switch checked={form.scanners[s]} onCheckedChange={(v) => set('scanners', { ...form.scanners, [s]: v })} aria-label={`Enable ${SCANNER_LABEL[s]}`} />
                      {SCANNER_LABEL[s]}
                    </label>
                  ))}
                </div>
                {!SCANNERS.some((s) => form.scanners[s]) ? <p className="mt-1 text-destructive-foreground text-xs">Enable at least one scanner.</p> : null}
              </Row>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Compliance reporting</CardTitle>
              <CardDescription>Used on POA&amp;M, STIG checklist, SAR and OSCAL outputs.</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-5">
              <Row id="systemName" label="System name" hint="Defaults to the cluster name.">
                <div className="max-w-sm">
                  <Input id="systemName" value={form.systemName} onChange={(e) => set('systemName', e.target.value)} />
                </div>
              </Row>
              <Row id="organization" label="Organization">
                <div className="max-w-sm">
                  <Input id="organization" value={form.organization} onChange={(e) => set('organization', e.target.value)} />
                </div>
              </Row>
              <Row label="Remediation SLA" hint="Days from first seen; drives POA&M scheduled completion and overdue flags.">
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                  {SLA_KEYS.map((k) => (
                    <div key={k} className="flex flex-col gap-1">
                      <Label htmlFor={`sla-${k}`} className="text-muted-foreground text-xs capitalize">
                        {k}
                      </Label>
                      <NumberInput id={`sla-${k}`} value={form.remediationSlaDays[k]} min={1} max={3650} suffix="days" onChange={(n) => set('remediationSlaDays', { ...form.remediationSlaDays, [k]: n })} />
                    </div>
                  ))}
                </div>
              </Row>
              <Row label="Auto-generate reports" hint="Generated after every completed scan.">
                <div className="grid gap-2 sm:grid-cols-2">
                  {(reportTypes.data ?? []).map((t) => (
                    <Checkbox
                      key={t.type}
                      checked={form.reports.autoGenerate.includes(t.type)}
                      onCheckedChange={(checked) =>
                        set('reports', {
                          autoGenerate: checked ? [...form.reports.autoGenerate, t.type] : form.reports.autoGenerate.filter((x) => x !== t.type),
                        })
                      }
                      description={t.formats.join(', ')}
                    >
                      {t.title ?? t.type}
                    </Checkbox>
                  ))}
                  {reportTypes.isLoading ? <span className="text-muted-foreground text-sm">Loading report types…</span> : null}
                </div>
              </Row>
            </CardContent>
          </Card>

          {prov ? (
            <Card>
              <CardHeader>
                <CardTitle>Supply chain</CardTitle>
                <CardDescription>Signature, SBOM, SLSA provenance and update checks run per image after inventory (DESIGN §12).</CardDescription>
              </CardHeader>
              <CardContent className="flex flex-col gap-5">
                <Row label="Stage">
                  <Toggle label="Run supply-chain checks during scans" checked={prov.enabled ?? true} onChange={(v) => setProv({ enabled: v })} />
                </Row>
                <Row label="Signatures" hint="cosign verify; without verification only signature existence is checked.">
                  <div className="flex flex-col gap-3">
                    <Toggle label="Verify signatures" checked={prov.verifySignatures} onChange={(v) => setProv({ verifySignatures: v })} />
                    <div className="flex flex-wrap items-center gap-3">
                      <span className="text-muted-foreground text-sm">Mode</span>
                      <SimpleSelect
                        ariaLabel="Cosign verification mode"
                        className="w-44"
                        value={keyMode ? 'key' : 'keyless'}
                        disabled={!prov.verifySignatures}
                        onChange={(v) => {
                          setKeyMode(v === 'key');
                          if (v !== 'key') setProv({ cosignPublicKey: '' });
                        }}
                        options={[
                          { value: 'keyless', label: 'Keyless (Fulcio/Rekor)' },
                          { value: 'key', label: 'Public key' },
                        ]}
                      />
                    </div>
                  </div>
                </Row>
                {keyMode ? (
                  <Row id="cosign-key" label="Cosign public key" hint="PEM text, a file path or a KMS URI.">
                    <Textarea
                      id="cosign-key"
                      rows={4}
                      className="font-mono text-xs"
                      placeholder="-----BEGIN PUBLIC KEY-----"
                      value={prov.cosignPublicKey}
                      disabled={!prov.verifySignatures}
                      aria-invalid={prov.verifySignatures && !prov.cosignPublicKey.trim() ? true : undefined}
                      onChange={(e) => setProv({ cosignPublicKey: e.target.value })}
                    />
                    {prov.verifySignatures && !prov.cosignPublicKey.trim() ? <p className="mt-1 text-destructive-foreground text-xs">A public key is required in key mode.</p> : null}
                  </Row>
                ) : (
                  <Row id="cosign-identity" label="Keyless identity" hint="Certificate identity and OIDC issuer (regular expressions) accepted for keyless verification.">
                    <div className="grid max-w-xl gap-2">
                      <Input id="cosign-identity" placeholder="https://github.com/org/.*" value={prov.cosignCertificateIdentityRegexp} disabled={!prov.verifySignatures} onChange={(e) => setProv({ cosignCertificateIdentityRegexp: e.target.value })} />
                      <Input aria-label="Certificate OIDC issuer" placeholder="https://token.actions.githubusercontent.com" value={prov.cosignCertificateOidcIssuerRegexp} disabled={!prov.verifySignatures} onChange={(e) => setProv({ cosignCertificateOidcIssuerRegexp: e.target.value })} />
                    </div>
                  </Row>
                )}
                <Row label="Attestations" hint="Looked up via the OCI referrers API and cosign attestation tags.">
                  <div className="flex flex-wrap gap-6">
                    <Toggle label="Check SBOM" checked={prov.checkSbom} onChange={(v) => setProv({ checkSbom: v })} />
                    <Toggle label="Check SLSA provenance" checked={prov.checkProvenance} onChange={(v) => setProv({ checkProvenance: v })} />
                  </div>
                </Row>
                <Row label="Updates" hint="skopeo list-tags + semver comparison. Level sets the smallest change reported.">
                  <div className="flex flex-col gap-3">
                    <Toggle label="Check for image updates" checked={prov.checkUpdates} onChange={(v) => setProv({ checkUpdates: v })} />
                    <div className="flex flex-wrap items-center gap-6">
                      <span className="flex items-center gap-3">
                        <span className="text-muted-foreground text-sm">Update level</span>
                        <SimpleSelect ariaLabel="Update level" className="w-40" value={prov.updateLevel} disabled={!prov.checkUpdates} onChange={(v) => setProv({ updateLevel: v as UpdateLevel })} options={UPDATE_LEVELS} />
                      </span>
                      <Toggle label="Skip pre-releases" checked={prov.skipPrerelease} disabled={!prov.checkUpdates} onChange={(v) => setProv({ skipPrerelease: v })} />
                    </div>
                  </div>
                </Row>
                <Row label="Helm releases" hint="Reads sh.helm.release.v1.* secrets cluster-wide (needs the optional RBAC rule).">
                  <Toggle label="Discover Helm releases" checked={prov.helmReleases} onChange={(v) => setProv({ helmReleases: v })} />
                </Row>
              </CardContent>
            </Card>
          ) : null}

          {scapOn ? (
            <ScapCard
              enabled={Boolean(form.scanners.scap)}
              scap={{ ...DEFAULT_SCAP, ...form.scap }}
              contentVersions={contentVersions}
              onEnabled={(v) => set('scanners', { ...form.scanners, scap: v })}
              onChange={setScap}
            />
          ) : null}

          <Card>
            <CardHeader>
              <CardTitle>Control evidence engine</CardTitle>
              <CardDescription>Live NIST 800-53 assertions after every scan; feeds the Controls tab and the OSCAL SSP (DESIGN §13).</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-5">
              <Row label="Engine">
                <Toggle label="Run control assertions after each scan" checked={form.controlsEngine.enabled} disabled onChange={(v) => setCtl({ enabled: v })} />
                <p className="mt-1 text-muted-foreground text-xs">Set by the Helm value <code className="font-mono">controlsEngine.enabled</code>; read-only here.</p>
              </Row>
              <Row label="Baseline" hint="NIST SP 800-53B baseline used for coverage and the SSP.">
                <SimpleSelect
                  ariaLabel="Control baseline"
                  className="w-44"
                  value={form.controlsEngine.baseline}
                  onChange={(v) => setCtl({ baseline: v as Baseline })}
                  options={BASELINES.map((b) => ({ value: b, label: `${b[0].toUpperCase()}${b.slice(1)}` }))}
                />
              </Row>
              <Row label="Admin subjects allowlist" hint="Keycloak realm admins and cluster-admin subjects that assertions accept (e.g. nebari-admin, User/admin, Group/platform-ops).">
                <TagInput
                  ariaLabel="Add admin subject"
                  placeholder="subject, then Enter"
                  value={form.controlsEngine.adminSubjects}
                  onChange={(v) => setCtl({ adminSubjects: v })}
                  validate={(t) => (/^[\w.@:/-]{1,253}$/.test(t) ? null : 'Letters, digits and . @ : / - _ only')}
                />
              </Row>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Lock className="size-4" /> Access
              </CardTitle>
              <CardDescription>Admin groups come from the Helm value <code className="font-mono">adminGroups</code> and are enforced at the gateway and the API. Read-only here.</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-wrap gap-1.5">
              {form.adminGroups.map((g) => (
                <Badge key={g} variant="outline" className="font-mono">
                  {g}
                </Badge>
              ))}
            </CardContent>
            <CardFooter className="justify-end gap-2 border-border border-t">
              <Button type="button" variant="ghost" disabled={!dirty || save.isPending} onClick={() => data && setForm(normalise(data))}>
                <Undo2 />
                Reset
              </Button>
              <Button type="submit" disabled={!dirty || !valid} loading={save.isPending} loadingText="Saving…">
                <Save />
                Save settings
              </Button>
            </CardFooter>
          </Card>
        </form>
      ) : null}
    </>
  );
}

/** Content fetched from a source: the `scap` scanner's content entries whose `sourceName` (or file) matches. */
function sourceContent(src: ScapSettings['sources'][number], versions: ScapContentVersion[]): ScapContentVersion[] {
  const file = src.url.split('/').pop() ?? '';
  return versions.filter(
    (v) => (src.name && v.sourceName === src.name) || (src.name && v.name === src.name) || v.name === file || (v.file && (v.file === file || src.url.includes(v.file))),
  );
}

function ScapCard({
  enabled,
  scap,
  contentVersions,
  onEnabled,
  onChange,
}: {
  enabled: boolean;
  scap: ScapSettings;
  contentVersions: ScapContentVersion[];
  onEnabled: (v: boolean) => void;
  onChange: (patch: Partial<ScapSettings>) => void;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>SCAP (product and OS STIGs)</CardTitle>
        <CardDescription>
          OpenSCAP evaluates the applicable DISA / ComplianceAsCode benchmark inside each cached image (DESIGN §14). The scap-worker itself is deployed by the Helm
          value <code className="font-mono">scanner.scap.enabled</code>.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-5">
        <Row label="Stage">
          <Toggle label="Run SCAP evaluation during scans" checked={enabled} onChange={onEnabled} />
        </Row>
        <Row label="Content preference" hint="When both a DISA SCAP benchmark and SSG content match an image, use DISA.">
          <Toggle label="Prefer DISA benchmarks" checked={scap.preferDisa} disabled={!enabled} onChange={(v) => onChange({ preferDisa: v })} />
        </Row>
        <Row id="scap-timeout" label="Timeout per image" hint="oscap-chroot is stopped after this; the image is then reported with an error.">
          <NumberInput id="scap-timeout" value={scap.timeoutSeconds} min={SCAP_TIMEOUT.min} max={SCAP_TIMEOUT.max} suffix="seconds" onChange={(n) => onChange({ timeoutSeconds: n })} />
        </Row>
        <Row label="Content sources" hint="From the Helm value scap.content.sources[] (or a mounted PVC on air-gapped installs). Read-only here.">
          {scap.sources.length ? (
            <Table aria-label="SCAP content sources">
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="px-2">Source</TableHead>
                  <TableHead className="px-2">Content</TableHead>
                  <TableHead className="px-2">Version</TableHead>
                  <TableHead className="px-2">Fetched</TableHead>
                  <TableHead className="px-2">sha256</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scap.sources.map((src) => {
                  const content = sourceContent(src, contentVersions);
                  const versions = [...new Set([src.version, ...content.map((c) => c.version)].filter(Boolean))];
                  const fetchedAt = src.fetchedAt ?? content.map((c) => c.fetchedAt).filter(Boolean).sort().at(-1);
                  const kind = src.kind ?? src.source ?? content[0]?.source;
                  return (
                    <TableRow key={src.url}>
                      <TableCell className="px-2 py-1.5">
                        <SourceBadge source={kind ?? (/cyber\.mil/.test(src.url) ? 'disa' : /ComplianceAsCode|scap-security-guide/i.test(src.url) ? 'ssg' : null)} />
                      </TableCell>
                      <TableCell className="max-w-[360px] px-2 py-1.5">
                        <span className="block truncate text-sm" title={src.url}>{src.name ?? src.url.split('/').pop()}</span>
                        <a href={src.url} target="_blank" rel="noreferrer" className="block truncate text-[11px] text-muted-foreground underline-offset-4 hover:underline" title={src.url}>
                          {src.url}
                        </a>
                      </TableCell>
                      <TableCell className="px-2 py-1.5 font-mono text-xs">
                        {versions.length ? versions.join(', ') : '—'}
                        {content.length > 1 ? <span className="block font-sans text-[11px] text-muted-foreground">{content.length} datastreams</span> : null}
                      </TableCell>
                      <TableCell className="px-2 py-1.5 text-muted-foreground text-xs">{fetchedAt ? formatAge(fetchedAt) : '—'}</TableCell>
                      <TableCell className="px-2 py-1.5 font-mono text-[11px] text-muted-foreground" title={src.sha256 ?? undefined}>
                        {src.sha256 ? `${src.sha256.slice(0, 12)}…` : '—'}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          ) : (
            <p className="text-muted-foreground text-sm">No content sources configured; the bundled ComplianceAsCode content is used.</p>
          )}
        </Row>
      </CardContent>
    </Card>
  );
}
