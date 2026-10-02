import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Lock, Save, Undo2 } from 'lucide-react';
import { type ReactNode, useState } from 'react';
import { api } from '@/api/client';
import { qk, useReportTypes, useSettings } from '@/api/queries';
import type { ScannerName, Settings } from '@/api/types';
import { SCANNERS } from '@/api/types';
import { CardsSkeleton, ErrorAlert, PageHeader, errorMessage } from '@/components/page';
import { SCANNER_LABEL } from '@/components/posture';
import { TagInput } from '@/components/tag-input';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
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

function normalise(s: Settings): Required<Settings> {
  return {
    ...s,
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
  const [form, setForm] = useState<Required<Settings> | null>(() => (data ? normalise(data) : null));
  const [source, setSource] = useState(data);
  // re-seed the form whenever fresh server data arrives (load or after save)
  if (data !== source) {
    setSource(data);
    setForm(data ? normalise(data) : null);
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
    SCANNERS.some((s) => form.scanners[s]);

  return (
    <>
      <PageHeader title="Settings" description="Scan schedule, scanners and compliance reporting. Stored in the database; Helm values provide defaults." />
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
