import { CheckIcon, CopyIcon, LogIn, RefreshCw, ShieldAlert, TriangleAlert } from 'lucide-react';
import { type ReactNode, useState } from 'react';
import { Link } from 'react-router';
import { ApiError } from '@/api/client';
import { Alert, AlertAction, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from '@/components/ui/breadcrumb';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';

export function PageHeader({
  title,
  description,
  actions,
  crumbs,
  children,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  crumbs?: Array<{ label: string; to?: string }>;
  children?: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-2">
      {crumbs?.length ? (
        <Breadcrumb>
          <BreadcrumbList>
            {crumbs.map((c, i) => (
              <span key={`${c.label}-${i}`} className="contents">
                {i > 0 ? <BreadcrumbSeparator /> : null}
                <BreadcrumbItem>
                  {c.to ? <BreadcrumbLink render={<Link to={c.to} />}>{c.label}</BreadcrumbLink> : <BreadcrumbPage>{c.label}</BreadcrumbPage>}
                </BreadcrumbItem>
              </span>
            ))}
          </BreadcrumbList>
        </Breadcrumb>
      ) : null}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="truncate font-semibold text-2xl tracking-tight">{title}</h1>
          {description ? <p className="mt-1 text-muted-foreground text-sm">{description}</p> : null}
        </div>
        {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
      </div>
      {children}
    </div>
  );
}

export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return `${error.status}: ${error.detail}`;
  if (error instanceof Error) return error.message;
  return 'Unexpected error';
}

export function ErrorAlert({ error, onRetry, title = 'Couldn’t load data' }: { error: unknown; onRetry?: () => void; title?: string }) {
  return (
    <Alert variant="destructive">
      <TriangleAlert />
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription>{errorMessage(error)}</AlertDescription>
      {onRetry ? (
        <AlertAction>
          <Button size="sm" variant="outline" onClick={onRetry}>
            <RefreshCw />
            Retry
          </Button>
        </AlertAction>
      ) : null}
    </Alert>
  );
}

export function CardsSkeleton({ count = 3, className }: { count?: number; className?: string }) {
  return (
    <div className={cn('grid gap-4 sm:grid-cols-2 xl:grid-cols-3', className)} aria-busy="true" aria-label="Loading">
      {Array.from({ length: count }, (_, i) => (
        <Card key={i}>
          <CardContent className="flex flex-col gap-3">
            <Skeleton className="w-1/3" />
            <Skeleton shape="block" className="h-20" />
            <Skeleton className="w-2/3" />
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

export function CopyButton({ value, label = 'Copy' }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      size="icon-xs"
      variant="ghost"
      aria-label={copied ? 'Copied' : label}
      title={copied ? 'Copied' : label}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1500);
        } catch {
          setCopied(false);
        }
      }}
    >
      {copied ? <CheckIcon className="text-success-foreground" /> : <CopyIcon />}
    </Button>
  );
}

function FullPageNotice({ icon, title, children, action }: { icon: ReactNode; title: string; children: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex min-h-full items-center justify-center bg-canvas p-6">
      <Card className="w-full max-w-md">
        <CardContent className="flex flex-col items-center gap-3 py-6 text-center">
          <span className="inline-flex size-12 items-center justify-center rounded-full bg-muted text-muted-foreground-strong">{icon}</span>
          <h1 className="font-semibold text-xl">{title}</h1>
          <div className="text-muted-foreground text-sm">{children}</div>
          {action}
        </CardContent>
      </Card>
    </div>
  );
}

export function SessionExpired() {
  return (
    <FullPageNotice
      icon={<LogIn className="size-6" />}
      title="Session expired"
      action={
        <Button onClick={() => window.location.reload()}>
          <LogIn />
          Sign in
        </Button>
      }
    >
      Your Nebari session is no longer valid. Sign in again to continue.
    </FullPageNotice>
  );
}

export function AdminsOnly() {
  return (
    <FullPageNotice
      icon={<ShieldAlert className="size-6" />}
      title="Admins only"
      action={
        <div className="flex gap-2">
          <Button variant="outline" render={<a href="/" />}>
            Back to Nebari
          </Button>
          <Button variant="ghost" render={<a href="/logout" />}>
            Sign out
          </Button>
        </div>
      }
    >
      Security Posture is restricted to members of an admin group. Ask a Nebari administrator for access if you need it.
    </FullPageNotice>
  );
}

/** Small key/value item used in detail headers. */
export function Meta({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-0.5">
      <span className="text-[11px] text-muted-foreground uppercase tracking-wide">{label}</span>
      <span className="min-w-0 text-sm">{children}</span>
    </div>
  );
}

export function EmptyState({ icon, title, children }: { icon?: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-10 text-center" role="status">
      {icon ? <span className="text-muted-foreground">{icon}</span> : null}
      <p className="font-medium text-sm">{title}</p>
      {children ? <div className="max-w-sm text-muted-foreground text-sm">{children}</div> : null}
    </div>
  );
}
