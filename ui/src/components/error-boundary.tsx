import { useQueryClient } from '@tanstack/react-query';
import { House, RefreshCw, TriangleAlert } from 'lucide-react';
import { isRouteErrorResponse, Link, useLocation, useNavigate, useRouteError } from 'react-router';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';

/** Text for any thrown value (Error, Response, string, object). */
export function describeError(error: unknown): string {
  if (isRouteErrorResponse(error)) return `${error.status} ${error.statusText}`.trim();
  if (error instanceof Error) return error.message || error.name;
  if (typeof error === 'string') return error;
  try {
    return JSON.stringify(error) ?? 'Unknown error';
  } catch {
    return 'Unknown error';
  }
}

/** Compact error card: what failed, the error text, and how to recover. */
export function ErrorCard({ title, error, onRetry, home = true }: { title: string; error: unknown; onRetry?: () => void; home?: boolean }) {
  return (
    <Card role="alert" aria-labelledby="route-error-title" className="mx-auto w-full max-w-xl">
      <CardContent className="flex flex-col gap-3 py-5">
        <div className="flex items-center gap-2">
          <TriangleAlert className="size-5 shrink-0 text-destructive" aria-hidden />
          <h2 id="route-error-title" className="font-semibold text-base">
            {title}
          </h2>
        </div>
        <p className="text-muted-foreground text-sm">
          The API returned data this page could not display. This can happen while the API and UI are being upgraded.
        </p>
        <pre className="max-h-32 overflow-auto whitespace-pre-wrap break-words rounded-md bg-muted px-3 py-2 font-mono text-xs">{describeError(error)}</pre>
        <div className="flex flex-wrap gap-2">
          {onRetry ? (
            <Button size="sm" onClick={onRetry}>
              <RefreshCw />
              Retry
            </Button>
          ) : null}
          {home ? (
            <Button size="sm" variant="outline" render={<Link to="/" />}>
              <House />
              Overview
            </Button>
          ) : null}
        </div>
      </CardContent>
    </Card>
  );
}

/**
 * Route-level `errorElement` (quality review M5). A render error in one page stays inside the
 * app shell instead of replacing the whole app with React Router's "Unexpected Application Error".
 * Retry drops the cached API responses and re-navigates to the same URL, which clears the
 * router's error state and refetches.
 */
export function RouteErrorBoundary() {
  const error = useRouteError();
  const navigate = useNavigate();
  const location = useLocation();
  const client = useQueryClient();
  const retry = () => {
    void client.resetQueries();
    void navigate(`${location.pathname}${location.search}${location.hash}`, { replace: true });
  };
  return <ErrorCard title="This page failed to load" error={error} onRetry={retry} />;
}

/** Top-level fallback, outside the app shell (the layout itself failed). */
export function RootErrorBoundary() {
  const error = useRouteError();
  return (
    <div className="flex min-h-full items-center justify-center p-6">
      <ErrorCard title="Security Posture failed to load" error={error} onRetry={() => window.location.reload()} home={false} />
    </div>
  );
}
