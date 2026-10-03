import { QueryClientProvider, type QueryClient } from '@tanstack/react-query';
import { type ReactNode, useState } from 'react';
import { createBrowserRouter, createMemoryRouter, RouterProvider, type RouteObject } from 'react-router';
import { AppLayout } from '@/components/app-layout';
import { RootErrorBoundary, RouteErrorBoundary } from '@/components/error-boundary';
import { Toaster } from '@/components/ui/toast';
import { ThemeProvider } from '@/hooks/theme-provider';
import { CheckDetailPage } from '@/pages/check-detail';
import { ChecksPage } from '@/pages/checks';
import { CompliancePage } from '@/pages/compliance';
import { ImageDetailPage } from '@/pages/image-detail';
import { ImagesPage } from '@/pages/images';
import { NamespacesPage } from '@/pages/namespaces';
import { NotFoundPage } from '@/pages/not-found';
import { OverviewPage } from '@/pages/overview';
import { ReportsPage } from '@/pages/reports';
import { ScanDetailPage } from '@/pages/scan-detail';
import { ScansPage } from '@/pages/scans';
import { SettingsPage } from '@/pages/settings';
import { SupplyChainPage } from '@/pages/supply-chain';
import { VulnerabilitiesPage } from '@/pages/vulnerabilities';
import { VulnerabilityDetailPage } from '@/pages/vulnerability-detail';
import { WorkloadsPage } from '@/pages/workloads';
import { TooltipProvider } from '@/components/ui/tooltip';

export const routes: RouteObject[] = [
  {
    path: '/',
    element: <AppLayout />,
    errorElement: <RootErrorBoundary />,
    children: [
      {
        // pathless layout route: a page error renders inside the app shell (sidebar stays usable)
        errorElement: <RouteErrorBoundary />,
        children: [
          { index: true, element: <OverviewPage /> },
          { path: 'images', element: <ImagesPage /> },
          { path: 'images/:id', element: <ImageDetailPage /> },
          { path: 'vulnerabilities', element: <VulnerabilitiesPage /> },
          { path: 'vulnerabilities/:vulnId', element: <VulnerabilityDetailPage /> },
          { path: 'workloads', element: <WorkloadsPage /> },
          { path: 'namespaces', element: <NamespacesPage /> },
          { path: 'checks', element: <ChecksPage /> },
          { path: 'supply-chain', element: <SupplyChainPage /> },
          { path: 'checks/:id', element: <CheckDetailPage /> },
          { path: 'scans', element: <ScansPage /> },
          { path: 'scans/:id', element: <ScanDetailPage /> },
          { path: 'reports', element: <ReportsPage /> },
          { path: 'compliance', element: <CompliancePage /> },
          { path: 'settings', element: <SettingsPage /> },
          { path: '*', element: <NotFoundPage /> },
        ],
      },
    ],
  },
];

export function Providers({ client, children }: { client: QueryClient; children: ReactNode }) {
  return (
    <ThemeProvider>
      <QueryClientProvider client={client}>
        <TooltipProvider>
          <Toaster>{children}</Toaster>
        </TooltipProvider>
      </QueryClientProvider>
    </ThemeProvider>
  );
}

export function App({ client, initialPath }: { client: QueryClient; initialPath?: string }) {
  const [router] = useState(() => (initialPath ? createMemoryRouter(routes, { initialEntries: [initialPath] }) : createBrowserRouter(routes)));
  return (
    <Providers client={client}>
      <RouterProvider router={router} />
    </Providers>
  );
}
