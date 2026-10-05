import { QueryClientProvider, type QueryClient } from '@tanstack/react-query';
import { type ReactNode, useState } from 'react';
import { createBrowserRouter, createMemoryRouter, RouterProvider, type RouteObject } from 'react-router';
import { AppLayout } from '@/components/app-layout';
import { ByMode, Gate } from '@/components/mode-gate';
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
import { ProvenanceOverviewPage } from '@/pages/provenance/overview';
import { ProvenanceReportsPage } from '@/pages/provenance/reports';
import { ProvenanceScansPage } from '@/pages/provenance/scans';
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
          { index: true, element: <ByMode posture={<OverviewPage />} provenance={<ProvenanceOverviewPage />} /> },
          { path: 'images', element: <ImagesPage /> },
          { path: 'images/:id', element: <ImageDetailPage /> },
          { path: 'vulnerabilities', element: <Gate feature="vulnerabilities"><VulnerabilitiesPage /></Gate> },
          { path: 'vulnerabilities/:vulnId', element: <Gate feature="vulnerabilities"><VulnerabilityDetailPage /></Gate> },
          { path: 'workloads', element: <Gate feature="workloads"><WorkloadsPage /></Gate> },
          { path: 'namespaces', element: <Gate feature="namespaces"><NamespacesPage /></Gate> },
          { path: 'checks', element: <Gate feature="checks"><ChecksPage /></Gate> },
          { path: 'supply-chain', element: <SupplyChainPage /> },
          { path: 'checks/:id', element: <Gate feature="checks"><CheckDetailPage /></Gate> },
          { path: 'scans', element: <ByMode posture={<ScansPage />} provenance={<ProvenanceScansPage />} /> },
          { path: 'scans/:id', element: <Gate feature="scanDetail"><ScanDetailPage /></Gate> },
          { path: 'reports', element: <ByMode posture={<ReportsPage />} provenance={<ProvenanceReportsPage />} /> },
          { path: 'compliance', element: <Gate feature="compliance"><CompliancePage /></Gate> },
          { path: 'settings', element: <Gate feature="settings"><SettingsPage /></Gate> },
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
