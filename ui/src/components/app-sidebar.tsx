import {
  Boxes,
  ClipboardCheck,
  FileText,
  Folders,
  History,
  Landmark,
  LayoutDashboard,
  Layers,
  Settings,
  ShieldCheck,
  Bug,
  PackageCheck,
} from 'lucide-react';
import { NavLink as RouterNavLink, useLocation } from 'react-router';
import { type Feature, productTitle, useCapabilities } from '@/capabilities';
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuDescription,
  SidebarMenuItem,
  SidebarMenuLabel,
  SidebarTrigger,
} from '@/components/ui/sidebar';

const GROUPS: Array<{ label: string; provenanceLabel: string; items: Array<{ to: string; label: string; icon: typeof Boxes; feature: Feature; end?: boolean }> }> = [
  {
    label: 'Posture',
    provenanceLabel: 'Supply chain',
    items: [
      { to: '/', label: 'Overview', icon: LayoutDashboard, feature: 'overview', end: true },
      { to: '/images', label: 'Images', icon: Boxes, feature: 'images' },
      { to: '/vulnerabilities', label: 'Vulnerabilities', icon: Bug, feature: 'vulnerabilities' },
      { to: '/workloads', label: 'Workloads', icon: Layers, feature: 'workloads' },
      { to: '/namespaces', label: 'Namespaces', icon: Folders, feature: 'namespaces' },
      { to: '/checks', label: 'Posture checks', icon: ClipboardCheck, feature: 'checks' },
      { to: '/supply-chain', label: 'Supply chain', icon: PackageCheck, feature: 'supplyChain' },
    ],
  },
  {
    label: 'Compliance',
    provenanceLabel: 'History',
    items: [
      { to: '/compliance', label: 'Compliance', icon: Landmark, feature: 'compliance' },
      { to: '/reports', label: 'Reports', icon: FileText, feature: 'reports' },
    ],
  },
  {
    label: 'Operations',
    provenanceLabel: 'Operations',
    items: [
      { to: '/scans', label: 'Scans', icon: History, feature: 'scans' },
      { to: '/settings', label: 'Settings', icon: Settings, feature: 'settings' },
    ],
  },
];

export function AppSidebar() {
  const { pathname } = useLocation();
  const caps = useCapabilities();
  const provenance = caps.mode === 'provenance';
  const groups = GROUPS.map((g) => ({ label: provenance ? g.provenanceLabel : g.label, items: g.items.filter((i) => caps.features[i.feature]) })).filter((g) => g.items.length);
  const isActive = (to: string, end?: boolean) => (end ? pathname === to : pathname === to || pathname.startsWith(`${to}/`));

  return (
    <Sidebar aria-label="Security Posture sections" variant="inset" className="h-full border border-border">
      <SidebarHeader>
        <div className="flex h-12 w-full items-center gap-2 px-2 py-2">
          <span className="inline-flex size-8 min-w-8 items-center justify-center rounded-lg bg-sidebar-primary text-sidebar-primary-foreground">
            <ShieldCheck className="size-4" />
          </span>
          <span className="min-w-0 flex-1">
            <SidebarMenuLabel className="block font-medium text-sm leading-5">{productTitle(caps)}</SidebarMenuLabel>
            <SidebarMenuDescription>{provenance ? 'cosign · SBOM · SLSA' : 'Trivy · Grype · Clair'}</SidebarMenuDescription>
          </span>
        </div>
      </SidebarHeader>
      <SidebarContent className="gap-3">
        {groups.map((group) => (
          <SidebarGroup key={group.label}>
            <SidebarGroupLabel>{group.label}</SidebarGroupLabel>
            <SidebarMenu>
              {group.items.map((item) => (
                <SidebarMenuItem key={item.to}>
                  <SidebarMenuButton
                    active={isActive(item.to, item.end)}
                    tooltip={item.label}
                    render={<RouterNavLink to={item.to} end={item.end} />}
                  >
                    <item.icon className="size-4 shrink-0" />
                    <SidebarMenuLabel>{item.label}</SidebarMenuLabel>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroup>
        ))}
      </SidebarContent>
      <SidebarFooter className="flex items-center bg-transparent px-3 group-data-[state=collapsed]/sidebar:justify-center">
        <SidebarTrigger />
      </SidebarFooter>
    </Sidebar>
  );
}
