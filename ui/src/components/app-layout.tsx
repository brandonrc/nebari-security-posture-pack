import { useEffect, useState } from 'react';
import { Outlet } from 'react-router';
import { useAuthState } from '@/api/auth-state';
import { useMe } from '@/api/queries';
import { AppHeader } from '@/components/app-header';
import { AppSidebar } from '@/components/app-sidebar';
import { AdminsOnly, SessionExpired } from '@/components/page';
import { SidebarProvider } from '@/components/ui/sidebar';

const NARROW = '(max-width: 1100px)';

function useNarrow() {
  const [narrow, setNarrow] = useState(() => (typeof window !== 'undefined' && window.matchMedia ? window.matchMedia(NARROW).matches : false));
  useEffect(() => {
    if (!window.matchMedia) return;
    const mq = window.matchMedia(NARROW);
    const onChange = () => setNarrow(mq.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);
  return narrow;
}

export function AppLayout() {
  const auth = useAuthState();
  const me = useMe();
  const narrow = useNarrow();
  const [collapsed, setCollapsed] = useState<boolean | null>(null);

  if (auth === 'expired') return <SessionExpired />;
  if (auth === 'forbidden' || (me.data && me.data.isAdmin === false)) return <AdminsOnly />;

  return (
    <SidebarProvider collapsed={collapsed ?? narrow} onCollapsedChange={setCollapsed}>
      <div className="flex h-full flex-col bg-canvas text-canvas-foreground">
        <AppHeader />
        <div className="flex min-h-0 flex-1">
          <div className="hidden shrink-0 p-2 pr-0 sm:block">
            <AppSidebar />
          </div>
          <main className="min-w-0 flex-1 overflow-y-auto" id="main">
            <div className="mx-auto flex w-full max-w-[1600px] flex-col gap-5 p-4 md:p-6">
              <Outlet />
            </div>
          </main>
        </div>
      </div>
    </SidebarProvider>
  );
}
