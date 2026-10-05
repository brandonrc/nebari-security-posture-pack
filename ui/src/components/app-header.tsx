import { Menu as MenuPrimitive } from '@base-ui/react/menu';
import { ChevronDown, LogOut, Monitor, Moon, Sun } from 'lucide-react';
import { useNavigate } from 'react-router';
import { useMe } from '@/api/queries';
import { getAuthStrategy } from '@/auth/strategy';
import { brandLogo } from '@/branding';
import { productTitle, useCapabilities } from '@/capabilities';
import { getConfig } from '@/config';
import { Avatar, AvatarFallback } from '@/components/avatar';
import { Badge } from '@/components/ui/badge';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuPortal,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { MenuBarActions, MenuBarBrand, MenuBarNav, NavigationMenu } from '@/components/ui/navigation-menu';
import { Skeleton } from '@/components/ui/skeleton';
import { useTheme } from '@/hooks/theme-provider';
import { isThemeMode } from '@/hooks/use-theme-preference';
import { cn } from '@/lib/utils';

const THEME_OPTIONS = [
  { value: 'light', label: 'Light', icon: Sun },
  { value: 'dark', label: 'Dark', icon: Moon },
  { value: 'system', label: 'System', icon: Monitor },
] as const;

function initialsOf(name: string): string {
  const parts = name.split(/[\s._-]+/).filter(Boolean);
  return ((parts[0]?.[0] ?? '?') + (parts[1]?.[0] ?? '')).toUpperCase();
}

/** Gateway `/logout` in posture mode; keycloak-js logout in provenance mode (auth strategy). */
export function signOut() {
  getAuthStrategy().signOut();
}

function ProfileMenu() {
  const { data: me, isLoading } = useMe();
  const { themeMode, setThemeMode } = useTheme();

  if (isLoading) return <Skeleton className="h-8 w-32" />;
  const name = me?.username ?? 'Account';

  return (
    <DropdownMenu modal={false}>
      <DropdownMenuTrigger
        variant="ghost"
        aria-label="Account menu"
        className="h-auto px-2.5 py-1 hover:bg-header-action-hover hover:no-underline focus-visible:ring-offset-0 active:bg-header-action-hover data-[popup-open]:bg-header-action-hover data-[popup-open]:no-underline"
      >
        <Avatar>
          <AvatarFallback className="bg-primary font-semibold text-primary-foreground">{initialsOf(name)}</AvatarFallback>
        </Avatar>
        <span className="hidden sm:inline">{name}</span>
        <ChevronDown />
      </DropdownMenuTrigger>
      <DropdownMenuPortal>
        <DropdownMenuContent align="end" className="w-[248px] p-2">
          <div className="border-b px-1.5 pb-2">
            <p className="font-medium text-foreground text-sm">{name}</p>
            {me?.email ? <p className="text-muted-foreground text-xs">{me.email}</p> : null}
            {me?.groups?.length ? (
              <div className="mt-2 flex flex-wrap gap-1" aria-label="Groups">
                {me.groups.map((g) => (
                  <Badge key={g} variant={me.isAdmin && g === 'admin' ? 'default' : 'outline'} className="text-[10px]">
                    {g}
                  </Badge>
                ))}
              </div>
            ) : null}
          </div>

          <div className="py-2">
            <MenuPrimitive.RadioGroup
              aria-label="Theme"
              value={themeMode}
              onValueChange={(value) => {
                if (isThemeMode(value)) setThemeMode(value);
              }}
              className="flex h-[34px] items-center gap-1 rounded-md bg-muted p-1"
            >
              {THEME_OPTIONS.map(({ value, label, icon: Icon }) => (
                <MenuPrimitive.RadioItem
                  key={value}
                  value={value}
                  aria-label={`${label} mode`}
                  title={`${label} mode`}
                  closeOnClick={false}
                  className={cn(
                    'flex h-auto flex-1 cursor-pointer items-center justify-center gap-1 rounded-sm border border-transparent px-1.5 py-0.5 font-medium text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring',
                    'text-muted-foreground-strong hover:text-foreground',
                    'data-checked:border-border-strong data-checked:bg-card data-checked:text-foreground data-checked:shadow-[0_1px_3px_0_rgba(0,0,0,0.10)]',
                  )}
                >
                  <Icon className="h-4 w-4" />
                  <span>{label}</span>
                </MenuPrimitive.RadioItem>
              ))}
            </MenuPrimitive.RadioGroup>
          </div>

          <DropdownMenuSeparator />

          <DropdownMenuItem className="leading-5 text-sign-out-foreground data-[highlighted]:text-sign-out-foreground" onClick={signOut}>
            <LogOut className="size-4 shrink-0" aria-hidden="true" />
            Sign out
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenuPortal>
    </DropdownMenu>
  );
}

export function AppHeader() {
  const { isDarkMode } = useTheme();
  const navigate = useNavigate();
  const caps = useCapabilities();
  return (
    <NavigationMenu className="h-14 shrink-0 justify-between border-border bg-header pl-4 text-header-foreground">
      <MenuBarBrand
        href="/"
        aria-label="Go to homepage"
        onClick={(event) => {
          event.preventDefault();
          navigate('/');
        }}
      >
        <img
          src={
            brandLogo(getConfig().branding, isDarkMode) ??
            (isDarkMode ? '/Nebari-Logo-Horizontal-Lockup-White-text.png' : '/Nebari-Logo-Horizontal-Lockup.png')
          }
          alt={getConfig().title || 'Nebari'}
          className="h-8 w-auto"
        />
      </MenuBarBrand>
      <MenuBarNav aria-label="Application" className="hidden md:flex">
        <span className="ml-2 border-border border-l pl-4 font-medium text-muted-foreground-strong text-sm">{productTitle(caps)}</span>
      </MenuBarNav>
      <MenuBarActions className="gap-2">
        <ProfileMenu />
      </MenuBarActions>
    </NavigationMenu>
  );
}
