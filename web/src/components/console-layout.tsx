import { useState, type ReactNode } from "react"
import { Menu as AccountMenu } from "@base-ui/react/menu"
import {
  ChevronRight,
  ChevronsUpDown,
  LogOut,
  UserRound,
  type LucideIcon,
} from "lucide-react"
import { Link, type NavigationState } from "@/navigation"
import { routeURL } from "@/routes"
import { Separator } from "@/components/ui/separator"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarRail,
  SidebarTrigger,
  useSidebar,
} from "@/components/ui/sidebar"
import { TooltipProvider } from "@/components/ui/tooltip"

type NavigationItem = {
  label: string
  href: string
  icon: LucideIcon
  active: boolean
  group: string
}
export type BreadcrumbItem = {
  label: string
  href?: string
  state?: NavigationState
}

type ConsoleLayoutProps = {
  breadcrumbs: BreadcrumbItem[]
  navigation: NavigationItem[]
  actor: {
    displayName: string
    memberId: string
    organizationId: string
    platform: boolean
  }
  scope: ReactNode
  children: ReactNode
  onSignOut: () => Promise<void>
}

function Navigation({ items }: { items: NavigationItem[] }) {
  const { setOpenMobile } = useSidebar()
  return (
    <nav aria-label="主导航">
      {[...new Set(items.map((item) => item.group))].map((group) => (
        <SidebarGroup key={group} role="group" aria-label={group}>
          <SidebarGroupLabel>{group}</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {items
                .filter((item) => item.group === group)
                .map(({ label, href, icon: Icon, active }) => (
                  <SidebarMenuItem key={label}>
                    <SidebarMenuButton
                      render={<Link href={href} />}
                      isActive={active}
                      aria-current={active ? "page" : undefined}
                      aria-label={label}
                      tooltip={label}
                      onClick={() => setOpenMobile(false)}
                    >
                      <Icon aria-hidden="true" />
                      <span>{label}</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      ))}
    </nav>
  )
}

export function ConsoleLayout(props: ConsoleLayoutProps) {
  return (
    <TooltipProvider>
      <SidebarProvider className="console-shell">
        <ConsoleContents {...props} />
      </SidebarProvider>
    </TooltipProvider>
  )
}

function ConsoleContents({
  navigation,
  breadcrumbs,
  actor,
  scope,
  children,
  onSignOut,
}: ConsoleLayoutProps) {
  const { isMobile, setOpenMobile } = useSidebar()
  const [signingOut, setSigningOut] = useState(false)
  const role = actor.platform ? "平台管理员" : "组织管理员"
  const signOut = async () => {
    if (signingOut) return
    setSigningOut(true)
    try {
      await onSignOut()
    } finally {
      setSigningOut(false)
    }
  }
  const accountIdentity = (
    <>
      <span
        className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-muted text-sm font-medium"
        aria-hidden="true"
      >
        {Array.from(actor.displayName)[0] || "M"}
      </span>
      <div className="grid min-w-0 flex-1 text-left text-sm leading-tight group-data-[collapsible=icon]:hidden">
        <span className="truncate font-medium" title={actor.displayName}>
          {actor.displayName}
        </span>
        <span className="truncate text-xs text-muted-foreground">{role}</span>
      </div>
    </>
  )
  return (
    <>
      <a
        className="skip-link"
        href="#console-content"
        onClick={(event) => {
          event.preventDefault()
          document.getElementById("console-content")?.focus()
        }}
      >
        跳到主要内容
      </a>
      <Sidebar id="console-sidebar" collapsible="icon" aria-label="管理导航">
        <SidebarHeader>{scope}</SidebarHeader>
        <SidebarContent>
          <Navigation items={navigation} />
        </SidebarContent>
        <SidebarFooter>
          <SidebarMenu>
            <SidebarMenuItem>
              <AccountMenu.Root>
                <AccountMenu.Trigger
                  render={<SidebarMenuButton size="lg" />}
                  aria-label={`账户菜单 · ${actor.displayName}`}
                  title={actor.displayName}
                >
                  {accountIdentity}
                  <ChevronsUpDown
                    aria-hidden="true"
                    className="ml-auto group-data-[collapsible=icon]:hidden"
                  />
                </AccountMenu.Trigger>
                <AccountMenu.Portal>
                  <AccountMenu.Positioner
                    side={isMobile ? "bottom" : "right"}
                    align="end"
                    sideOffset={4}
                    className="account-menu-positioner"
                  >
                    <AccountMenu.Popup
                      className="account-menu"
                      aria-label="账户菜单"
                    >
                      <div className="account-menu-identity">
                        {accountIdentity}
                      </div>
                      <AccountMenu.Separator className="account-menu-separator" />
                      <AccountMenu.LinkItem
                        className="account-menu-item"
                        closeOnClick
                        render={
                          <Link
                            href={routeURL({
                              view: "members",
                              org: actor.organizationId,
                              member: actor.memberId,
                            })}
                            onClick={() => setOpenMobile(false)}
                          />
                        }
                      >
                        <UserRound aria-hidden="true" />
                        我的成员资料
                      </AccountMenu.LinkItem>
                      <AccountMenu.Separator className="account-menu-separator" />
                      <AccountMenu.Item
                        className="account-menu-item"
                        disabled={signingOut}
                        closeOnClick={false}
                        onClick={signOut}
                      >
                        <LogOut aria-hidden="true" />
                        {signingOut ? "正在退出…" : "退出后台"}
                      </AccountMenu.Item>
                    </AccountMenu.Popup>
                  </AccountMenu.Positioner>
                </AccountMenu.Portal>
              </AccountMenu.Root>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarFooter>
        <SidebarRail aria-controls="console-sidebar" />
      </Sidebar>
      <SidebarInset className="min-w-0">
        <header className="scope-bar">
          <SidebarTrigger aria-controls="console-sidebar" />
          <Separator
            orientation="vertical"
            className="scope-divider h-4! data-vertical:self-center"
          />
          <nav className="console-breadcrumbs" aria-label="面包屑">
            <ol>
              {breadcrumbs.map(({ label, href, state }, index) => (
                <li key={index}>
                  {index > 0 && <ChevronRight aria-hidden="true" />}
                  {href ? (
                    <Link href={href} state={state} title={label}>
                      {label}
                    </Link>
                  ) : (
                    <span
                      title={label}
                      aria-current={
                        index === breadcrumbs.length - 1 ? "page" : undefined
                      }
                    >
                      {label}
                    </span>
                  )}
                </li>
              ))}
            </ol>
          </nav>
        </header>
        <div id="console-content" className="page-content w-full" tabIndex={-1}>
          {children}
        </div>
      </SidebarInset>
    </>
  )
}
