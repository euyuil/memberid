import { Fragment, useState, type ReactNode } from "react"
import {
  ChevronRight,
  ChevronsUpDown,
  LogOut,
  ArrowRightLeft,
  UserRound,
  type LucideIcon,
} from "lucide-react"
import { cn } from "cn"
import { Link, type NavigationState } from "@/navigation"
import { routeURL } from "@/routes"
import {
  Breadcrumb,
  BreadcrumbItem as BreadcrumbListItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Separator } from "@/components/ui/separator"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
  SidebarProvider,
  SidebarRail,
  SidebarTrigger,
  useSidebar,
} from "@/components/ui/sidebar"
import { TooltipProvider } from "@/components/ui/tooltip"

type NavigationItem = {
  label: string
  href: string
  active: boolean
}
type NavigationGroup = {
  label: string
  icon: LucideIcon
  items: NavigationItem[]
}
export type BreadcrumbItem = {
  label: string
  href?: string
  state?: NavigationState
}

type ConsoleLayoutProps = {
  breadcrumbs: BreadcrumbItem[]
  navigation: NavigationGroup[]
  actor: {
    displayName: string
    memberId: string
    organizationId: string
    platform: boolean
  }
  scope: ReactNode
  children: ReactNode
  onSignOut: () => Promise<void>
  onChooseIdentity: () => void
}

function Navigation({ groups }: { groups: NavigationGroup[] }) {
  const { setOpenMobile } = useSidebar()
  return (
    <nav aria-label="主导航">
      <SidebarGroup>
        <SidebarMenu>
          {groups.map(({ label, icon: Icon, items }) => (
            <Collapsible
              key={label}
              defaultOpen={items.some((item) => item.active)}
              className="group/collapsible"
              render={<SidebarMenuItem />}
            >
              <CollapsibleTrigger
                render={
                  <SidebarMenuButton
                    tooltip={label}
                    isActive={items.some((item) => item.active)}
                  />
                }
                aria-label={label}
              >
                <Icon aria-hidden="true" />
                <span>{label}</span>
                <ChevronRight
                  aria-hidden="true"
                  className="ml-auto transition-transform duration-200 group-data-open/collapsible:rotate-90"
                />
              </CollapsibleTrigger>
              <CollapsibleContent>
                <SidebarMenuSub>
                  {items.map(({ label, href, active }) => (
                    <SidebarMenuSubItem key={label}>
                      <SidebarMenuSubButton
                        render={<Link href={href} />}
                        isActive={active}
                        aria-current={active ? "page" : undefined}
                        onClick={() => setOpenMobile(false)}
                      >
                        <span>{label}</span>
                      </SidebarMenuSubButton>
                    </SidebarMenuSubItem>
                  ))}
                </SidebarMenuSub>
              </CollapsibleContent>
            </Collapsible>
          ))}
        </SidebarMenu>
      </SidebarGroup>
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
  onChooseIdentity,
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
      <Avatar aria-hidden="true">
        <AvatarFallback>
          {Array.from(actor.displayName)[0] || "M"}
        </AvatarFallback>
      </Avatar>
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
          <Navigation groups={navigation} />
        </SidebarContent>
        <SidebarFooter>
          <SidebarMenu>
            <SidebarMenuItem>
              <DropdownMenu>
                <DropdownMenuTrigger
                  render={<SidebarMenuButton size="lg" />}
                  aria-label={`账户菜单 · ${actor.displayName}`}
                  title={actor.displayName}
                >
                  {accountIdentity}
                  <ChevronsUpDown
                    aria-hidden="true"
                    className="ml-auto group-data-[collapsible=icon]:hidden"
                  />
                </DropdownMenuTrigger>
                <DropdownMenuContent
                  side={isMobile ? "bottom" : "right"}
                  align="end"
                  sideOffset={4}
                  className="max-w-[calc(100vw-1.5rem)] min-w-56"
                  aria-label="账户菜单"
                >
                  <DropdownMenuGroup>
                    <DropdownMenuLabel className="p-0">
                      <div className="flex items-center gap-2 px-1 py-1.5">
                        {accountIdentity}
                      </div>
                    </DropdownMenuLabel>
                  </DropdownMenuGroup>
                  <DropdownMenuSeparator />
                  <DropdownMenuGroup>
                    <DropdownMenuItem onClick={onChooseIdentity}>
                      <ArrowRightLeft aria-hidden="true" />
                      切换身份
                    </DropdownMenuItem>
                    <DropdownMenuItem
                      nativeButton={false}
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
                    </DropdownMenuItem>
                  </DropdownMenuGroup>
                  <DropdownMenuSeparator />
                  <DropdownMenuGroup>
                    <DropdownMenuItem
                      disabled={signingOut}
                      closeOnClick={false}
                      onClick={signOut}
                    >
                      <LogOut aria-hidden="true" />
                      {signingOut ? "正在退出…" : "退出后台"}
                    </DropdownMenuItem>
                  </DropdownMenuGroup>
                </DropdownMenuContent>
              </DropdownMenu>
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
          <Breadcrumb className="min-w-0 flex-1" aria-label="面包屑">
            <BreadcrumbList className="flex-nowrap">
              {breadcrumbs.map(({ label, href, state }, index) => (
                <Fragment key={index}>
                  {index > 0 && <BreadcrumbSeparator className="shrink-0" />}
                  <BreadcrumbListItem
                    className={cn(
                      "min-w-0 first:shrink-0",
                      index > 1 && "max-w-36 shrink-0"
                    )}
                  >
                    {href ? (
                      <BreadcrumbLink
                        render={<Link href={href} state={state} />}
                        className="truncate"
                        title={label}
                      >
                        {label}
                      </BreadcrumbLink>
                    ) : index === breadcrumbs.length - 1 ? (
                      <BreadcrumbPage className="truncate" title={label}>
                        {label}
                      </BreadcrumbPage>
                    ) : (
                      <span className="truncate" title={label}>
                        {label}
                      </span>
                    )}
                  </BreadcrumbListItem>
                </Fragment>
              ))}
            </BreadcrumbList>
          </Breadcrumb>
        </header>
        <div id="console-content" className="page-content w-full" tabIndex={-1}>
          {children}
        </div>
      </SidebarInset>
    </>
  )
}
