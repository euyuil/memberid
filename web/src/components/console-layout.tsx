import { useState, type ReactNode } from "react"
import { Menu as AccountMenu } from "@base-ui/react/menu"
import {
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Fingerprint,
  LogOut,
  Menu,
  UserRound,
  type LucideIcon,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Link, type NavigationState } from "@/navigation"
import { routeURL } from "@/routes"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"

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

function Navigation({
  items,
  onNavigate,
}: {
  items: NavigationItem[]
  onNavigate?: () => void
}) {
  return (
    <nav aria-label="主导航" className="console-navigation">
      {[...new Set(items.map((item) => item.group))].map((group) => (
        <div className="nav-group" key={group} role="group" aria-label={group}>
          <span className="nav-group-label">{group}</span>
          {items
            .filter((item) => item.group === group)
            .map(({ label, href, icon: Icon, active }) => (
              <Link
                className="nav-link"
                key={label}
                href={href}
                aria-current={active ? "page" : undefined}
                aria-label={label}
                title={label}
                onClick={onNavigate}
              >
                <Icon aria-hidden="true" />
                <span className="nav-label">{label}</span>
              </Link>
            ))}
        </div>
      ))}
    </nav>
  )
}

export function ConsoleLayout({
  navigation,
  breadcrumbs,
  actor,
  scope,
  children,
  onSignOut,
}: ConsoleLayoutProps) {
  const [collapsed, setCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)
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
  const brand = (
    <>
      <span className="brand-mark">
        <Fingerprint aria-hidden="true" />
      </span>
      <span className="brand-label">
        MemberID<small>管理控制台</small>
      </span>
    </>
  )
  const accountIdentity = (
    <>
      <span className="actor-avatar" aria-hidden="true">
        {Array.from(actor.displayName)[0] || "M"}
      </span>
      <span className="actor-info">
        <strong title={actor.displayName}>{actor.displayName}</strong>
        <span>{role}</span>
      </span>
    </>
  )
  const account = (onNavigate?: () => void) => (
    <AccountMenu.Root>
      <AccountMenu.Trigger
        className="actor-trigger"
        aria-label={`账户菜单 · ${actor.displayName}`}
        title={actor.displayName}
      >
        {accountIdentity}
      </AccountMenu.Trigger>
      <AccountMenu.Portal>
        <AccountMenu.Positioner
          side="top"
          align="start"
          sideOffset={8}
          className="account-menu-positioner"
        >
          <AccountMenu.Popup className="account-menu" aria-label="账户菜单">
            <div className="account-menu-identity">{accountIdentity}</div>
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
                  onClick={onNavigate}
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
  )
  return (
    <div className="console-shell" data-collapsed={collapsed}>
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
      <aside id="console-sidebar" className="sidebar" aria-label="管理导航">
        <Link className="brand" href="/" aria-label="MemberID 管理控制台">
          {brand}
        </Link>
        <Navigation items={navigation} />
        <div className="sidebar-footer">
          <Button
            variant="ghost"
            className="nav-link sidebar-toggle"
            aria-label={collapsed ? "展开侧栏" : "收起侧栏"}
            title={collapsed ? "展开侧栏" : "收起侧栏"}
            aria-expanded={!collapsed}
            aria-controls="console-sidebar"
            onClick={() => setCollapsed(!collapsed)}
          >
            {collapsed ? (
              <ChevronsRight aria-hidden="true" />
            ) : (
              <ChevronsLeft aria-hidden="true" />
            )}
            <span className="nav-label">收起侧栏</span>
          </Button>
          <div className="actor-panel">{account()}</div>
        </div>
      </aside>
      <div className="workspace">
        <header className="scope-bar">
          <Dialog open={mobileOpen} onOpenChange={setMobileOpen}>
            <DialogTrigger
              render={
                <Button
                  variant="ghost"
                  size="icon"
                  className="mobile-navigation-toggle"
                  aria-label="打开导航"
                />
              }
            >
              <Menu />
            </DialogTrigger>
            <DialogContent className="navigation-drawer translate-x-0 translate-y-0 data-open:zoom-in-100 data-closed:zoom-out-100">
              <DialogTitle className="brand">{brand}</DialogTitle>
              <DialogDescription className="sr-only">主导航</DialogDescription>
              <Navigation
                items={navigation}
                onNavigate={() => setMobileOpen(false)}
              />
              <div className="actor-panel">
                {account(() => setMobileOpen(false))}
              </div>
            </DialogContent>
          </Dialog>
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
          <div className="scope-control">{scope}</div>
        </header>
        <main id="console-content" className="page-content" tabIndex={-1}>
          {children}
        </main>
      </div>
    </div>
  )
}
