import { useState, type ReactNode } from "react"
import {
  Fingerprint,
  LogOut,
  Menu,
  PanelLeftClose,
  PanelLeftOpen,
  type LucideIcon,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Link } from "@/navigation"
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
type ConsoleLayoutProps = {
  navigation: NavigationItem[]
  actor: { displayName: string; memberId: string; platform: boolean }
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
  const account = (
    <div className="actor-panel">
      <span className="actor-avatar" aria-hidden="true">
        {Array.from(actor.displayName)[0] || "M"}
      </span>
      <div className="actor-info">
        <strong title={actor.displayName}>{actor.displayName}</strong>
        <span>{role}</span>
      </div>
      <Button
        variant="ghost"
        size="icon"
        aria-label="退出后台"
        title={`退出后台 · ${actor.displayName}（${role}）`}
        disabled={signingOut}
        onClick={signOut}
      >
        <LogOut aria-hidden="true" />
      </Button>
    </div>
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
      <aside className="sidebar" aria-label="管理导航">
        <Link className="brand" href="/" aria-label="MemberID 管理控制台">
          {brand}
        </Link>
        <Navigation items={navigation} />
        {account}
      </aside>
      <div className="workspace">
        <header className="scope-bar">
          <Button
            variant="ghost"
            size="icon"
            className="desktop-navigation-toggle"
            aria-label={collapsed ? "展开侧栏" : "收起侧栏"}
            title={collapsed ? "展开侧栏" : "收起侧栏"}
            aria-expanded={!collapsed}
            onClick={() => setCollapsed(!collapsed)}
          >
            {collapsed ? <PanelLeftOpen /> : <PanelLeftClose />}
          </Button>
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
              <DialogDescription className="sr-only">
                选择管理页面，当前管理范围保持不变。
              </DialogDescription>
              <Navigation
                items={navigation}
                onNavigate={() => setMobileOpen(false)}
              />
              {account}
            </DialogContent>
          </Dialog>
          {scope}
        </header>
        <main id="console-content" className="page-content" tabIndex={-1}>
          {children}
        </main>
      </div>
    </div>
  )
}
