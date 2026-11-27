import { MemberGrants } from "@/MemberGrants"
import {
  MemberBindings,
  SelfAccountLink,
  type MemberBinding,
} from "@/MemberBindings"
import { useEffect, useRef, useState, type FormEvent } from "react"
import {
  Building2,
  AppWindow,
  ChevronsUpDown,
  ChevronRight,
  Fingerprint,
  History,
  Plus,
  RefreshCw,
  X,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import {
  Card,
  CardAction,
  CardContent,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Skeleton } from "@/components/ui/skeleton"
import { ConsoleLayout, type BreadcrumbItem } from "@/components/console-layout"
import {
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  DirectoryResults,
  DirectoryState,
  RecordIdentifier,
  RecordTime,
} from "@/components/directory"
import {
  AuthenticationEvents,
  AuthenticationEventFilters,
} from "@/AuthenticationEvents"
import {
  authenticationEventPath,
  authenticationEventQuery,
  type AuthenticationEventPage,
} from "@/authentication-events"
import { Providers, type ProviderDirectory } from "@/Providers"
import {
  ApplicationUses,
  ApplicationViews,
  type ApplicationUse,
} from "@/ApplicationUses"
import { SAMLServiceProviders } from "@/SAMLServiceProviders"
import { MemberPassword } from "@/MemberPassword"
import { MemberEmail, type ManagedEmail } from "@/MemberEmail"
import { IdentitySwitch } from "@/IdentitySwitch"
import { OrganizationDetails, type Organization } from "@/OrganizationDetails"
import {
  OIDCApplications,
  type OIDCApplicationDirectory,
} from "@/OIDCApplications"
import {
  passwordUsernameError,
  passwordUsernamePattern,
} from "@/member-password"
import type {
  SAMLDirectory,
  SAMLServiceProvider,
} from "@/saml-service-providers"
import {
  isOrganizationDetail,
  memberListLocation,
  parseRoute,
  routeURL,
  type Route,
} from "@/routes"
import { describeEvent, type ManagementEvent } from "@/operation-history"
import { currentLocation, Link, navigate } from "@/navigation"

type Actor = {
  memberId: string
  organizationId: string
  displayName: string
  platform: boolean
}
type Session = { actor: Actor; csrf: string }
type Member = {
  id: string
  organizationId: string
  displayName: string
  status: string
  blockSources: string[]
}
type DirectoryMember = Member & {
  organizationName?: string
  administrator?: boolean
}
type MemberPage = Page<DirectoryMember> & { administratorIds?: string[] }
type Binding = MemberBinding
type Page<T> = { items: T[]; nextAfter?: string }
type Detail = {
  member: Member
  bindings: Binding[]
  administratorIds: string[]
  passwordUsername?: string
  email: ManagedEmail
}
type Data = {
  organizations?: Page<Organization>
  organization?: Organization
  members?: MemberPage
  detail?: Detail
  events?: ManagementEvent[]
  authenticationEvents?: AuthenticationEventPage
  historyMember?: Member
  providers?: ProviderDirectory
  applicationUses?: ApplicationUse[]
  applicationPreview?: ApplicationUse | null
  oidcApplications?: OIDCApplicationDirectory
  saml?: SAMLDirectory
  serviceProvider?: SAMLServiceProvider
}
type Action = {
  title: string
  description?: string
  path: string
  method: string
  body: Record<string, unknown>
  field?: string
  value?: string
  destructive?: boolean
  openCreated?: (id: string) => void
}
const messages: Record<string, string> = {
  forbidden: "没有操作权限，或成员尚未具备可用的登录方式。",
  last_administrator: "需要保留至少一名可用管理员，请先设置另一名管理员。",
  invalid_request: "请检查填写内容。",
  provider_unavailable: "无法验证应用凭据。请检查应用状态、应用 ID 和密钥。",
  not_found: "记录不存在，请返回列表刷新。",
  conflict: "当前状态发生冲突，请刷新后重新检查。",
  username_taken: "该用户名已被本组织中的其他成员使用。",
  email_taken: "该邮箱已被本组织中的其他成员使用。请核对邮箱及成员身份。",
  invalid_csrf: "页面验证已失效，请刷新后重试。",
  sign_in_required: "登录已过期或管理员资格已失效，请重新登录。",
  not_administrator: "当前成员没有管理权限，请使用已授权的管理员身份登录。",
  login_failed: "登录未完成，请重新发起登录。",
  identity_switch_failed:
    "身份切换未完成。请刷新后重试，登录过期时请重新登录。",
}
class RequestError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { credentials: "same-origin", ...init })
  if (!response.ok) {
    if (
      response.status === 401 &&
      path !== "/api/session" &&
      !init?.signal?.aborted
    )
      window.dispatchEvent(new Event("memberid-sign-in-required"))
    const body = await response.json().catch(() => null)
    throw new RequestError(
      response.status,
      messages[body?.error] ?? "请求未完成，请稍后重试。"
    )
  }
  return response.json() as Promise<T>
}
function Status({ active, text }: { active: boolean; text?: string }) {
  return (
    <Badge variant={active ? "secondary" : "destructive"}>
      {text ?? (active ? "正常" : "已停用")}
    </Badge>
  )
}
function MemberStatus({ member }: { member: Member }) {
  return (
    <Status
      active={member.status === "active"}
      text={member.status === "active" ? "未阻断" : "已阻断"}
    />
  )
}

function signInBlockers(
  organization: Organization,
  member: Member,
  bindings: Binding[]
) {
  return [
    ...(organization.status !== "enabled" ? ["所属组织已停用"] : []),
    ...(member.blockSources.includes("manual") ? ["成员已被人工封禁"] : []),
    ...(member.blockSources.includes("externalDeparture")
      ? ["外部身份已标记为离职"]
      : []),
    ...(!bindings.some((binding) => binding.status === "active")
      ? [bindings.length ? "登录方式的绑定均已撤销" : "成员尚未绑定登录方式"]
      : []),
  ]
}

function EventDetails({
  event,
  presentation,
  description,
}: {
  event: ManagementEvent
  presentation: ReturnType<typeof describeEvent>
  description: string
}) {
  return (
    <Dialog>
      <DialogTrigger
        render={<Button variant="ghost" size="sm" />}
        aria-label={`查看操作记录详情：${presentation.action} ${presentation.targetName}`}
      >
        查看详情
      </DialogTrigger>
      <DialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>操作记录详情</DialogTitle>
          <DialogDescription>
            {presentation.action} · <RecordTime value={event.createdAt} />
          </DialogDescription>
        </DialogHeader>
        <p className="wrap-anywhere">{description}</p>
        <dl>
          <dt>操作者</dt>
          <dd className="wrap-anywhere">{presentation.actorName}</dd>
          <dt>组织</dt>
          <dd className="wrap-anywhere">
            <Link
              className="text-primary hover:underline"
              href={routeURL({ org: event.organizationId })}
            >
              {presentation.organizationName}
            </Link>
          </dd>
          <dt>对象</dt>
          <dd className="wrap-anywhere">
            {presentation.targetURL ? (
              <Link
                className="text-primary hover:underline"
                href={presentation.targetURL}
              >
                {presentation.targetName}
              </Link>
            ) : (
              presentation.targetName
            )}
          </dd>
          <dt>操作者标识</dt>
          <dd>
            <RecordIdentifier value={event.actor} label="操作者标识" />
          </dd>
          <dt>组织 ID</dt>
          <dd>
            <RecordIdentifier value={event.organizationId} label="组织 ID" />
          </dd>
          {event.memberId && (
            <>
              <dt>成员 ID</dt>
              <dd>
                <RecordIdentifier value={event.memberId} label="成员 ID" />
              </dd>
            </>
          )}
          {presentation.providerId && (
            <>
              <dt>提供商 ID</dt>
              <dd>
                <RecordIdentifier
                  value={presentation.providerId}
                  label="提供商 ID"
                />
              </dd>
            </>
          )}
        </dl>
        <h3>原始变更</h3>
        <pre>
          {JSON.stringify(
            { previous: event.previous ?? {}, changes: event.changes },
            null,
            2
          )}
        </pre>
      </DialogContent>
    </Dialog>
  )
}

export default function App() {
  const [session, setSession] = useState<Session | null>()
  const [sessionCheckFailed, setSessionCheckFailed] = useState(false)
  const [sessionCheckRevision, setSessionCheckRevision] = useState(0)
  const [sessionExpired, setSessionExpired] = useState(false)
  const [location, setLocation] = useState(currentLocation)
  const [revision, setRevision] = useState(0)
  const [data, setData] = useState<Data>({})
  const [loading, setLoading] = useState(true)
  const [loadFailure, setLoadFailure] = useState<
    "forbidden" | "missing" | "unavailable"
  >()
  const [error, setError] = useState("")
  const [action, setAction] = useState<Action | null>(null)
  const [choosingIdentity, setChoosingIdentity] = useState(false)
  const route = parseRoute(location)
  const params = route?.query ?? new URLSearchParams()
  const org = route?.org ?? ""
  const view = route?.view
  const events = view === "events"
  const authenticationEvents = view === "authentication-events"
  const providers = view === "providers"
  const oidcApplications = view === "oidc-applications"
  const saml = view === "saml-service-providers"
  const appView = saml ? "saml-service-providers" : "oidc-applications"
  const join = oidcApplications || saml ? params.get("join") || "" : ""
  const usingApps =
    (oidcApplications || saml) &&
    !!org &&
    (params.get("tab") === "used" || !!join)
  const membersView = view === "members"
  const activeView = view ?? "organization"
  const member = route?.member ?? ""
  const historyTarget = events ? (params.get("memberId") ?? "") : ""
  const after = params.get("after") ?? ""
  const before = params.get("before") ?? ""
  const memberFilters = {
    q: params.get("q") ?? "",
    status: params.get("status") ?? "",
    administrator: params.get("administrator") ?? "",
  }
  const scopeRoute: Route = org ? { org } : {}
  const memberDirectoryRoute: Route = { view: "members", ...scopeRoute }
  const memberReturnRoute =
    memberListLocation(window.history.state?.memberList) ??
    routeURL(memberDirectoryRoute)
  const fromAllOrganizations = !parseRoute(memberReturnRoute)?.org
  const memberNavigationState = { memberList: memberReturnRoute }
  const memberQuery = new URLSearchParams({ ...memberFilters, after })
  const memberSearchActive = Object.values(memberFilters).some(Boolean)
  const forbidden =
    !!session &&
    !!route &&
    !session.actor.platform &&
    !route.root &&
    org !== session.actor.organizationId

  useEffect(() => {
    let previousLocation = currentLocation()
    const change = () => {
      const next = currentLocation()
      if (next === previousLocation) return
      const sameOrganization =
        parseRoute(next)?.org === parseRoute(previousLocation)?.org
      previousLocation = next
      setAction(null)
      setData((current) =>
        sameOrganization ? { organization: current.organization } : {}
      )
      setLoading(true)
      setLoadFailure(undefined)
      setError("")
      setLocation(next)
    }
    const expired = () => {
      setSessionExpired(true)
      setSession(null)
    }
    window.addEventListener("memberid-sign-in-required", expired)
    window.addEventListener("popstate", change)
    return () => {
      window.removeEventListener("popstate", change)
      window.removeEventListener("memberid-sign-in-required", expired)
    }
  }, [])

  useEffect(() => {
    const abort = new AbortController()
    request<Session>("/api/session", { signal: abort.signal })
      .then((value) => {
        if (!abort.signal.aborted) setSession(value)
      })
      .catch((error: unknown) => {
        if (abort.signal.aborted) return
        if (error instanceof RequestError && error.status === 401)
          setSession(null)
        else setSessionCheckFailed(true)
      })
    return () => abort.abort()
  }, [sessionCheckRevision])

  useEffect(() => {
    if (!session) return
    let checking = false
    const check = async () => {
      if (document.visibilityState !== "visible" || checking) return
      checking = true
      try {
        const current = await request<Session>("/api/session")
        if (current.csrf !== session.csrf) window.location.replace("/")
      } catch (error) {
        if (error instanceof RequestError && error.status === 401)
          window.location.replace("/")
      } finally {
        checking = false
      }
    }
    window.addEventListener("focus", check)
    document.addEventListener("visibilitychange", check)
    return () => {
      window.removeEventListener("focus", check)
      document.removeEventListener("visibilitychange", check)
    }
  }, [session])

  useEffect(() => {
    if (session && join && !org) {
      navigate(
        { view: appView, org: session.actor.organizationId, join },
        { replace: true }
      )
    } else if (session && parseRoute(location)?.root) {
      navigate(
        session.actor.platform
          ? { view: "organization" }
          : { view: "members", org: session.actor.organizationId },
        { replace: true }
      )
    }
  }, [session, location, join, org, appView])

  useEffect(() => {
    if (!session || !route || route.root || forbidden || (join && !org)) return
    const abort = new AbortController()
    async function load() {
      setLoading(true)
      setLoadFailure(undefined)
      setError("")
      setData((current) => ({ organization: current.organization }))
      const options = { signal: abort.signal }
      let organization: Organization | undefined
      const fetchOrganization = async () => {
        organization = await request<Organization>(
          `/api/organizations/${encodeURIComponent(org)}`,
          options
        )
        return organization
      }
      try {
        let result: Data
        if (usingApps) {
          const base =
            "/api/organizations/" +
            encodeURIComponent(org) +
            (saml ? "/saml-application-uses" : "/oidc-application-uses")
          if (join) {
            const [preview, organization] = await Promise.all([
              request<ApplicationUse>(
                base + "/" + encodeURIComponent(join),
                options
              ).catch((err: unknown) => {
                if (err instanceof RequestError && err.status === 404)
                  return null
                throw err
              }),
              fetchOrganization(),
            ])
            result = { applicationPreview: preview, organization }
          } else {
            const [uses, organization] = await Promise.all([
              request<{ items: ApplicationUse[] }>(base, options),
              fetchOrganization(),
            ])
            result = { applicationUses: uses.items, organization }
          }
        } else if (oidcApplications) {
          const [directory, organization] = await Promise.all([
            request<OIDCApplicationDirectory>(
              `/api${routeURL({ view: "oidc-applications", org })}`,
              options
            ),
            org ? fetchOrganization() : undefined,
          ])
          result = { oidcApplications: directory, organization }
        } else if (authenticationEvents) {
          const [page, organization] = await Promise.all([
            request<AuthenticationEventPage>(
              `/api${authenticationEventPath(org)}?${authenticationEventQuery(params)}`,
              options
            ),
            org ? fetchOrganization() : undefined,
          ])
          result = { authenticationEvents: page, organization }
        } else if (events) {
          const query = new URLSearchParams({
            organizationId: org,
            before,
            memberId: historyTarget,
          })
          const [history, organization, memberDetail] = await Promise.all([
            request<{ items: ManagementEvent[] }>(
              `/api/events?${query}`,
              options
            ),
            org ? fetchOrganization() : undefined,
            org && historyTarget
              ? request<Detail>(
                  `/api/organizations/${encodeURIComponent(org)}/members/${encodeURIComponent(historyTarget)}`,
                  options
                ).catch(() => undefined)
              : undefined,
          ])
          result = {
            events: history.items,
            organization,
            historyMember: memberDetail?.member,
          }
        } else if (org) {
          result = { organization: await fetchOrganization() }
          if (providers) {
            result.providers = await request<ProviderDirectory>(
              `/api/organizations/${encodeURIComponent(org)}/providers`,
              options
            )
          } else if (saml) {
            const endpoint = `/api/organizations/${encodeURIComponent(org)}/saml-service-providers`
            const selected = params.get("serviceProviderId")
            const [directory, detail] = await Promise.all([
              request<SAMLDirectory>(
                `${endpoint}${after ? `?after=${encodeURIComponent(after)}` : ""}`,
                options
              ),
              selected
                ? request<SAMLServiceProvider>(
                    `${endpoint}/${encodeURIComponent(selected)}`,
                    options
                  )
                : undefined,
            ])
            result.saml = directory
            result.serviceProvider = detail
          } else if (member) {
            result.detail = await request<Detail>(
              `/api/organizations/${encodeURIComponent(org)}/members/${encodeURIComponent(member)}`,
              options
            )
          } else if (membersView) {
            result.members = await request<MemberPage>(
              `/api/organizations/${encodeURIComponent(org)}/members?${memberQuery}`,
              options
            )
          }
        } else if (membersView) {
          result = {
            members: await request<MemberPage>(
              `/api/members?${memberQuery}`,
              options
            ),
          }
        } else
          result = {
            organizations: await request<Page<Organization>>(
              `/api/organizations?after=${encodeURIComponent(after)}`,
              options
            ),
          }
        if (!abort.signal.aborted) setData(result)
      } catch (error) {
        if (!abort.signal.aborted) {
          const status =
            error instanceof RequestError ? error.status : undefined
          setData((current) => ({
            organization:
              status === 403 || status === 404
                ? undefined
                : (organization ?? current.organization),
          }))
          setLoadFailure(
            status === 403
              ? "forbidden"
              : status === 404
                ? "missing"
                : "unavailable"
          )
        }
      } finally {
        if (!abort.signal.aborted) setLoading(false)
      }
    }
    void load()
    return () => abort.abort()
    // Route parameters are represented by location; successful mutations bump revision.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session, location, revision])

  if (!route)
    return (
      <main className="login-page">
        <h1>页面不存在</h1>
        <p>请检查链接，或返回管理首页。</p>
        <Button render={<Link href="/" />} nativeButton={false}>
          返回管理首页
        </Button>
      </main>
    )

  if (sessionCheckFailed)
    return (
      <main className="login-page">
        <h1 role="alert">暂时无法检查登录状态</h1>
        <Button
          onClick={() => {
            setSessionCheckFailed(false)
            setSessionCheckRevision((value) => value + 1)
          }}
        >
          重试
        </Button>
      </main>
    )

  if (session === undefined || (session && route.root))
    return (
      <main className="login-page">
        <Skeleton className="h-12 w-64" />
        <p>正在检查登录状态…</p>
      </main>
    )
  if (!session) {
    const code = new URLSearchParams(window.location.search).get("error") ?? ""
    const returnQuery = new URLSearchParams(window.location.search)
    returnQuery.delete("error")
    const returnTo =
      window.location.pathname + (returnQuery.size ? `?${returnQuery}` : "")
    return (
      <main className="login-page">
        <div className="identity-mark">
          <Fingerprint />
        </div>
        <h1>{sessionExpired ? "登录已过期" : "MemberID 管理控制台"}</h1>
        <Button
          size="lg"
          render={
            <a href={`/auth/login?${new URLSearchParams({ returnTo })}`} />
          }
          nativeButton={false}
        >
          {sessionExpired ? "重新登录" : "使用 MemberID 登录"}
          <ChevronRight data-icon="inline-end" />
        </Button>
        <div className="feedback" role="status">
          {code && (
            <Alert variant="destructive">
              <AlertDescription>
                {messages[code] ?? messages.login_failed}
              </AlertDescription>
            </Alert>
          )}
        </div>
      </main>
    )
  }

  const actor = session.actor
  const accessDenied = forbidden || loadFailure === "forbidden"
  const navigationScope = forbidden ? { org: actor.organizationId } : scopeRoute
  const unavailableScope = accessDenied || loadFailure === "missing"
  const emptyOrganizationPage = !after && data.organizations?.items.length === 0
  const emptyMemberPage = !after && data.members?.items.length === 0
  const noMemberMatches = emptyMemberPage && memberSearchActive
  const showCreateOrganization =
    actor.platform && activeView === "organization" && !org && !unavailableScope
  const showOrganizationDetails = isOrganizationDetail(route)
  const showCreateMember = membersView && !member && !!org && !unavailableScope
  const base = `/api/organizations/${encodeURIComponent(org)}`
  const scopeName = org ? (data.organization?.name ?? "当前组织") : "所有组织"
  const breadcrumbs: BreadcrumbItem[] = []
  if (membersView || (events && historyTarget)) {
    breadcrumbs.push({
      label: "成员",
      href: member || historyTarget ? memberReturnRoute : undefined,
    })
    if (member)
      breadcrumbs.push({ label: data.detail?.member.displayName ?? "成员详情" })
    if (historyTarget) {
      breadcrumbs.push(
        {
          label: data.historyMember?.displayName ?? "成员详情",
          href: routeURL({ ...memberDirectoryRoute, member: historyTarget }),
          state: memberNavigationState,
        },
        { label: "操作记录" }
      )
    }
  } else if (providers) {
    breadcrumbs.push({ label: "身份提供商" })
  } else if (oidcApplications) {
    breadcrumbs.push({ label: "OIDC 应用" })
  } else if (saml) {
    breadcrumbs.push({ label: "SAML 应用" })
  } else if (authenticationEvents) {
    breadcrumbs.push({ label: "认证记录" })
  } else if (events) {
    breadcrumbs.push({ label: "操作记录" })
  } else {
    breadcrumbs.push({
      label: "组织",
      href:
        org && actor.platform ? routeURL({ view: "organization" }) : undefined,
    })
    if (org) breadcrumbs.push({ label: scopeName })
  }
  const selected = data.detail?.member
  const administrator =
    !!selected && !!data.detail?.administratorIds.includes(selected.id)
  const blockers =
    selected && data.detail && data.organization
      ? signInBlockers(data.organization, selected, data.detail.bindings)
      : []
  const systemOrganizationId = actor.platform ? actor.organizationId : undefined
  const adminTitle = org === systemOrganizationId ? "平台管理员" : "组织管理员"
  const rename = (field: string, value: string, path: string, title: string) =>
    setAction({
      title,
      field,
      value,
      path,
      method: "PATCH",
      body: {},
    })
  const refresh = () => setRevision((v) => v + 1)
  const clearMemberFilters = () => navigate(memberDirectoryRoute)
  const create = (isOrganization: boolean) =>
    setAction({
      title: isOrganization ? "新建组织" : "新增成员",
      path: isOrganization ? "/api/organizations" : `${base}/members`,
      method: "POST",
      body: {},
      field: isOrganization ? "name" : "displayName",
      openCreated: (id) =>
        navigate(
          isOrganization
            ? { view: "organization", org: id }
            : { ...memberDirectoryRoute, member: id },
          { state: isOrganization ? undefined : { memberList: location } }
        ),
    })

  return (
    <ConsoleLayout
      actor={actor}
      breadcrumbs={breadcrumbs}
      navigation={[
        {
          label: "身份管理",
          icon: Building2,
          items: [
            {
              label: "组织",
              href: routeURL({ view: "organization", ...navigationScope }),
              active: activeView === "organization",
            },
            {
              label: "成员",
              href: routeURL({ view: "members", ...navigationScope }),
              active: membersView,
            },
            {
              label: "身份提供商",
              href: routeURL({ view: "providers", ...navigationScope }),
              active: providers,
            },
          ],
        },
        {
          label: "应用接入",
          icon: AppWindow,
          items: [
            {
              label: "OIDC 应用",
              href: routeURL({ view: "oidc-applications", ...navigationScope }),
              active: oidcApplications,
            },
            {
              label: "SAML 应用",
              href: routeURL({
                view: "saml-service-providers",
                ...navigationScope,
              }),
              active: saml,
            },
          ],
        },
        {
          label: "活动",
          icon: History,
          items: [
            {
              label: "认证记录",
              href: routeURL({
                view: "authentication-events",
                ...navigationScope,
              }),
              active: authenticationEvents,
            },
            {
              label: "操作记录",
              href: routeURL({ view: "events", ...navigationScope }),
              active: events,
            },
          ],
        },
      ]}
      onSignOut={async () => {
        try {
          await request("/api/logout", {
            method: "POST",
            headers: { "X-CSRF-Token": session.csrf },
          })
          setSessionExpired(false)
          setSession(null)
          navigate("/", { replace: true })
        } catch (e) {
          setError((e as Error).message)
        }
      }}
      onChooseIdentity={() => setChoosingIdentity(true)}
      scope={
        <OrganizationSwitcher
          organizationId={org}
          name={scopeName}
          system={org === systemOrganizationId}
          canSwitch={actor.platform}
          onSelect={(id) =>
            navigate({ view: activeView, ...(id ? { org: id } : {}) })
          }
        />
      }
    >
      {choosingIdentity && (
        <IdentitySwitch
          memberId={actor.memberId}
          csrf={session.csrf}
          request={request}
          onClose={() => setChoosingIdentity(false)}
        />
      )}
      {params.get("error") === "identity_switch_failed" && (
        <Alert variant="destructive">
          <AlertDescription>{messages.identity_switch_failed}</AlertDescription>
        </Alert>
      )}
      <div className="page-heading">
        <div>
          <h1>
            {authenticationEvents
              ? "认证记录"
              : events
                ? historyTarget
                  ? `${data.historyMember?.displayName ?? "成员"}的操作记录`
                  : "操作记录"
                : providers
                  ? "身份提供商"
                  : oidcApplications || saml
                    ? oidcApplications
                      ? "OIDC 应用"
                      : "SAML 应用"
                    : membersView
                      ? member
                        ? (selected?.displayName ?? "成员详情")
                        : "成员"
                      : (data.organization?.name ?? "组织")}
          </h1>
        </div>
        <div className="actions">
          {!unavailableScope && !loadFailure && (
            <Button
              variant="outline"
              size="icon"
              aria-label="刷新页面"
              title="刷新"
              disabled={loading}
              onClick={refresh}
            >
              <RefreshCw className={loading ? "animate-spin" : undefined} />
            </Button>
          )}
          {events && org && historyTarget && (
            <>
              {data.historyMember && (
                <Button
                  variant="outline"
                  render={
                    <Link
                      href={routeURL({
                        ...memberDirectoryRoute,
                        member: historyTarget,
                      })}
                      state={memberNavigationState}
                    />
                  }
                  nativeButton={false}
                >
                  返回成员详情
                </Button>
              )}
              <Button
                variant="outline"
                render={<Link href={routeURL({ view: "events", org })} />}
                nativeButton={false}
              >
                查看本组织记录
              </Button>
            </>
          )}
          {showCreateOrganization && !emptyOrganizationPage && (
            <Button onClick={() => create(true)}>
              <Plus data-icon="inline-start" />
              新建组织
            </Button>
          )}
          {member && (
            <Button
              variant="outline"
              render={<Link href={memberReturnRoute} />}
              nativeButton={false}
            >
              {fromAllOrganizations ? "返回所有组织的成员" : "返回成员列表"}
            </Button>
          )}
          {showCreateMember && (!emptyMemberPage || memberSearchActive) && (
            <Button
              disabled={loading || !!loadFailure}
              onClick={() => create(false)}
            >
              <Plus data-icon="inline-start" />
              新增成员
            </Button>
          )}
          {showOrganizationDetails && (
            <>
              {actor.platform && (
                <Button
                  variant="outline"
                  render={<Link href="/organizations" />}
                  nativeButton={false}
                >
                  所有组织
                </Button>
              )}
              {data.organization && (
                <Button
                  render={<Link href={routeURL(memberDirectoryRoute)} />}
                  nativeButton={false}
                >
                  查看成员
                </Button>
              )}
            </>
          )}
        </div>
      </div>
      <div className="console-feedback" aria-live="polite">
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
            <Button
              variant="ghost"
              size="icon-sm"
              aria-label="关闭提示"
              onClick={() => setError("")}
            >
              <X />
            </Button>
          </Alert>
        )}
      </div>
      <div
        className={
          membersView && !member
            ? "w-full"
            : unavailableScope || loadFailure
              ? "directory"
              : undefined
        }
      >
        {membersView && !member && !unavailableScope && (
          <MemberSearch
            key={`${org}:${JSON.stringify(memberFilters)}`}
            filters={memberFilters}
            onSubmit={(filters) =>
              navigate({ ...memberDirectoryRoute, ...filters })
            }
            onClear={clearMemberFilters}
            showClear={!noMemberMatches}
          />
        )}
        {authenticationEvents && !unavailableScope && (
          <AuthenticationEventFilters
            key={`${org}:${authenticationEventQuery(params)}`}
            org={org}
            query={params}
          />
        )}
        {unavailableScope ? (
          <DirectoryState
            kind={accessDenied ? "forbidden" : "error"}
            title={
              accessDenied ? "当前账号无权访问此管理范围" : "找不到此管理范围"
            }
            action={
              <Button
                variant="outline"
                render={<Link href="/" />}
                nativeButton={false}
              >
                返回管理首页
              </Button>
            }
          />
        ) : loadFailure ? (
          <DirectoryState
            kind="error"
            title={
              authenticationEvents
                ? "暂时无法加载认证记录"
                : events
                  ? "暂时无法加载操作记录"
                  : providers
                    ? "暂时无法加载身份提供商"
                    : oidcApplications || saml
                      ? oidcApplications
                        ? "暂时无法加载 OIDC 应用"
                        : "暂时无法加载 SAML 应用"
                      : membersView
                        ? member
                          ? "暂时无法加载成员详情"
                          : "暂时无法加载成员列表"
                        : org
                          ? "暂时无法加载组织详情"
                          : "暂时无法加载组织列表"
            }
            action={
              <Button variant="outline" onClick={refresh}>
                重试
              </Button>
            }
          />
        ) : loading ? (
          <div
            className="directory-loading"
            role="status"
            aria-label="正在加载列表"
          >
            <Skeleton className="h-12 w-full" />
            <Skeleton className="h-64 w-full" />
          </div>
        ) : (
          <>
            {(oidcApplications || saml) && org && (
              <ApplicationViews view={appView} org={org} used={usingApps} />
            )}
            {usingApps && data.organization && (
              <ApplicationUses
                view={appView}
                key={location}
                org={data.organization}
                items={data.applicationUses}
                preview={data.applicationPreview}
                csrf={session.csrf}
                request={request}
                refresh={refresh}
              />
            )}
            {data.oidcApplications && (
              <OIDCApplications
                key={org}
                directory={data.oidcApplications}
                ownerId={org}
                platform={actor.platform}
                csrf={session.csrf}
                request={request}
                onComplete={(application) =>
                  setData((current) => {
                    const directory = current.oidcApplications
                    if (!directory || currentLocation() !== location)
                      return current
                    const items = directory.items.filter(
                      (item) => item.clientId !== application.clientId
                    )
                    items.push(application)
                    items.sort((a, b) => a.clientId.localeCompare(b.clientId))
                    return {
                      ...current,
                      oidcApplications: { ...directory, items },
                    }
                  })
                }
              />
            )}
            {data.organizations && (
              <section aria-label="组织列表">
                <div className="overflow-hidden rounded-md border">
                  <DirectoryResults
                    count={data.organizations.items.length}
                    empty={
                      after ? undefined : (
                        <DirectoryState
                          kind="empty"
                          title="暂无组织"
                          action={
                            showCreateOrganization && (
                              <Button onClick={() => create(true)}>
                                <Plus data-icon="inline-start" />
                                新建组织
                              </Button>
                            )
                          }
                        />
                      )
                    }
                  >
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>组织</TableHead>
                          <TableHead>状态</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {data.organizations.items.map((o) => (
                          <TableRow key={o.id}>
                            <TableCell>
                              <div className="flex items-center gap-2">
                                <Link
                                  className="block max-w-64 truncate font-medium hover:underline"
                                  title={o.name}
                                  href={routeURL({
                                    view: activeView,
                                    org: o.id,
                                  })}
                                >
                                  {o.name}
                                </Link>
                                {o.id === systemOrganizationId && (
                                  <Badge variant="outline">系统</Badge>
                                )}
                              </div>
                            </TableCell>
                            <TableCell>
                              {o.status === "enabled" ? "已启用" : "已停用"}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </DirectoryResults>
                </div>
                <OrganizationPagination
                  count={data.organizations.items.length}
                  after={after}
                  next={data.organizations.nextAfter}
                  route={providers || saml ? { view: activeView } : {}}
                />
              </section>
            )}
            {data.providers && data.organization && (
              <Providers
                key={`${org}:${params.get("providerId") ?? ""}`}
                selectedId={params.get("providerId") ?? undefined}
                directory={data.providers}
                enabled={data.organization.status === "enabled"}
                system={org === systemOrganizationId}
                base={base}
                csrf={session.csrf}
                save={request}
                onComplete={refresh}
              />
            )}
            {data.saml && data.organization && (
              <SAMLServiceProviders
                key={`${org}:${params.get("serviceProviderId") ?? ""}:${revision}`}
                directory={data.saml}
                selected={data.serviceProvider}
                organizationId={org}
                after={after}
                csrf={session.csrf}
                save={request}
                onComplete={refresh}
              />
            )}
            {showOrganizationDetails && data.organization && (
              <OrganizationDetails
                key={JSON.stringify([
                  data.organization.id,
                  data.organization.slug,
                ])}
                organization={data.organization}
                canChangeSlug={
                  org !== systemOrganizationId &&
                  (data.organization.slug
                    ? actor.platform
                    : actor.organizationId === org)
                }
                onChangeSlug={(slug) => {
                  const previous = data.organization?.slug ?? ""
                  setAction({
                    title: previous ? "修改组织登录名" : "设置组织登录名",
                    description: previous
                      ? `将“${previous}”改为“${slug}”后，旧登录链接将无法访问本组织。成员须更新密码管理器中以 @${previous} 结尾的用户名。其他组织可以立即使用旧登录名。`
                      : `将本组织的登录名设为“${slug}”。设置后，仅平台管理员可以修改。`,
                    path: base + "/login-slug",
                    method: "PUT",
                    body: { expectedSlug: previous, slug },
                    destructive: !!previous,
                  })
                }}
                canChangeStatus={actor.platform && org !== systemOrganizationId}
                save={(name) =>
                  request<Organization>(base, {
                    method: "PATCH",
                    headers: {
                      "Content-Type": "application/json",
                      "X-CSRF-Token": session.csrf,
                    },
                    body: JSON.stringify({ name }),
                  })
                }
                onSaved={(organization) =>
                  setData((current) =>
                    current.organization?.id === organization.id
                      ? {
                          ...current,
                          organization: {
                            ...current.organization,
                            ...organization,
                          },
                        }
                      : current
                  )
                }
                onStatusChange={() =>
                  setAction({
                    title:
                      data.organization!.status === "enabled"
                        ? "停用组织"
                        : "启用组织",
                    description:
                      data.organization!.status === "enabled"
                        ? "停用后，该组织成员无法通过后续登录和身份有效性检查。已有业务系统会话由各应用管理。"
                        : undefined,
                    path: base,
                    method: "PATCH",
                    body: {
                      status:
                        data.organization!.status === "enabled"
                          ? "disabled"
                          : "enabled",
                    },
                    destructive: data.organization!.status === "enabled",
                  })
                }
              />
            )}
            {data.members && (
              <section aria-label="成员列表">
                <div className="overflow-hidden rounded-md border">
                  <DirectoryResults
                    count={data.members.items.length}
                    empty={
                      after ? undefined : (
                        <DirectoryState
                          kind={noMemberMatches ? "filtered" : "empty"}
                          title={
                            noMemberMatches
                              ? "没有符合当前筛选条件的成员"
                              : org
                                ? "本组织还没有成员"
                                : "还没有成员"
                          }
                          action={
                            noMemberMatches ? (
                              <Button
                                variant="outline"
                                onClick={clearMemberFilters}
                              >
                                清除筛选
                              </Button>
                            ) : (
                              showCreateMember && (
                                <Button onClick={() => create(false)}>
                                  <Plus data-icon="inline-start" />
                                  新增成员
                                </Button>
                              )
                            )
                          }
                        />
                      )
                    }
                  >
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>成员</TableHead>
                          {!org && <TableHead>所属组织</TableHead>}
                          <TableHead>身份状态</TableHead>
                          <TableHead>管理权限</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {data.members.items.map((m) => (
                          <TableRow key={m.id}>
                            <TableCell>
                              <Link
                                className="block max-w-64 truncate font-medium hover:underline"
                                title={m.displayName}
                                href={routeURL({
                                  view: "members",
                                  org: m.organizationId,
                                  member: m.id,
                                })}
                                state={{ memberList: location }}
                              >
                                {m.displayName}
                              </Link>
                            </TableCell>
                            {!org && (
                              <TableCell>
                                <span
                                  className="block max-w-64 truncate"
                                  title={m.organizationName}
                                >
                                  {m.organizationName ?? "所属组织"}
                                </span>
                              </TableCell>
                            )}
                            <TableCell>
                              {m.status === "active" ? "未阻断" : "已阻断"}
                            </TableCell>
                            <TableCell>
                              {(m.administrator ??
                              data.members?.administratorIds?.includes(m.id))
                                ? m.organizationId === systemOrganizationId
                                  ? "平台管理员"
                                  : "组织管理员"
                                : "普通成员"}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </DirectoryResults>
                </div>
                <MemberPagination
                  count={data.members.items.length}
                  after={after}
                  next={data.members.nextAfter}
                  route={{ ...memberDirectoryRoute, ...memberFilters }}
                />
              </section>
            )}
            {selected && data.detail && (
              <section
                aria-label="成员详情"
                className="grid items-start gap-4 lg:grid-cols-2"
              >
                <Card>
                  <CardHeader>
                    <CardTitle role="heading" aria-level={2}>
                      成员资料
                    </CardTitle>
                    <CardAction>
                      <MemberStatus member={selected} />
                    </CardAction>
                  </CardHeader>
                  <CardContent>
                    <dl>
                      <dt>成员 ID</dt>
                      <dd>
                        <RecordIdentifier value={selected.id} label="成员 ID" />
                      </dd>
                      <dt>阻断原因</dt>
                      <dd>
                        {selected.blockSources
                          .map((v) =>
                            v === "manual" ? "人工封禁" : "外部离职"
                          )
                          .join("、") || "无"}
                      </dd>
                    </dl>
                  </CardContent>
                  <CardFooter className="flex-wrap gap-2">
                    <Button
                      variant="outline"
                      onClick={() =>
                        rename(
                          "displayName",
                          selected.displayName,
                          `${base}/members/${member}`,
                          "修改成员名称"
                        )
                      }
                    >
                      修改名称
                    </Button>
                    <Button
                      variant={
                        selected.blockSources.includes("manual")
                          ? "outline"
                          : "destructive"
                      }
                      onClick={() =>
                        setAction({
                          title: selected.blockSources.includes("manual")
                            ? "解除人工封禁"
                            : "封禁成员",
                          description: "人工解封不会清除外部离职等阻断。",
                          path: `${base}/members/${member}`,
                          method: "PATCH",
                          body: {
                            manualBlocked:
                              !selected.blockSources.includes("manual"),
                          },
                          destructive:
                            !selected.blockSources.includes("manual"),
                        })
                      }
                    >
                      {selected.blockSources.includes("manual")
                        ? "解除人工封禁"
                        : "封禁成员"}
                    </Button>
                    <Button
                      variant="outline"
                      render={
                        <Link
                          href={routeURL({
                            org,
                            view: "events",
                            target: member,
                          })}
                          state={memberNavigationState}
                        />
                      }
                      nativeButton={false}
                    >
                      查看记录
                      <ChevronRight data-icon="inline-end" />
                    </Button>
                  </CardFooter>
                </Card>
                <div className="grid gap-4">
                  <MemberEmail
                    key={member}
                    email={data.detail.email}
                    save={(input) =>
                      request(`${base}/members/${member}/email`, {
                        method: "PUT",
                        headers: {
                          "Content-Type": "application/json",
                          "X-CSRF-Token": session.csrf,
                        },
                        body: JSON.stringify(input),
                      })
                    }
                    onComplete={refresh}
                  />
                  <Card>
                    <CardHeader>
                      <CardTitle role="heading" aria-level={2}>
                        管理权限
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <Badge variant={administrator ? "secondary" : "outline"}>
                        {administrator ? adminTitle : "普通成员"}
                      </Badge>
                    </CardContent>
                    <CardFooter>
                      <Button
                        variant={administrator ? "destructive" : "outline"}
                        onClick={() =>
                          setAction({
                            title: administrator
                              ? `取消${adminTitle}`
                              : `设为${adminTitle}`,
                            description: administrator
                              ? "撤销后，该成员后续的管理请求将被拒绝。"
                              : "成员需具有可用的登录方式。此授权不会赋予业务应用中的角色。",
                            path: `${base}/members/${member}/administrator`,
                            method: "PUT",
                            body: { enabled: !administrator },
                            destructive: administrator,
                          })
                        }
                      >
                        {administrator ? "取消管理员" : "设为管理员"}
                      </Button>
                    </CardFooter>
                  </Card>
                  <Card>
                    <CardHeader>
                      <CardTitle role="heading" aria-level={2}>
                        登录方式
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="grid gap-4">
                      {blockers.length > 0 && (
                        <Alert variant="destructive">
                          <AlertTitle>当前无法登录</AlertTitle>
                          <AlertDescription>
                            <ul className="flex list-disc flex-col gap-1 pl-5">
                              {blockers.map((reason) => (
                                <li key={reason}>{reason}</li>
                              ))}
                            </ul>
                          </AlertDescription>
                        </Alert>
                      )}
                      <MemberGrants
                        key={`${org}:${member}`}
                        organizationId={org}
                        memberId={member}
                        request={request}
                      />
                      <MemberBindings
                        items={data.detail.bindings}
                        username={data.detail.passwordUsername}
                      />
                      {actor.memberId === member && (
                        <SelfAccountLink
                          csrf={session.csrf}
                          request={request}
                        />
                      )}
                    </CardContent>
                    {actor.platform && (
                      <CardFooter className="flex flex-wrap gap-2">
                        {data.detail.passwordUsername &&
                          !(
                            org === systemOrganizationId &&
                            data.detail.passwordUsername === "root"
                          ) && (
                            <Button
                              variant="outline"
                              onClick={() =>
                                setAction({
                                  title: "修改登录用户名",
                                  path: `${base}/members/${member}/password`,
                                  method: "PATCH",
                                  field: "username",
                                  value: data.detail?.passwordUsername,
                                  body: {
                                    expectedUsername:
                                      data.detail?.passwordUsername,
                                  },
                                })
                              }
                            >
                              修改登录用户名
                            </Button>
                          )}
                        <MemberPassword
                          key={member}
                          configured={data.detail.bindings.some(
                            (binding) => binding.factorType === "password"
                          )}
                          generate={(username) =>
                            request(
                              `${base}/members/${member}/password${username === undefined ? "/reset" : ""}`,
                              {
                                method: "POST",
                                headers: {
                                  "Content-Type": "application/json",
                                  "X-CSRF-Token": session.csrf,
                                },
                                body: JSON.stringify(
                                  username === undefined ? {} : { username }
                                ),
                              }
                            )
                          }
                          onComplete={refresh}
                        />
                      </CardFooter>
                    )}
                  </Card>
                </div>
              </section>
            )}
            {data.authenticationEvents && (
              <AuthenticationEvents
                org={org}
                query={params}
                page={data.authenticationEvents}
                loadEvent={request}
              />
            )}
            {data.events && (
              <section aria-label="操作记录列表">
                <div className="overflow-hidden rounded-md border">
                  <DirectoryResults
                    count={data.events.length}
                    empty={
                      before ? undefined : (
                        <DirectoryState kind="empty" title="暂无管理操作记录" />
                      )
                    }
                  >
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>时间</TableHead>
                          <TableHead>操作者</TableHead>
                          {!org && <TableHead>组织</TableHead>}
                          <TableHead>操作</TableHead>
                          <TableHead>对象</TableHead>
                          <TableHead>变更</TableHead>
                          <TableHead className="w-0 text-right">
                            <span className="sr-only">详情</span>
                          </TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {data.events.map((event) => {
                          const presentation = describeEvent(event)
                          const description =
                            presentation.changes.join("；") || "—"
                          return (
                            <TableRow key={event.id}>
                              <TableCell>
                                <RecordTime value={event.createdAt} compact />
                              </TableCell>
                              <TableCell>
                                <span
                                  className="block max-w-40 truncate"
                                  title={presentation.actorName}
                                >
                                  {presentation.actorName}
                                </span>
                              </TableCell>
                              {!org && (
                                <TableCell>
                                  <Link
                                    className="block max-w-48 truncate font-medium hover:underline"
                                    title={presentation.organizationName}
                                    href={routeURL({
                                      org: event.organizationId,
                                    })}
                                  >
                                    {presentation.organizationName}
                                  </Link>
                                </TableCell>
                              )}
                              <TableCell>{presentation.action}</TableCell>
                              <TableCell>
                                {presentation.targetURL ? (
                                  <Link
                                    className="block max-w-48 truncate font-medium hover:underline"
                                    title={presentation.targetName}
                                    href={presentation.targetURL}
                                  >
                                    {presentation.targetName}
                                  </Link>
                                ) : (
                                  <span
                                    className="block max-w-48 truncate"
                                    title={presentation.targetName}
                                  >
                                    {presentation.targetName}
                                  </span>
                                )}
                              </TableCell>
                              <TableCell>
                                <span
                                  className="block max-w-64 truncate"
                                  title={description}
                                >
                                  {description}
                                </span>
                              </TableCell>
                              <TableCell className="w-0 text-right">
                                <EventDetails
                                  event={event}
                                  presentation={presentation}
                                  description={description}
                                />
                              </TableCell>
                            </TableRow>
                          )
                        })}
                      </TableBody>
                    </Table>
                  </DirectoryResults>
                </div>
                {(data.events.length > 0 || before) && (
                  <div className="flex items-center justify-end gap-2 py-4">
                    <div className="flex-1 text-sm text-muted-foreground">
                      {data.events.length
                        ? `本页 ${data.events.length} 条记录`
                        : "没有更早的记录"}
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={!before}
                      onClick={() =>
                        navigate(
                          { org, view: "events", target: historyTarget },
                          { state: memberNavigationState }
                        )
                      }
                    >
                      {data.events.length > 0 ? "最新记录" : "返回最新记录"}
                    </Button>
                    {data.events.length > 0 && (
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={data.events.length < 50}
                        onClick={() =>
                          navigate(
                            {
                              org,
                              view: "events",
                              target: historyTarget,
                              before: String(data.events!.at(-1)!.id),
                            },
                            { state: memberNavigationState }
                          )
                        }
                      >
                        更早记录
                      </Button>
                    )}
                  </div>
                )}
              </section>
            )}
          </>
        )}
      </div>
      {action && (
        <ActionDialog
          key={`${action.path}:${action.title}`}
          action={action}
          csrf={session.csrf}
          onClose={() => setAction(null)}
          onComplete={(id, submittedFrom) => {
            if (currentLocation() !== submittedFrom) {
              refresh()
              return
            }
            setAction(null)
            if (id && action.openCreated) {
              action.openCreated(id)
            } else {
              refresh()
            }
          }}
        />
      )}
    </ConsoleLayout>
  )
}

function OrganizationSwitcher({
  organizationId,
  name,
  system,
  canSwitch,
  onSelect,
}: {
  organizationId: string
  name: string
  system: boolean
  canSwitch: boolean
  onSelect: (id: string) => void
}) {
  const [open, setOpen] = useState(false)
  const { isMobile, setOpenMobile, state } = useSidebar()
  const identity = (
    <>
      <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-primary text-primary-foreground">
        <Fingerprint aria-hidden="true" />
      </span>
      <div className="grid min-w-0 flex-1 text-left text-sm leading-tight group-data-[collapsible=icon]:hidden">
        <span className="truncate font-medium" title={name}>
          {name}
        </span>
        <span className="truncate text-xs">
          {system ? "MemberID · 系统组织" : "MemberID"}
        </span>
      </div>
    </>
  )
  return (
    <SidebarMenu>
      <SidebarMenuItem>
        {canSwitch ? (
          <DropdownMenu open={open} onOpenChange={setOpen}>
            <DropdownMenuTrigger
              render={
                <SidebarMenuButton
                  size="lg"
                  tooltip={{
                    children: name,
                    hidden: open || isMobile || state !== "collapsed",
                  }}
                  className="data-open:bg-sidebar-accent data-open:text-sidebar-accent-foreground"
                />
              }
              aria-label={`切换组织，当前为${name}`}
            >
              {identity}
              <ChevronsUpDown
                aria-hidden="true"
                className="ml-auto group-data-[collapsible=icon]:hidden"
              />
            </DropdownMenuTrigger>
            <DropdownMenuContent
              aria-label="切换组织"
              className="w-64 max-w-[calc(100vw-2rem)]"
              align="start"
              side={isMobile ? "bottom" : "right"}
              sideOffset={4}
            >
              {open && (
                <OrganizationChoices
                  organizationId={organizationId}
                  onSelect={(id) => {
                    setOpen(false)
                    setOpenMobile(false)
                    if (id !== organizationId) onSelect(id)
                  }}
                />
              )}
            </DropdownMenuContent>
          </DropdownMenu>
        ) : (
          <SidebarMenuButton size="lg" render={<div />} title={name}>
            {identity}
          </SidebarMenuButton>
        )}
      </SidebarMenuItem>
    </SidebarMenu>
  )
}

function OrganizationChoices({
  organizationId,
  onSelect,
}: {
  organizationId: string
  onSelect: (id: string) => void
}) {
  const [after, setAfter] = useState("")
  const [page, setPage] = useState<Page<Organization>>()
  const [error, setError] = useState("")
  const [retry, setRetry] = useState(0)

  useEffect(() => {
    const abort = new AbortController()
    request<Page<Organization>>(
      `/api/organizations?after=${encodeURIComponent(after)}`,
      { signal: abort.signal }
    )
      .then((result) => {
        if (!abort.signal.aborted) setPage(result)
      })
      .catch((err: Error) => {
        if (!abort.signal.aborted) setError(err.message)
      })
    return () => abort.abort()
  }, [after, retry])

  const nextAfter = page?.nextAfter
  const goToPage = (cursor: string) => {
    setPage(undefined)
    setAfter(cursor)
  }

  return (
    <>
      <DropdownMenuGroup>
        <DropdownMenuRadioGroup value={organizationId}>
          <DropdownMenuRadioItem
            value=""
            className="gap-2 p-2 pr-8"
            closeOnClick
            onClick={() => onSelect("")}
          >
            <span className="flex size-6 shrink-0 items-center justify-center rounded-md border">
              <Fingerprint aria-hidden="true" />
            </span>
            所有组织
          </DropdownMenuRadioItem>
          <DropdownMenuSeparator />
          <div className="max-h-[50dvh] overflow-y-auto">
            {page ? (
              page.items.map((organization) => (
                <DropdownMenuRadioItem
                  key={organization.id}
                  value={organization.id}
                  className="gap-2 p-2 pr-8"
                  closeOnClick
                  onClick={() => onSelect(organization.id)}
                >
                  <span className="flex size-6 shrink-0 items-center justify-center rounded-md border">
                    <Building2 aria-hidden="true" />
                  </span>
                  <span className="truncate" title={organization.name}>
                    {organization.name}
                  </span>
                  {organization.status !== "enabled" && (
                    <Badge variant="secondary">已停用</Badge>
                  )}
                </DropdownMenuRadioItem>
              ))
            ) : error ? (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            ) : (
              <p className="p-2 text-sm text-muted-foreground" role="status">
                正在加载组织…
              </p>
            )}
          </div>
        </DropdownMenuRadioGroup>
      </DropdownMenuGroup>
      {error && (
        <DropdownMenuGroup>
          <DropdownMenuItem
            closeOnClick={false}
            onClick={() => {
              setError("")
              setRetry((attempt) => attempt + 1)
            }}
          >
            重试
          </DropdownMenuItem>
        </DropdownMenuGroup>
      )}
      {(after || nextAfter) && (
        <>
          <DropdownMenuSeparator />
          <DropdownMenuGroup className="flex gap-1">
            <DropdownMenuItem
              className="flex-1 justify-center"
              closeOnClick={false}
              disabled={!page || !after}
              onClick={() => goToPage("")}
            >
              第一页
            </DropdownMenuItem>
            <DropdownMenuItem
              className="flex-1 justify-center"
              closeOnClick={false}
              disabled={!nextAfter}
              onClick={() => nextAfter && goToPage(nextAfter)}
            >
              下一页
            </DropdownMenuItem>
          </DropdownMenuGroup>
        </>
      )}
    </>
  )
}

type MemberFilters = {
  q: string
  status: string
  administrator: string
}

const memberStatusOptions = [
  { value: "all", label: "全部状态" },
  { value: "active", label: "未阻断" },
  { value: "blocked", label: "已阻断" },
]
const memberRoleOptions = [
  { value: "all", label: "全部成员" },
  { value: "yes", label: "管理员" },
  { value: "no", label: "普通成员" },
]

function MemberSearch({
  filters,
  onSubmit,
  onClear,
  showClear,
}: {
  filters: MemberFilters
  onSubmit: (filters: MemberFilters) => void
  onClear: () => void
  showClear: boolean
}) {
  const [query, setQuery] = useState(filters.q)
  const [status, setStatus] = useState(filters.status)
  const [administrator, setAdministrator] = useState(filters.administrator)
  return (
    <form
      aria-label="查找成员"
      className="flex flex-wrap items-center gap-2 py-4"
      onSubmit={(event) => {
        event.preventDefault()
        onSubmit({ q: query.trim(), status, administrator })
      }}
    >
      <label className="w-full sm:max-w-sm">
        <span className="sr-only">姓名或成员 ID</span>
        <Input
          type="search"
          placeholder="搜索姓名或成员 ID…"
          value={query}
          maxLength={128}
          onChange={(event) => setQuery(event.target.value)}
        />
      </label>
      <Select
        items={memberStatusOptions}
        value={status || "all"}
        onValueChange={(value) =>
          setStatus(value === "all" ? "" : (value ?? ""))
        }
      >
        <SelectTrigger aria-label="身份状态" className="min-w-24">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            {memberStatusOptions.map(({ value, label }) => (
              <SelectItem key={value} value={value}>
                {label}
              </SelectItem>
            ))}
          </SelectGroup>
        </SelectContent>
      </Select>
      <Select
        items={memberRoleOptions}
        value={administrator || "all"}
        onValueChange={(value) =>
          setAdministrator(value === "all" ? "" : (value ?? ""))
        }
      >
        <SelectTrigger aria-label="管理权限" className="min-w-24">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            {memberRoleOptions.map(({ value, label }) => (
              <SelectItem key={value} value={value}>
                {label}
              </SelectItem>
            ))}
          </SelectGroup>
        </SelectContent>
      </Select>
      <div className="flex items-center gap-2">
        <Button type="submit" variant="outline">
          搜索
        </Button>
        {showClear && (
          <Button
            type="button"
            variant="ghost"
            disabled={
              !(
                query ||
                status ||
                administrator ||
                Object.values(filters).some(Boolean)
              )
            }
            onClick={() => {
              setQuery("")
              setStatus("")
              setAdministrator("")
              onClear()
            }}
          >
            清除筛选
          </Button>
        )}
      </div>
    </form>
  )
}

function MemberPagination({
  count,
  after,
  next,
  route,
}: {
  count: number
  after: string
  next?: string
  route: Route
}) {
  if (!count && !after) return null
  return (
    <div className="flex items-center justify-end gap-2 py-4">
      <div className="flex-1 text-sm text-muted-foreground">
        {count ? `本页 ${count} 位成员` : "没有更多成员"}
      </div>
      <Button
        variant="outline"
        size="sm"
        disabled={!after}
        onClick={() => navigate(route)}
      >
        第一页
      </Button>
      <Button
        variant="outline"
        size="sm"
        disabled={!next}
        onClick={() => next && navigate({ ...route, after: next })}
      >
        下一页
      </Button>
    </div>
  )
}

function OrganizationPagination({
  count,
  after,
  next,
  route,
}: {
  count: number
  after: string
  next?: string
  route: Route
}) {
  if (!count && !after) return null
  return (
    <div className="flex items-center justify-end gap-2 py-4">
      <div className="flex-1 text-sm text-muted-foreground">
        {count ? `本页 ${count} 个组织` : "没有更多组织"}
      </div>
      <Button
        variant="outline"
        size="sm"
        disabled={!after}
        onClick={() => navigate(route)}
      >
        第一页
      </Button>
      <Button
        variant="outline"
        size="sm"
        disabled={!next}
        onClick={() => next && navigate({ ...route, after: next })}
      >
        下一页
      </Button>
    </div>
  )
}
function ActionDialog({
  action,
  csrf,
  onClose,
  onComplete,
}: {
  action: Action
  csrf: string
  onClose: () => void
  onComplete: (id: string | undefined, submittedFrom: string) => void
}) {
  const [value, setValue] = useState(action.value ?? "")
  const [pending, setPending] = useState(false)
  const [error, setError] = useState("")
  const cancelRef = useRef<HTMLButtonElement>(null)
  const usernameField = action.field === "username"
  async function submit(e?: FormEvent<HTMLFormElement>) {
    e?.preventDefault()
    if (pending) return
    setError("")
    if (usernameField && !passwordUsernamePattern.test(value)) {
      setError(passwordUsernameError)
      return
    }
    if (
      action.field &&
      !usernameField &&
      (!value.trim() || [...value].length > 128)
    ) {
      setError("请检查填写内容。名称不能为空，最多 128 个字符。")
      return
    }
    const submittedFrom = currentLocation()
    setPending(true)
    try {
      const result = await request<{ id?: string }>(action.path, {
        method: action.method,
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrf,
        },
        body: JSON.stringify(
          action.field ? { ...action.body, [action.field]: value } : action.body
        ),
      })
      onComplete(result.id, submittedFrom)
    } catch (err) {
      setError((err as Error).message)
    } finally {
      setPending(false)
    }
  }
  if (!action.field) {
    return (
      <AlertDialog
        open
        onOpenChange={(open) => {
          if (!open && !pending) onClose()
        }}
      >
        <AlertDialogContent initialFocus={cancelRef}>
          <AlertDialogHeader>
            <AlertDialogTitle>{action.title}</AlertDialogTitle>
            {action.description && (
              <AlertDialogDescription>
                {action.description}
              </AlertDialogDescription>
            )}
          </AlertDialogHeader>
          <div className="form-feedback" role="alert">
            {error}
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel ref={cancelRef} disabled={pending}>
              取消
            </AlertDialogCancel>
            <AlertDialogAction
              variant={action.destructive ? "destructive" : "default"}
              disabled={pending}
              onClick={() => void submit()}
            >
              {pending ? "正在保存…" : action.title}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    )
  }
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open && !pending) onClose()
      }}
    >
      <DialogContent showCloseButton={!pending}>
        <DialogHeader>
          <DialogTitle>{action.title}</DialogTitle>
          {action.description && (
            <DialogDescription>{action.description}</DialogDescription>
          )}
        </DialogHeader>
        <form onSubmit={submit}>
          <FieldGroup>
            {action.field && (
              <Field data-invalid={!!error}>
                <FieldLabel htmlFor="record-name">
                  {usernameField ? "用户名" : "名称"}
                </FieldLabel>
                <Input
                  id="record-name"
                  autoFocus
                  value={value}
                  disabled={pending}
                  aria-invalid={!!error}
                  autoComplete={usernameField ? "off" : undefined}
                  autoCapitalize={usernameField ? "none" : undefined}
                  spellCheck={usernameField ? false : undefined}
                  onChange={(e) => setValue(e.target.value)}
                />
              </Field>
            )}
          </FieldGroup>
          <div className="form-feedback" role="alert">
            {error}
          </div>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              disabled={pending}
              onClick={onClose}
            >
              取消
            </Button>
            <Button
              type="submit"
              variant={action.destructive ? "destructive" : "default"}
              disabled={pending}
            >
              {pending ? "正在保存…" : "确认"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
