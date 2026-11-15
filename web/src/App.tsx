import { useEffect, useState } from "react"
import {
  Building2,
  Check,
  ChevronDown,
  ChevronRight,
  Fingerprint,
  History,
  KeyRound,
  Plus,
  RefreshCw,
  ShieldCheck,
  X,
  Search,
  Users,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
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
  DirectoryToolbar,
  DirectoryFooter,
  DirectoryResults,
  DirectoryState,
  RecordIdentity,
  RecordIdentifier,
  RecordTime,
  StatusBadge,
} from "@/components/directory"
import { Providers, type ProviderDirectory } from "@/Providers"
import { memberListLocation, parseRoute, routeURL, type Route } from "@/routes"
import { describeEvent, type ManagementEvent } from "@/operation-history"
import { currentLocation, Link, navigate } from "@/navigation"

type Actor = {
  memberId: string
  organizationId: string
  displayName: string
  platform: boolean
}
type Session = { actor: Actor; csrf: string }
type Organization = { id: string; name: string; status: string }
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
type Binding = { id: string; factorType: string; status: string }
const factorLabels: Partial<Record<string, string>> = {
  phone: "手机号",
  dingtalk: "钉钉",
  feishu: "飞书",
}
type Page<T> = { items: T[]; nextAfter?: string }
type Detail = {
  member: Member
  bindings: Binding[]
  administratorIds: string[]
}
type Data = {
  organizations?: Page<Organization>
  organization?: Organization
  members?: MemberPage
  detail?: Detail
  events?: ManagementEvent[]
  historyMember?: Member
  providers?: ProviderDirectory
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
  invalid_csrf: "页面验证已失效，请刷新后重试。",
  sign_in_required: "登录已过期或管理员资格已失效，请重新登录。",
  not_administrator: "当前成员没有管理权限，请使用已授权的管理员身份登录。",
  login_failed: "登录未完成，请重新发起登录。",
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
    <StatusBadge tone={active ? "positive" : "negative"}>
      {text ?? (active ? "正常" : "已停用")}
    </StatusBadge>
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
  const route = parseRoute(location)
  const params = route?.query ?? new URLSearchParams()
  const org = route?.org ?? ""
  const view = route?.view
  const events = view === "events"
  const providers = view === "providers"
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
    if (session && parseRoute(location)?.root) {
      navigate(
        session.actor.platform
          ? { view: "organization" }
          : { view: "members", org: session.actor.organizationId },
        { replace: true }
      )
    }
  }, [session, location])

  useEffect(() => {
    if (!session || !route || route.root || forbidden) return
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
        if (events) {
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
  const adminTitle = org === "org_system" ? "平台管理员" : "组织管理员"
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
          label: "组织",
          href: routeURL({ view: "organization", ...navigationScope }),
          icon: Building2,
          active: activeView === "organization",
          group: "身份管理",
        },
        {
          label: "成员",
          href: routeURL({ view: "members", ...navigationScope }),
          icon: Users,
          active: membersView,
          group: "身份管理",
        },
        {
          label: "身份提供商",
          href: routeURL({ view: "providers", ...navigationScope }),
          icon: KeyRound,
          active: providers,
          group: "身份管理",
        },
        {
          label: "操作记录",
          href: routeURL({ view: "events", ...navigationScope }),
          icon: History,
          active: events,
          group: "活动",
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
      scope={
        <>
          {actor.platform ? (
            <OrganizationSwitcher
              organizationId={org}
              name={scopeName}
              onSelect={(id) =>
                navigate({
                  view: activeView,
                  ...(id ? { org: id } : {}),
                })
              }
            />
          ) : (
            <strong title={scopeName}>{scopeName}</strong>
          )}
          {org === "org_system" && <Badge variant="outline">系统组织</Badge>}
        </>
      }
    >
      <div className="page-heading">
        <div>
          <h1>
            {events
              ? historyTarget
                ? `${data.historyMember?.displayName ?? "成员"}的操作记录`
                : "操作记录"
              : providers
                ? "身份提供商"
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
          {!membersView && !events && !providers && org && (
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
            ? "directory member-directory"
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
              events
                ? "暂时无法加载操作记录"
                : providers
                  ? "暂时无法加载身份提供商"
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
            {data.organizations && (
              <section className="directory" aria-label="组织列表">
                {providers && <DirectoryToolbar title="选择组织" />}
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
                        <TableHead>
                          <span className="sr-only">操作</span>
                        </TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {data.organizations.items.map((o) => (
                        <TableRow key={o.id}>
                          <TableCell>
                            <RecordIdentity
                              name={o.name}
                              icon={<Building2 />}
                              href={routeURL({ view: activeView, org: o.id })}
                            />
                          </TableCell>
                          <TableCell>
                            <div className="cell-status">
                              <Status active={o.status === "enabled"} />
                              {o.id === "org_system" && (
                                <Badge variant="outline">系统</Badge>
                              )}
                            </div>
                          </TableCell>
                          <TableCell className="row-actions">
                            <Button
                              variant="ghost"
                              aria-label={
                                providers
                                  ? `管理 ${o.name} 的身份提供商`
                                  : `管理 ${o.name}`
                              }
                              render={
                                <Link
                                  href={routeURL({
                                    view: activeView,
                                    org: o.id,
                                  })}
                                />
                              }
                              nativeButton={false}
                            >
                              <ChevronRight />
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </DirectoryResults>
                <Pager
                  count={data.organizations.items.length}
                  after={after}
                  next={data.organizations.nextAfter}
                  route={providers ? { view: "providers" } : {}}
                />
              </section>
            )}
            {data.providers && data.organization && (
              <Providers
                key={`${org}:${params.get("providerId") ?? ""}`}
                selectedId={params.get("providerId") ?? undefined}
                directory={data.providers}
                enabled={data.organization.status === "enabled"}
                system={org === "org_system"}
                base={base}
                csrf={session.csrf}
                save={request}
                onComplete={refresh}
              />
            )}
            {data.organization && !events && !membersView && !providers && (
              <section className="organization-summary">
                <div className="organization-identity">
                  <div className="organization-status">
                    <Status active={data.organization.status === "enabled"} />
                  </div>
                  <RecordIdentifier value={org} label="组织 ID" />
                </div>
                <div className="actions">
                  <Button
                    variant="outline"
                    onClick={() =>
                      rename(
                        "name",
                        data.organization!.name,
                        base,
                        "修改组织名称"
                      )
                    }
                  >
                    修改名称
                  </Button>
                  {actor.platform && org !== "org_system" && (
                    <Button
                      variant={
                        data.organization.status === "enabled"
                          ? "destructive"
                          : "outline"
                      }
                      onClick={() =>
                        setAction({
                          title:
                            data.organization!.status === "enabled"
                              ? "停用组织"
                              : "恢复组织",
                          description:
                            "停用后，该组织成员无法通过后续登录和身份有效性检查。已有业务系统会话由各应用管理。",
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
                    >
                      {data.organization.status === "enabled"
                        ? "停用组织"
                        : "恢复组织"}
                    </Button>
                  )}
                </div>
              </section>
            )}
            {data.members && (
              <section aria-label="成员列表">
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
                            <RecordIdentity
                              name={m.displayName}
                              icon={Array.from(m.displayName)[0] || <Users />}
                              href={routeURL({
                                view: "members",
                                org: m.organizationId,
                                member: m.id,
                              })}
                              state={{ memberList: location }}
                            />
                          </TableCell>
                          {!org && (
                            <TableCell>
                              <RecordIdentity
                                name={m.organizationName ?? "所属组织"}
                              />
                            </TableCell>
                          )}
                          <TableCell>
                            <MemberStatus member={m} />
                          </TableCell>
                          <TableCell>
                            {(m.administrator ??
                            data.members?.administratorIds?.includes(m.id)) ? (
                              <Badge variant="secondary" className="role-badge">
                                <ShieldCheck aria-hidden="true" />
                                {m.organizationId === "org_system"
                                  ? "平台管理员"
                                  : "组织管理员"}
                              </Badge>
                            ) : (
                              <span className="muted">普通成员</span>
                            )}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </DirectoryResults>
                <Pager
                  count={data.members.items.length}
                  after={after}
                  next={data.members.nextAfter}
                  route={{ ...memberDirectoryRoute, ...memberFilters }}
                />
              </section>
            )}
            {selected && data.detail && (
              <div className="detail-grid">
                <section className="detail-section">
                  <h2>成员资料</h2>
                  <dl>
                    <dt>成员 ID</dt>
                    <dd>
                      <RecordIdentifier value={selected.id} label="成员 ID" />
                    </dd>
                    <dt>身份状态</dt>
                    <dd>
                      <MemberStatus member={selected} />
                    </dd>
                    <dt>阻断原因</dt>
                    <dd>
                      {selected.blockSources
                        .map((v) => (v === "manual" ? "人工封禁" : "外部离职"))
                        .join("、") || "无"}
                    </dd>
                  </dl>
                  <div className="actions">
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
                  </div>
                </section>
                <section className="detail-section">
                  <h2>管理权限</h2>
                  <p>
                    {administrator
                      ? `此成员是${adminTitle}。`
                      : "此成员没有管理权限。"}
                  </p>
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
                </section>
                <section className="detail-section">
                  <h2>登录方式</h2>
                  {blockers.length > 0 && (
                    <div className="grid gap-2">
                      <Badge variant="destructive">当前无法登录</Badge>
                      <ul className="list-disc space-y-1 pl-5 text-sm">
                        {blockers.map((reason) => (
                          <li key={reason}>{reason}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {data.detail.bindings.length > 0 &&
                    data.detail.bindings.map((b) => (
                      <div className="binding-row" key={b.id}>
                        <strong>
                          {factorLabels[b.factorType] ?? b.factorType}
                        </strong>
                        <Status
                          active={b.status === "active"}
                          text={b.status === "active" ? "已绑定" : "已撤销"}
                        />
                      </div>
                    ))}
                </section>
                <section className="detail-section">
                  <h2>管理记录</h2>
                  <Button
                    variant="outline"
                    render={
                      <Link
                        href={routeURL({ org, view: "events", target: member })}
                        state={memberNavigationState}
                      />
                    }
                    nativeButton={false}
                  >
                    查看记录
                    <ChevronRight data-icon="inline-end" />
                  </Button>
                </section>
              </div>
            )}
            {data.events && (
              <section
                className="directory event-directory"
                aria-label="操作记录列表"
              >
                <DirectoryResults
                  count={data.events.length}
                  empty={
                    before ? undefined : (
                      <DirectoryState kind="empty" title="暂无管理操作记录" />
                    )
                  }
                >
                  <Table className="table-fixed">
                    <TableHeader>
                      <TableRow>
                        <TableHead className="event-time">时间</TableHead>
                        <TableHead className="event-wide-column">
                          操作者
                        </TableHead>
                        {!org && (
                          <TableHead className="event-wide-column">
                            组织
                          </TableHead>
                        )}
                        <TableHead>操作</TableHead>
                        <TableHead className="event-wide-column">
                          对象
                        </TableHead>
                        <TableHead className="event-wide-column">
                          变更
                        </TableHead>
                        <TableHead className="row-actions">
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
                            <TableCell className="event-wide-column">
                              <RecordIdentity name={presentation.actorName} />
                            </TableCell>
                            {!org && (
                              <TableCell className="event-wide-column">
                                <RecordIdentity
                                  name={presentation.organizationName}
                                  href={routeURL({ org: event.organizationId })}
                                />
                              </TableCell>
                            )}
                            <TableCell>
                              {presentation.action}
                              <span className="event-context">
                                {presentation.targetName}
                              </span>
                            </TableCell>
                            <TableCell className="event-wide-column">
                              <RecordIdentity
                                name={presentation.targetName}
                                href={presentation.targetURL}
                              />
                            </TableCell>
                            <TableCell className="event-wide-column">
                              <span
                                className="event-summary"
                                title={description}
                              >
                                {description}
                              </span>
                            </TableCell>
                            <TableCell className="row-actions">
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
                {(data.events.length > 0 || before) && (
                  <DirectoryFooter
                    count={data.events.length}
                    message={
                      data.events.length === 0 ? "没有更早的记录" : undefined
                    }
                  >
                    <Button
                      variant="outline"
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
                  </DirectoryFooter>
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
  onSelect,
}: {
  organizationId: string
  name: string
  onSelect: (id: string) => void
}) {
  const [open, setOpen] = useState(false)
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger
        render={
          <Button
            variant="outline"
            className="max-w-full min-w-0"
            title={name}
          />
        }
        aria-label={`切换组织，当前为${name}`}
      >
        <span className="truncate">{name}</span>
        <ChevronDown data-icon="inline-end" />
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>切换管理组织</DialogTitle>
        </DialogHeader>
        {open && (
          <OrganizationChoices
            organizationId={organizationId}
            onSelect={(id) => {
              setOpen(false)
              if (id !== organizationId) onSelect(id)
            }}
          />
        )}
      </DialogContent>
    </Dialog>
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
    <div className="grid min-w-0 gap-2">
      <Button
        variant="ghost"
        className="w-full justify-between"
        aria-current={!organizationId ? "true" : undefined}
        onClick={() => onSelect("")}
      >
        所有组织
        {!organizationId && <Check aria-hidden="true" />}
      </Button>
      <div className="grid max-h-[45dvh] min-h-20 content-start gap-1 overflow-y-auto border-y py-2">
        {page ? (
          page.items.map((organization) => (
            <Button
              key={organization.id}
              variant="ghost"
              className="min-w-0 justify-between gap-3 text-left"
              aria-current={
                organizationId === organization.id ? "true" : undefined
              }
              onClick={() => onSelect(organization.id)}
            >
              <span className="truncate" title={organization.name}>
                {organization.name}
              </span>
              {organization.status !== "enabled" && <span>已停用</span>}
              {organizationId === organization.id && (
                <Check aria-hidden="true" />
              )}
            </Button>
          ))
        ) : error ? (
          <div className="grid justify-items-start gap-2 p-2">
            <p role="status">{error}</p>
            <Button
              variant="outline"
              onClick={() => {
                setError("")
                setRetry((attempt) => attempt + 1)
              }}
            >
              重试
            </Button>
          </div>
        ) : (
          <p className="muted p-2" role="status">
            正在加载组织…
          </p>
        )}
      </div>
      <div className="flex justify-end gap-2">
        <Button
          variant="outline"
          disabled={!page || !after}
          onClick={() => goToPage("")}
        >
          第一页
        </Button>
        <Button
          variant="outline"
          disabled={!nextAfter}
          onClick={() => nextAfter && goToPage(nextAfter)}
        >
          下一页
        </Button>
      </div>
    </div>
  )
}

type MemberFilters = {
  q: string
  status: string
  administrator: string
}

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
      className="directory-filters"
      onSubmit={(event) => {
        event.preventDefault()
        onSubmit({ q: query.trim(), status, administrator })
      }}
    >
      <label className="search-field">
        <span className="sr-only">姓名或成员 ID</span>
        <Search aria-hidden="true" />
        <Input
          type="search"
          placeholder="搜索姓名或成员 ID…"
          value={query}
          maxLength={128}
          onChange={(event) => setQuery(event.target.value)}
        />
      </label>
      <label className="filter-field">
        <span className="sr-only">身份状态</span>
        <select
          className="filter-select"
          value={status}
          onChange={(event) => setStatus(event.target.value)}
        >
          <option value="">全部状态</option>
          <option value="active">未阻断</option>
          <option value="blocked">已阻断</option>
        </select>
      </label>
      <label className="filter-field">
        <span className="sr-only">管理权限</span>
        <select
          className="filter-select"
          value={administrator}
          onChange={(event) => setAdministrator(event.target.value)}
        >
          <option value="">全部成员</option>
          <option value="yes">管理员</option>
          <option value="no">普通成员</option>
        </select>
      </label>
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

function Pager({
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
  if (!count)
    return (
      <DirectoryFooter count={0} message="没有更多记录">
        <Button variant="outline" onClick={() => navigate(route)}>
          返回第一页
        </Button>
      </DirectoryFooter>
    )
  return (
    <DirectoryFooter count={count}>
      <Button
        variant="outline"
        disabled={!after}
        onClick={() => navigate(route)}
      >
        第一页
      </Button>
      <Button
        variant="outline"
        disabled={!next}
        onClick={() => next && navigate({ ...route, after: next })}
      >
        下一页
        <ChevronRight data-icon="inline-end" />
      </Button>
    </DirectoryFooter>
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
        <form
          onSubmit={async (e) => {
            e.preventDefault()
            setError("")
            if (action.field && (!value.trim() || [...value].length > 128)) {
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
                  action.field ? { [action.field]: value } : action.body
                ),
              })
              onComplete(result.id, submittedFrom)
            } catch (err) {
              setError((err as Error).message)
            } finally {
              setPending(false)
            }
          }}
        >
          <FieldGroup>
            {action.field && (
              <Field data-invalid={!!error}>
                <FieldLabel htmlFor="record-name">名称</FieldLabel>
                <Input
                  id="record-name"
                  autoFocus
                  value={value}
                  disabled={pending}
                  aria-invalid={!!error}
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
