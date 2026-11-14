import { useEffect, useState } from "react"
import {
  Building2,
  Check,
  ChevronDown,
  ChevronRight,
  Fingerprint,
  History,
  KeyRound,
  LogOut,
  Plus,
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
import {
  Empty,
  EmptyHeader,
  EmptyTitle,
  EmptyDescription,
} from "@/components/ui/empty"
import {
  Field,
  FieldGroup,
  FieldLabel,
  FieldDescription,
} from "@/components/ui/field"
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
import { Separator } from "@/components/ui/separator"
import { Providers, type ProviderDirectory } from "@/Providers"

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
type Event = {
  id: number
  actor: string
  organizationId: string
  memberId: string
  action: string
  changes: Record<string, unknown>
  createdAt: string
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
  events?: Event[]
  historyMember?: Member
  providers?: ProviderDirectory
}
type Action = {
  title: string
  description: string
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
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { credentials: "same-origin", ...init })
  const body = await response.json()
  if (response.status === 401) window.dispatchEvent(new Event("memberid-sign-in-required"))
  if (!response.ok)
    throw new Error(messages[body.error] ?? "请求未完成，请稍后重试。")
  return body as T
}
function routeHash(values: Record<string, string>) {
  return `#${new URLSearchParams(values)}`
}
function navigate(values: Record<string, string>) {
  window.location.hash = routeHash(values)
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

const eventLabels: Record<string, string> = {
  "organization.create": "创建组织",
  "organization.update": "修改组织",
  "member.create": "创建成员",
  "member.update": "修改成员",
  "administrator.update": "管理员任免",
  "binding.revoke": "撤销绑定",
  "dingtalk.admission": "设置钉钉准入",
  "provider.configure": "配置身份提供商",
}

function operationSummary({ action, changes }: Event) {
  const details: string[] = []
  if (
    (action === "organization.create" || action === "organization.update") &&
    typeof changes.name === "string"
  ) {
    details.push(`组织名称设为「${changes.name}」`)
  }
  if (action === "organization.update") {
    if (changes.status === "enabled") details.push("恢复组织")
    if (changes.status === "disabled") details.push("停用组织")
  }
  if (
    (action === "member.create" || action === "member.update") &&
    typeof changes.displayName === "string"
  ) {
    details.push(`成员名称设为「${changes.displayName}」`)
  }
  if (action === "member.update" && typeof changes.manualBlocked === "boolean") {
    details.push(changes.manualBlocked ? "人工封禁" : "解除人工封禁")
  }
  if (action === "administrator.update" && typeof changes.enabled === "boolean") {
    details.push(changes.enabled ? "授予管理员权限" : "撤销管理员权限")
  }
  if (action === "dingtalk.admission" && typeof changes.enabled === "boolean") {
    details.push(changes.enabled ? "设置钉钉准入" : "取消钉钉准入")
  }
  if (action === "provider.configure" && typeof changes.displayName === "string") {
    details.push(`「${changes.displayName}」${changes.enabled ? "已启用" : "已停用"}`)
  }
  return details
}

function NoRecords({
  text,
  description = "新记录会显示在这里。",
}: {
  text: string
  description?: string
}) {
  return (
    <Empty>
      <EmptyHeader>
        <EmptyTitle>{text}</EmptyTitle>
        <EmptyDescription>{description}</EmptyDescription>
      </EmptyHeader>
    </Empty>
  )
}

export default function App() {
  const [session, setSession] = useState<Session | null>()
  const [location, setLocation] = useState(window.location.hash)
  const [revision, setRevision] = useState(0)
  const [data, setData] = useState<Data>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const [action, setAction] = useState<Action | null>(null)
  const params = new URLSearchParams(location.slice(1))
  const actorOrganization =
    session && !session.actor.platform ? session.actor.organizationId : ""
  const org = params.get("org") || actorOrganization
  const view = params.get("view")
  const events = view === "events"
  const providers = view === "providers"
  // Organization links without a view previously opened the member directory.
  const membersView =
    !events &&
    !providers &&
    (view === "members" || (view !== "organization" && !!org))
  const activeView = events
    ? "events"
    : providers
      ? "providers"
      : membersView
        ? "members"
        : "organization"
  const member = membersView && org ? (params.get("member") ?? "") : ""
  const historyTarget = params.get("target") ?? ""
  const after = params.get("after") ?? ""
  const memberFilters = {
    q: params.get("q") ?? "",
    status: params.get("status") ?? "",
    administrator: params.get("administrator") ?? "",
  }
  const scopeRoute: Record<string, string> = org ? { org } : {}
  const memberDirectoryRoute = { view: "members", ...scopeRoute }
  const memberListState = {
    ...memberFilters,
    ...(after ? { after } : {}),
  }
  const fromAllOrganizations = params.get("from") === "all"
  const memberListRoute = {
    ...memberDirectoryRoute,
    ...memberListState,
    ...(fromAllOrganizations ? { from: "all" } : {}),
  }
  const memberReturnRoute = fromAllOrganizations
    ? { view: "members", ...memberListState }
    : memberListRoute
  const memberQuery = new URLSearchParams({ ...memberFilters, after })
  const memberSearchActive = Object.values(memberFilters).some(Boolean)

  useEffect(() => {
    const change = () => {
      setAction(null)
      setData({})
      setLoading(true)
      setError("")
      setLocation(window.location.hash)
    }
    const expired = () => setSession(null)
    window.addEventListener("memberid-sign-in-required", expired)
    window.addEventListener("hashchange", change)
    request<Session>("/api/session")
      .then(setSession)
      .catch(() => setSession(null))
    return () => {
      window.removeEventListener("hashchange", change)
      window.removeEventListener("memberid-sign-in-required", expired)
    }
  }, [])

  useEffect(() => {
    if (!session) return
    const abort = new AbortController()
    async function load() {
      setLoading(true)
      setError("")
      setData({})
      const options = { signal: abort.signal }
      try {
        let result: Data
        if (events) {
          const query = new URLSearchParams({
            organizationId: org,
            before: params.get("before") ?? "",
            memberId: historyTarget,
          })
          const [history, organization, memberDetail] = await Promise.all([
            request<{ items: Event[] }>(`/api/events?${query}`, options),
            org
              ? request<Organization>(
                  `/api/organizations/${encodeURIComponent(org)}`,
                  options
                )
              : undefined,
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
          const organization = await request<Organization>(
            `/api/organizations/${encodeURIComponent(org)}`,
            options
          )
          result = { organization }
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
            members: await request<MemberPage>(`/api/members?${memberQuery}`, options),
          }
        } else
          result = {
            organizations: await request<Page<Organization>>(
              `/api/organizations?after=${encodeURIComponent(after)}`,
              options
            ),
          }
        if (!abort.signal.aborted) setData(result)
      } catch (e) {
        if (!abort.signal.aborted) setError((e as Error).message)
      } finally {
        if (!abort.signal.aborted) setLoading(false)
      }
    }
    void load()
    return () => abort.abort()
    // Route parameters are represented by location; successful mutations bump revision.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session, location, revision])

  if (session === undefined)
    return (
      <main className="login-page">
        <Skeleton className="h-12 w-64" />
        <p>正在检查登录状态…</p>
      </main>
    )
  if (!session) {
    const code = new URLSearchParams(window.location.search).get("error") ?? ""
    return (
      <main className="login-page">
        <div className="identity-mark">
          <Fingerprint />
        </div>
        <p className="eyebrow">MemberID · 管理控制台</p>
        <h1>管理组织，明确每个身份。</h1>
        <p className="muted">
          平台管理员与组织管理员使用同一个入口。
          <br />
          登录后，仅显示当前身份有权管理的内容。
        </p>
        <Button
          size="lg"
          render={<a href="/auth/login" />}
          nativeButton={false}
        >
          使用 MemberID 登录
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
        <p className="footnote">需要已有的管理员授权才能进入控制台。</p>
      </main>
    )
  }

  const actor = session.actor
  const base = `/api/organizations/${encodeURIComponent(org)}`
  const scopeName = org ? (data.organization?.name ?? org) : "所有组织"
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
      description: "修改名称不会改变身份 ID 或已有的登录绑定。",
      field,
      value,
      path,
      method: "PATCH",
      body: {},
    })
  const refresh = () => setRevision((v) => v + 1)
  const create = (isOrganization: boolean) =>
    setAction({
      title: isOrganization ? "新建组织" : "新增成员",
      description: isOrganization
        ? "创建普通组织，随后指定首位组织管理员。"
        : "创建成员记录。登录方式需通过现有身份验证与绑定流程配置。",
      path: isOrganization ? "/api/organizations" : `${base}/members`,
      method: "POST",
      body: {},
      field: isOrganization ? "name" : "displayName",
      openCreated: (id) =>
        navigate(
          isOrganization
            ? { view: "organization", org: id }
            : { ...memberListRoute, member: id }
        ),
    })

  return (
    <div className="console-shell">
      <aside className="sidebar">
        <a className="brand" href="#">
          <Fingerprint />
          <span>
            MemberID<small>管理控制台</small>
          </span>
        </a>
        <nav aria-label="主导航">
          <div className="nav-group" role="group" aria-labelledby="nav-identity">
            <span id="nav-identity">身份管理</span>
            <Button
              variant={!membersView && !events && !providers ? "secondary" : "ghost"}
              render={<a href={routeHash({ view: "organization", ...scopeRoute })} />}
              nativeButton={false}
              aria-current={!membersView && !events && !providers ? "page" : undefined}
            >
              <Building2 data-icon="inline-start" />
              组织
            </Button>
            <Button
              variant={membersView ? "secondary" : "ghost"}
              render={<a href={routeHash(memberDirectoryRoute)} />}
              nativeButton={false}
              aria-current={membersView ? "page" : undefined}
            >
              <Users data-icon="inline-start" />
              成员
            </Button>
            <Button
              variant={providers ? "secondary" : "ghost"}
              render={<a href={routeHash({ view: "providers", ...scopeRoute })} />}
              nativeButton={false}
              aria-current={providers ? "page" : undefined}
            >
              <KeyRound data-icon="inline-start" />
              身份提供商
            </Button>
          </div>
          <div className="nav-group" role="group" aria-labelledby="nav-audit">
            <span id="nav-audit">审计</span>
            <Button
              variant={events ? "secondary" : "ghost"}
              render={<a href={routeHash({ view: "events", ...scopeRoute })} />}
              nativeButton={false}
              aria-current={events ? "page" : undefined}
            >
              <History data-icon="inline-start" />
              操作记录
            </Button>
          </div>
        </nav>
        <div className="actor-panel">
          <Separator />
          <p className="eyebrow">当前操作者</p>
          <strong>{actor.displayName}</strong>
          <Badge variant="outline">
            {actor.platform ? "平台管理员" : "组织管理员"}
          </Badge>
          <code>{actor.memberId}</code>
          <Button
            variant="ghost"
            onClick={async () => {
              try {
                await request("/api/logout", {
                  method: "POST",
                  headers: { "X-CSRF-Token": session.csrf },
                })
                setSession(null)
                window.history.replaceState(null, "", "/")
              } catch (e) {
                setError((e as Error).message)
              }
            }}
          >
            <LogOut data-icon="inline-start" />
            退出后台
          </Button>
        </div>
      </aside>
      <main className="workspace">
        <header className="scope-bar">
          <span>管理范围</span>
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
            <strong>{data.organization?.name ?? (org || "本组织")}</strong>
          )}
          {org === "org_system" && <Badge variant="outline">系统组织</Badge>}
          <span className="scope-note">
            {actor.platform ? "切换组织不会改变操作者身份" : "仅限本组织"}
          </span>
        </header>
        <div className="page-content">
          <div className="page-heading">
            <div>
              <h1>
                {events
                  ? "操作记录"
                  : providers
                    ? "身份提供商"
                    : membersView
                      ? (member ? selected?.displayName ?? "成员详情" : "成员")
                      : (data.organization?.name ?? "组织")}
              </h1>
              {events && (
                <p className="muted">
                  {historyTarget
                    ? `仅查看成员 ${data.historyMember?.displayName ?? historyTarget} 的操作记录。`
                    : "查看已完成的管理操作及其变更内容。"}
                </p>
              )}
              {providers && !org && (
                <p className="muted">选择组织后管理登录提供商。</p>
              )}
            </div>
            <div className="actions">
              {events && org && historyTarget && (
                <>
                  {data.historyMember && (
                    <Button
                      variant="outline"
                      onClick={() => navigate({ ...memberListRoute, member: historyTarget })}
                    >
                      返回成员详情
                    </Button>
                  )}
                  <Button
                    variant="outline"
                    onClick={() => navigate({ view: "events", org })}
                  >
                    查看本组织记录
                  </Button>
                </>
              )}
              {actor.platform && !events && !membersView && !providers && !org && (
                <Button onClick={() => create(true)}>
                  <Plus data-icon="inline-start" />
                  新建组织
                </Button>
              )}
              {member && (
                <Button variant="outline" onClick={() => navigate(memberReturnRoute)}>
                  {fromAllOrganizations ? "返回所有组织的成员" : "返回成员列表"}
                </Button>
              )}
              {membersView && !member && data.organization && (
                <Button onClick={() => create(false)}>
                  <Plus data-icon="inline-start" />
                  新增成员
                </Button>
              )}
              {!membersView && !events && !providers && org && (
                <>
                  {actor.platform && (
                    <Button variant="outline" onClick={() => navigate({})}>
                      所有组织
                    </Button>
                  )}
                  {data.organization && (
                    <Button onClick={() => navigate(memberDirectoryRoute)}>
                      查看成员
                    </Button>
                  )}
                </>
              )}
            </div>
          </div>
          <div className="feedback" role="status" aria-live="polite">
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
          </div>
          {membersView && !member && (actor.platform || org === actor.organizationId) && (
            <MemberSearch
              key={`${org}:${JSON.stringify(memberFilters)}`}
              filters={memberFilters}
              onSubmit={(filters) => navigate({ ...memberDirectoryRoute, ...filters })}
              onClear={() => navigate(memberDirectoryRoute)}
            />
          )}
          {loading ? (
            <div className="flex flex-col gap-4">
              <Skeleton className="h-12 w-full" />
              <Skeleton className="h-64 w-full" />
            </div>
          ) : (
            <>
              {data.organizations && (
                <section className="directory">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>组织</TableHead>
                        <TableHead>状态</TableHead>
                        <TableHead>组织 ID</TableHead>
                        <TableHead>
                          <span className="sr-only">操作</span>
                        </TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {data.organizations.items.map((o) => (
                        <TableRow key={o.id}>
                          <TableCell>
                            <Button
                              variant="link"
                              onClick={() =>
                                navigate({ view: activeView, org: o.id })
                              }
                            >
                              {o.name}
                            </Button>
                            {o.id === "org_system" && (
                              <Badge variant="outline">系统</Badge>
                            )}
                          </TableCell>
                          <TableCell>
                            <Status active={o.status === "enabled"} />
                          </TableCell>
                          <TableCell>
                            <code>{o.id}</code>
                          </TableCell>
                          <TableCell>
                            <Button
                              variant="ghost"
                              aria-label={providers ? `管理 ${o.name} 的身份提供商` : `管理 ${o.name}`}
                              onClick={() =>
                                navigate({ view: activeView, org: o.id })
                              }
                            >
                              <ChevronRight />
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                  <Pager
                    after={after}
                    next={data.organizations.nextAfter}
                    route={providers ? { view: "providers" } : {}}
                  />
                </section>
              )}
              {data.providers && data.organization && (
                <Providers
                  key={org}
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
                  <div>
                    <Status active={data.organization.status === "enabled"} />
                    <code>{org}</code>
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
                            destructive:
                              data.organization!.status === "enabled",
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
                <section className="directory">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>成员</TableHead>
                        {!org && <TableHead>所属组织</TableHead>}
                        <TableHead>身份状态</TableHead>
                        <TableHead>管理权限</TableHead>
                        <TableHead>成员 ID</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {data.members.items.map((m) => (
                        <TableRow key={m.id}>
                          <TableCell>
                            <Button
                              variant="link"
                              onClick={() =>
                                navigate({
                                  ...memberListRoute,
                                  org: m.organizationId,
                                  member: m.id,
                                  ...(!org ? { from: "all" } : {}),
                                })
                              }
                            >
                              {m.displayName}
                            </Button>
                          </TableCell>
                          {!org && (
                            <TableCell>
                              <div>{m.organizationName}</div>
                              <code>{m.organizationId}</code>
                            </TableCell>
                          )}
                          <TableCell>
                            <MemberStatus member={m} />
                          </TableCell>
                          <TableCell>
                            {(m.administrator ?? data.members?.administratorIds?.includes(m.id)) ? (
                              <Badge variant="secondary">
                                {m.organizationId === "org_system" ? "平台管理员" : "组织管理员"}
                              </Badge>
                            ) : (
                              <span className="muted">普通成员</span>
                            )}
                          </TableCell>
                          <TableCell>
                            <code>{m.id}</code>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                  {data.members.items.length === 0 && (
                    <NoRecords
                      text={memberSearchActive ? "没有符合条件的成员" : "还没有成员"}
                      description={
                        memberSearchActive
                          ? "修改搜索条件或清除筛选后再试。"
                          : undefined
                      }
                    />
                  )}
                  <Pager
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
                        <code>{selected.id}</code>
                      </dd>
                      <dt>身份状态</dt>
                      <dd>
                        <MemberStatus member={selected} />
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
                    <p className="muted">
                      {org === "org_system"
                        ? "平台管理员可以管理整套实例的组织与成员。"
                        : "组织管理员可以管理本组织成员，并任免本组织管理员。"}
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
                          {blockers.map((reason) => <li key={reason}>{reason}</li>)}
                        </ul>
                      </div>
                    )}
                    {data.detail.bindings.length > 0 && (
                      data.detail.bindings.map((b) => (
                        <div className="binding-row" key={b.id}>
                          <strong>
                            {b.factorType === "phone" ? "手机号" : "钉钉"}
                          </strong>
                          <Status
                            active={b.status === "active"}
                            text={b.status === "active" ? "已绑定" : "已撤销"}
                          />
                        </div>
                      ))
                    )}
                    <p className="footnote">
                      {data.detail.bindings.length === 0
                        ? "请按本组织的身份验证与绑定流程配置登录方式。"
                        : "登录时还会检查验证因子及提供方当前状态。"}
                    </p>
                  </section>
                  <section className="detail-section">
                    <h2>管理记录</h2>
                    <p className="muted">
                      查看此成员的资料、状态和管理员权限变更。
                    </p>
                    <Button
                      variant="outline"
                      onClick={() =>
                        navigate({ ...memberListRoute, view: "events", target: member })
                      }
                    >
                      查看记录
                      <ChevronRight data-icon="inline-end" />
                    </Button>
                  </section>
                </div>
              )}
              {data.events && (
                <section className="directory">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>时间</TableHead>
                        <TableHead>操作者</TableHead>
                        <TableHead>操作</TableHead>
                        <TableHead>对象</TableHead>
                        <TableHead>变更</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {data.events.map((event) => {
                        const summary = operationSummary(event)
                        const targetName = event.memberId
                          ? event.memberId === data.historyMember?.id
                            ? data.historyMember.displayName
                            : undefined
                          : event.organizationId === data.organization?.id
                            ? data.organization.name
                            : undefined
                        const installationActor =
                          event.actor === "installation-operator"
                            ? "安装运维"
                            : event.actor === "installation-manager"
                              ? "集成管理服务"
                              : undefined
                        const currentActor = event.actor === actor.memberId
                        return (
                          <TableRow key={event.id}>
                            <TableCell>
                              {new Date(event.createdAt).toLocaleString("zh-CN")}
                            </TableCell>
                            <TableCell>
                              {installationActor ? (
                                installationActor
                              ) : (
                                <>
                                  {currentActor && <div>{actor.displayName}（当前操作者）</div>}
                                  <code>{event.actor}</code>
                                </>
                              )}
                            </TableCell>
                            <TableCell>
                              {eventLabels[event.action] ?? event.action}
                            </TableCell>
                            <TableCell>
                              {targetName && <div>{targetName}</div>}
                              <code>{event.memberId || event.organizationId}</code>
                              {!org && event.memberId && (
                                <div>
                                  <code>{event.organizationId}</code>
                                </div>
                              )}
                            </TableCell>
                            <TableCell className="min-w-40 whitespace-normal">
                              {summary.map((line) => (
                                <p key={line} className="wrap-anywhere">{line}</p>
                              ))}
                              <details>
                                <summary>原始变更</summary>
                                <pre>{JSON.stringify(event.changes, null, 2)}</pre>
                              </details>
                            </TableCell>
                          </TableRow>
                        )
                      })}
                    </TableBody>
                  </Table>
                  {data.events.length === 0 && (
                    <NoRecords text="暂无管理操作记录" />
                  )}
                  <div className="pagination">
                    <Button
                      variant="outline"
                      disabled={!params.get("before")}
                      onClick={() =>
                        navigate({
                          ...memberListRoute,
                          view: "events",
                          target: historyTarget,
                        })
                      }
                    >
                      最新记录
                    </Button>
                    <Button
                      variant="outline"
                      disabled={data.events.length < 50}
                      onClick={() =>
                        navigate({
                          ...memberListRoute,
                          view: "events",
                          target: historyTarget,
                          before: String(data.events!.at(-1)!.id),
                        })
                      }
                    >
                      更早记录
                    </Button>
                  </div>
                </section>
              )}
            </>
          )}
          <footer className="page-footer">
            MemberID · 独立的组织成员身份
            <Button variant="ghost" onClick={refresh}>
              刷新
            </Button>
          </footer>
        </div>
      </main>
      {action && (
        <ActionDialog
          key={`${action.path}:${action.title}`}
          action={action}
          csrf={session.csrf}
          onClose={() => setAction(null)}
          onComplete={(id, submittedFrom) => {
            if (window.location.hash !== submittedFrom) {
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
    </div>
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
        render={<Button variant="outline" className="max-w-full min-w-0" />}
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
      <div className="grid min-h-20 max-h-[45dvh] content-start gap-1 overflow-y-auto border-y py-2">
        {page ? (
          page.items.map((organization) => (
            <Button
              key={organization.id}
              variant="ghost"
              className="h-auto min-w-0 justify-between gap-3 py-2 text-left"
              aria-current={
                organizationId === organization.id ? "true" : undefined
              }
              onClick={() => onSelect(organization.id)}
            >
              <span className="grid min-w-0 gap-1">
                <span className="whitespace-normal wrap-anywhere">
                  {organization.name}
                  {organization.status !== "enabled" && "（已停用）"}
                </span>
                <code>{organization.id}</code>
              </span>
              {organizationId === organization.id && <Check aria-hidden="true" />}
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
}: {
  filters: MemberFilters
  onSubmit: (filters: MemberFilters) => void
  onClear: () => void
}) {
  const [query, setQuery] = useState(filters.q)
  const [status, setStatus] = useState(filters.status)
  const [administrator, setAdministrator] = useState(filters.administrator)
  return (
    <form
      aria-label="查找成员"
      className="mb-4 flex flex-wrap items-end gap-3 rounded-lg border p-4"
      onSubmit={(event) => {
        event.preventDefault()
        onSubmit({ q: query.trim(), status, administrator })
      }}
    >
      <label className="grid w-full max-w-72 gap-1 text-xs">
        姓名或成员 ID
        <Input
          type="search"
          placeholder="输入姓名或成员 ID"
          value={query}
          maxLength={128}
          onChange={(event) => setQuery(event.target.value)}
        />
      </label>
      <label className="grid gap-1 text-xs">
        身份状态
        <select
          className="h-8 rounded-lg border bg-background px-2 text-sm"
          value={status}
          onChange={(event) => setStatus(event.target.value)}
        >
          <option value="">全部状态</option>
          <option value="active">未阻断</option>
          <option value="blocked">已阻断</option>
        </select>
      </label>
      <label className="grid gap-1 text-xs">
        管理权限
        <select
          className="h-8 rounded-lg border bg-background px-2 text-sm"
          value={administrator}
          onChange={(event) => setAdministrator(event.target.value)}
        >
          <option value="">全部成员</option>
          <option value="yes">管理员</option>
          <option value="no">普通成员</option>
        </select>
      </label>
      <Button type="submit" variant="outline">
        <Search data-icon="inline-start" />
        搜索
      </Button>
      {(query || status || administrator || Object.values(filters).some(Boolean)) && (
        <Button
          type="button"
          variant="ghost"
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
    </form>
  )
}

function Pager({
  after,
  next,
  route,
}: {
  after: string
  next?: string
  route: Record<string, string>
}) {
  return (
    <div className="pagination">
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
          <DialogDescription>{action.description}</DialogDescription>
        </DialogHeader>
        <form
          onSubmit={async (e) => {
            e.preventDefault()
            setError("")
            if (action.field && (!value.trim() || [...value].length > 128)) {
              setError("请检查填写内容。名称不能为空，最多 128 个字符。")
              return
            }
            const submittedFrom = window.location.hash
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
                <FieldDescription>最多 128 个字符。</FieldDescription>
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
