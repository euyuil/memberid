import { useEffect, useState } from "react"
import {
  Building2,
  ChevronRight,
  Fingerprint,
  History,
  LogOut,
  Plus,
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
} from "@/components/ui/dialog"
import { Skeleton } from "@/components/ui/skeleton"
import { Separator } from "@/components/ui/separator"

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
  displayName: string
  status: string
  blockSources: string[]
}
type Binding = { id: string; factorType: string; status: string }
type Event = {
  id: number
  actor: string
  organizationId: string
  memberId: string
  action: string
  changes: object
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
  members?: Page<Member> & { administratorIds: string[] }
  detail?: Detail
  events?: Event[]
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
}
const messages: Record<string, string> = {
  forbidden: "没有操作权限，或成员尚未具备可用的登录方式。",
  last_administrator: "需要保留至少一名可用管理员，请先设置另一名管理员。",
  invalid_request: "请检查填写内容。名称不能为空，最多 128 个字符。",
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
function navigate(values: Record<string, string>) {
  window.location.hash = new URLSearchParams(values).toString()
}
function Status({ active, text }: { active: boolean; text?: string }) {
  return (
    <Badge variant={active ? "secondary" : "destructive"}>
      {text ?? (active ? "正常" : "已停用")}
    </Badge>
  )
}
function NoRecords({ text }: { text: string }) {
  return (
    <Empty>
      <EmptyHeader>
        <EmptyTitle>{text}</EmptyTitle>
        <EmptyDescription>新记录会显示在这里。</EmptyDescription>
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
  const org = params.get("org") ?? ""
  const member = params.get("member") ?? ""
  const events = params.get("view") === "events"
  const after = params.get("after") ?? ""

  useEffect(() => {
    const change = () => setLocation(window.location.hash)
    const expired = () => setSession(null)
    window.addEventListener("memberid-sign-in-required", expired)
    window.addEventListener("hashchange", change)
    request<Session>("/api/session")
      .then((s) => {
        setSession(s)
        if (
          !s.actor.platform &&
          !new URLSearchParams(window.location.hash.slice(1)).get("org")
        )
          navigate({ org: s.actor.organizationId })
      })
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
            memberId: params.get("target") ?? "",
          })
          result = {
            events: (
              await request<{ items: Event[] }>(`/api/events?${query}`, options)
            ).items,
          }
        } else if (org) {
          const organization = await request<Organization>(
            `/api/organizations/${encodeURIComponent(org)}`,
            options
          )
          result = member
            ? {
                organization,
                detail: await request<Detail>(
                  `/api/organizations/${encodeURIComponent(org)}/members/${encodeURIComponent(member)}`,
                  options
                ),
              }
            : {
                organization,
                members: await request<Data["members"]>(
                  `/api/organizations/${encodeURIComponent(org)}/members?after=${encodeURIComponent(after)}`,
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
  const selected = data.detail?.member
  const administrator =
    !!selected && !!data.detail?.administratorIds.includes(selected.id)
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
          <Button
            variant={!events ? "secondary" : "ghost"}
            onClick={() =>
              navigate(actor.platform ? {} : { org: actor.organizationId })
            }
          >
            <Building2 data-icon="inline-start" />
            {actor.platform ? "组织目录" : "我的组织"}
          </Button>
          <Button
            variant={events ? "secondary" : "ghost"}
            onClick={() =>
              navigate({ view: "events", ...(org ? { org } : {}) })
            }
          >
            <History data-icon="inline-start" />
            操作记录
          </Button>
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
          <strong>
            {data.organization?.name ??
              (org || (actor.platform ? "所有组织" : "本组织"))}
          </strong>
          {org === "org_system" && <Badge variant="outline">系统组织</Badge>}
          <span className="scope-note">
            {actor.platform ? "切换组织不会改变操作者身份" : "仅限本组织"}
          </span>
        </header>
        <div className="page-content">
          <div className="page-heading">
            <div>
              <p className="eyebrow">
                {events
                  ? "管理追溯"
                  : member
                    ? "成员身份"
                    : org
                      ? "组织工作区"
                      : "组织目录"}
              </p>
              <h1>
                {events
                  ? "操作记录"
                  : (selected?.displayName ??
                    data.organization?.name ??
                    "组织")}
              </h1>
              <p className="muted">
                {events
                  ? "查看管理变更的操作者、对象和结果。"
                  : member
                    ? "资料、登录方式与管理权限分别维护。"
                    : org
                      ? "管理本组织的独立成员身份与管理员。"
                      : "进入组织，维护成员与管理权限。"}
              </p>
            </div>
            <div className="actions">
              {actor.platform && !events && !org && (
                <Button onClick={() => create(true)}>
                  <Plus data-icon="inline-start" />
                  新建组织
                </Button>
              )}
              {org && !events && (member || actor.platform) && (
                <Button
                  variant="outline"
                  onClick={() => navigate(member ? { org } : {})}
                >
                  {member ? "返回成员列表" : "所有组织"}
                </Button>
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
                              onClick={() => navigate({ org: o.id })}
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
                              aria-label={`管理 ${o.name}`}
                              onClick={() => navigate({ org: o.id })}
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
                    org=""
                  />
                </section>
              )}
              {data.organization && !member && (
                <>
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
                  <section className="directory">
                    <div className="section-heading">
                      <h2>成员</h2>
                      <Button onClick={() => create(false)}>
                        <Plus data-icon="inline-start" />
                        新增成员
                      </Button>
                    </div>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>成员</TableHead>
                          <TableHead>身份状态</TableHead>
                          <TableHead>管理权限</TableHead>
                          <TableHead>成员 ID</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {data.members?.items.map((m) => (
                          <TableRow key={m.id}>
                            <TableCell>
                              <Button
                                variant="link"
                                onClick={() => navigate({ org, member: m.id })}
                              >
                                {m.displayName}
                              </Button>
                            </TableCell>
                            <TableCell>
                              <Status
                                active={m.status === "active"}
                                text={m.status === "active" ? "正常" : "已阻断"}
                              />
                            </TableCell>
                            <TableCell>
                              {data.members!.administratorIds.includes(m.id) ? (
                                <Badge variant="secondary">{adminTitle}</Badge>
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
                    {data.members?.items.length === 0 && (
                      <NoRecords text="还没有成员" />
                    )}
                    <Pager
                      after={after}
                      next={data.members?.nextAfter}
                      org={org}
                    />
                  </section>
                </>
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
                        <Status
                          active={selected.status === "active"}
                          text={
                            selected.status === "active" ? "正常" : "已阻断"
                          }
                        />
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
                    {data.detail.bindings.length ? (
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
                    ) : (
                      <p className="muted">
                        尚未配置登录方式。完成身份验证与绑定后，成员才能登录。
                      </p>
                    )}
                    <p className="footnote">
                      绑定、成员和组织状态共同决定能否登录。
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
                        navigate({ view: "events", org, target: member })
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
                        <TableHead>对象 / 变更</TableHead>
                        <TableHead>结果</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {data.events.map((e) => (
                        <TableRow key={e.id}>
                          <TableCell>
                            {new Date(e.createdAt).toLocaleString("zh-CN")}
                          </TableCell>
                          <TableCell>
                            <code>{e.actor}</code>
                          </TableCell>
                          <TableCell>
                            {{
                              "organization.create": "创建组织",
                              "organization.update": "修改组织",
                              "member.create": "创建成员",
                              "member.update": "修改成员",
                              "administrator.update": "管理员任免",
                              "binding.revoke": "撤销绑定",
                            }[e.action] ?? e.action}
                          </TableCell>
                          <TableCell>
                            <code>{e.memberId || e.organizationId}</code>
                            <details>
                              <summary>查看变更</summary>
                              <pre>{JSON.stringify(e.changes, null, 2)}</pre>
                            </details>
                          </TableCell>
                          <TableCell>
                            <Badge variant="secondary">成功</Badge>
                          </TableCell>
                        </TableRow>
                      ))}
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
                          view: "events",
                          org,
                          target: params.get("target") ?? "",
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
                          view: "events",
                          org,
                          target: params.get("target") ?? "",
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
          onComplete={() => {
            setAction(null)
            refresh()
          }}
        />
      )}
    </div>
  )
}

function Pager({
  after,
  next,
  org,
}: {
  after: string
  next?: string
  org: string
}) {
  return (
    <div className="pagination">
      <Button
        variant="outline"
        disabled={!after}
        onClick={() => navigate(org ? { org } : {})}
      >
        第一页
      </Button>
      <Button
        variant="outline"
        disabled={!next}
        onClick={() => navigate({ ...(org ? { org } : {}), after: next! })}
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
  onComplete: () => void
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
              setError(messages.invalid_request)
              return
            }
            setPending(true)
            try {
              await request(action.path, {
                method: action.method,
                headers: {
                  "Content-Type": "application/json",
                  "X-CSRF-Token": csrf,
                },
                body: JSON.stringify(
                  action.field ? { [action.field]: value } : action.body
                ),
              })
              onComplete()
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
