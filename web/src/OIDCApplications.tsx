import { useState, type FormEvent } from "react"
import { Plus } from "lucide-react"
import {
  DirectoryResults,
  DirectoryState,
  RecordIdentifier,
} from "@/components/directory"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Textarea } from "@/components/ui/textarea"

export type OIDCApplication = {
  clientId: string
  displayName: string
  organizationId?: string
  redirectUris: string[]
  postLogoutRedirectUris?: string[]
  accountReturnUris: string[] | null
  preauthorized: boolean
  subjectKind: "member" | "factor"
  evidenceScope?: string
  evidenceAudience?: string
  refresh: boolean
  enabled: boolean
  system: boolean
  revision: number
}

export type OIDCApplicationDirectory = {
  items: OIDCApplication[]
  issuer: string
  organizations: Organization[]
}

type Organization = { id: string; name: string }
type Mutation = { application: OIDCApplication; clientSecret?: string }
type Request = <T>(path: string, init?: RequestInit) => Promise<T>
type Panel =
  | { kind: "create" }
  | {
      kind: "detail" | "edit" | "rotate" | "toggle"
      application: OIDCApplication
    }
  | { kind: "secret"; application: OIDCApplication; secret: string }

const endpoint = "/api/oidc-applications"
const dialogClass = "max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-xl"

function ApplicationStatus({ application }: { application: OIDCApplication }) {
  return (
    <Badge variant={application.enabled ? "secondary" : "outline"}>
      {application.enabled ? "已启用" : "已停用"}
    </Badge>
  )
}

export function OIDCApplications({
  directory,
  csrf,
  request,
  onComplete,
}: {
  directory: OIDCApplicationDirectory
  csrf: string
  request: Request
  onComplete: (application: OIDCApplication) => void
}) {
  const { organizations } = directory
  const [panel, setPanel] = useState<Panel>()
  const [pending, setPending] = useState(false)
  const [error, setError] = useState("")
  const organizationName = (id?: string) =>
    id
      ? (organizations.find((organization) => organization.id === id)?.name ??
        id)
      : "所有组织"
  const open = (next?: Panel) => {
    setError("")
    setPanel(next)
  }
  const close = (show: boolean) => {
    if (!show && !pending) open()
  }
  const mutate = async (path: string, method: string, body: object) => {
    setPending(true)
    setError("")
    try {
      const result = await request<Mutation>(path, {
        method,
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
        body: JSON.stringify(body),
      })
      onComplete(result.application)
      open(
        result.clientSecret
          ? {
              kind: "secret",
              application: result.application,
              secret: result.clientSecret,
            }
          : { kind: "detail", application: result.application }
      )
    } catch (failure) {
      setError(
        failure instanceof Error ? failure.message : "操作失败，请重试。"
      )
    } finally {
      setPending(false)
    }
  }
  const application =
    panel && "application" in panel ? panel.application : undefined
  const applicationPath = application
    ? `${endpoint}/${encodeURIComponent(application.clientId)}`
    : endpoint
  const confirmation = panel?.kind === "rotate" || panel?.kind === "toggle"
  const rotating = panel?.kind === "rotate"
  const action = rotating
    ? "轮换密钥"
    : application?.enabled
      ? "停用应用"
      : "启用应用"

  return (
    <section aria-label="OIDC 应用列表">
      <div className="flex justify-end pb-4">
        <Button onClick={() => open({ kind: "create" })}>
          <Plus data-icon="inline-start" />
          添加 OIDC 应用
        </Button>
      </div>
      <div className="overflow-hidden rounded-md border">
        <DirectoryResults
          count={directory.items.length}
          empty={<DirectoryState kind="empty" title="尚未配置 OIDC 应用" />}
        >
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>应用名称</TableHead>
                <TableHead>客户端 ID</TableHead>
                <TableHead>允许登录的组织</TableHead>
                <TableHead>状态</TableHead>
                <TableHead className="w-0 text-right">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {directory.items.map((item) => (
                <TableRow key={item.clientId}>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        className="max-w-56 truncate text-left font-medium hover:underline"
                        title={item.displayName}
                        onClick={() =>
                          open({ kind: "detail", application: item })
                        }
                      >
                        {item.displayName}
                      </button>
                      {item.system && <Badge variant="outline">系统应用</Badge>}
                    </div>
                  </TableCell>
                  <TableCell>{item.clientId}</TableCell>
                  <TableCell>{organizationName(item.organizationId)}</TableCell>
                  <TableCell>
                    <ApplicationStatus application={item} />
                  </TableCell>
                  <TableCell className="w-0 text-right">
                    <Button
                      variant="ghost"
                      size="sm"
                      aria-label={`查看 ${item.displayName}`}
                      onClick={() =>
                        open({ kind: "detail", application: item })
                      }
                    >
                      查看
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </DirectoryResults>
      </div>
      {(panel?.kind === "create" || panel?.kind === "edit") && (
        <ApplicationForm
          key={application?.clientId ?? "create"}
          application={application}
          organizations={organizations}
          pending={pending}
          error={error}
          onClose={() =>
            open(application ? { kind: "detail", application } : undefined)
          }
          onSave={(values) =>
            mutate(applicationPath, application ? "PATCH" : "POST", {
              ...values,
              ...(application
                ? { expectedRevision: application.revision }
                : {}),
            })
          }
        />
      )}
      {panel?.kind === "detail" && (
        <Dialog open onOpenChange={close}>
          <DialogContent className={dialogClass}>
            <DialogHeader>
              <DialogTitle className="pr-8">
                {panel.application.displayName}
              </DialogTitle>
              <div className="flex gap-2">
                <ApplicationStatus application={panel.application} />
                {panel.application.system && (
                  <Badge variant="outline">系统应用</Badge>
                )}
              </div>
            </DialogHeader>
            <FieldGroup className="gap-4">
              <CopyField label="客户端 ID" value={panel.application.clientId} />
              <CopyField
                label="Discovery 地址"
                value={`${directory.issuer}/.well-known/openid-configuration`}
              />
              <div className="grid grid-cols-2 gap-4">
                <ReadField
                  label="允许登录的组织"
                  value={organizationName(panel.application.organizationId)}
                />
                <ReadField
                  label="Refresh Token"
                  value={panel.application.refresh ? "允许" : "不允许"}
                />
              </div>
              <ReadField
                label="身份类型"
                value={
                  panel.application.subjectKind === "member"
                    ? "组织成员"
                    : "认证因子"
                }
              />
              <ReadField
                label="用户授权确认"
                value={
                  panel.application.preauthorized ? "跳过确认" : "需要确认"
                }
              />
              {panel.application.evidenceScope && (
                <ReadField
                  label="身份凭据范围"
                  value={panel.application.evidenceScope}
                />
              )}
              {panel.application.evidenceAudience && (
                <CopyField
                  label="身份凭据接收方"
                  value={panel.application.evidenceAudience}
                />
              )}
              <URIFields
                label="账号绑定后返回地址"
                values={panel.application.accountReturnUris ?? []}
              />
              <URIFields
                label="登录回调地址"
                values={panel.application.redirectUris}
              />
              <URIFields
                label="退出后跳转地址"
                values={panel.application.postLogoutRedirectUris ?? []}
              />
            </FieldGroup>
            {!panel.application.system && (
              <DialogFooter className="sm:justify-between">
                <Button
                  variant={
                    panel.application.enabled ? "destructive" : "outline"
                  }
                  onClick={() =>
                    open({ kind: "toggle", application: panel.application })
                  }
                >
                  {panel.application.enabled ? "停用应用" : "启用应用"}
                </Button>
                <div className="flex flex-wrap justify-end gap-2">
                  <Button
                    variant="outline"
                    onClick={() =>
                      open({ kind: "rotate", application: panel.application })
                    }
                  >
                    轮换密钥
                  </Button>
                  <Button
                    onClick={() =>
                      open({ kind: "edit", application: panel.application })
                    }
                  >
                    编辑应用
                  </Button>
                </div>
              </DialogFooter>
            )}
          </DialogContent>
        </Dialog>
      )}
      {confirmation && application && (
        <AlertDialog open onOpenChange={close}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>{action}</AlertDialogTitle>
              <AlertDialogDescription>
                {rotating
                  ? `「${application.displayName}」的旧密钥会立即失效。生成后请更新应用服务端的配置。`
                  : application.enabled
                    ? `停用「${application.displayName}」会阻止新登录和续期，并撤销它在 MemberID 的现有授权。`
                    : `启用「${application.displayName}」后，允许登录的成员可以重新授权。`}
              </AlertDialogDescription>
            </AlertDialogHeader>
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
            <AlertDialogFooter>
              <Button
                variant="outline"
                disabled={pending}
                onClick={() => open({ kind: "detail", application })}
              >
                取消
              </Button>
              <Button
                variant={
                  rotating || application.enabled ? "destructive" : "default"
                }
                disabled={pending}
                onClick={() =>
                  rotating
                    ? mutate(`${applicationPath}/rotate-secret`, "POST", {
                        expectedRevision: application.revision,
                      })
                    : mutate(applicationPath, "PATCH", {
                        enabled: !application.enabled,
                        expectedRevision: application.revision,
                      })
                }
              >
                {pending ? "正在处理…" : action}
              </Button>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      )}
      {panel?.kind === "secret" && (
        <Dialog open onOpenChange={close}>
          <DialogContent className={dialogClass}>
            <DialogHeader>
              <DialogTitle>保存客户端密钥</DialogTitle>
              <DialogDescription>
                密钥只显示这一次。请复制并保存在应用服务端。
              </DialogDescription>
            </DialogHeader>
            <CopyField label="客户端密钥" value={panel.secret} />
            <DialogFooter>
              <Button
                onClick={() =>
                  open({ kind: "detail", application: panel.application })
                }
              >
                完成
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}
    </section>
  )
}

function CopyField({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex min-w-0 flex-col gap-1.5">
      <span className="text-sm font-medium">{label}</span>
      <RecordIdentifier label={label} value={value} />
    </div>
  )
}

function ReadField({ label, value }: { label: string; value: string }) {
  return (
    <Field>
      <FieldLabel htmlFor={`oidc-read-${label}`}>{label}</FieldLabel>
      <Input id={`oidc-read-${label}`} value={value} disabled />
    </Field>
  )
}

function URIFields({ label, values }: { label: string; values: string[] }) {
  return (
    <div className="flex min-w-0 flex-col gap-1.5">
      <span className="text-sm font-medium">{label}</span>
      {values.length ? (
        values.map((value, index) => (
          <RecordIdentifier
            key={value}
            label={values.length > 1 ? `${label} ${index + 1}` : label}
            value={value}
          />
        ))
      ) : (
        <span className="text-sm text-muted-foreground">未配置</span>
      )}
    </div>
  )
}

function ApplicationForm({
  application,
  organizations,
  pending,
  error,
  onClose,
  onSave,
}: {
  application?: OIDCApplication
  organizations: Organization[]
  pending: boolean
  error: string
  onClose: () => void
  onSave: (input: object) => void
}) {
  const [refresh, setRefresh] = useState(application?.refresh ?? false)
  const [preauthorized, setPreauthorized] = useState(
    application?.preauthorized ?? false
  )
  const [validationError, setValidationError] = useState("")
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const field = (name: string) => String(form.get(name) ?? "").trim()
    const uris = (name: string) =>
      field(name)
        .split(/\r?\n/)
        .map((value) => value.trim())
        .filter(Boolean)
    const redirectUris = uris("redirectUris")
    const postLogoutRedirectUris = uris("postLogoutRedirectUris")
    const accountReturnUris = uris("accountReturnUris")
    if (
      !redirectUris.length ||
      [...redirectUris, ...postLogoutRedirectUris, ...accountReturnUris].some(
        (value) => {
          const url = URL.parse(value)
          return (
            !url ||
            url.protocol !== "https:" ||
            Boolean(url.username || url.password) ||
            value.includes("#") ||
            value.includes("*")
          )
        }
      )
    ) {
      setValidationError(
        "请填写有效的 HTTPS 回调地址，每行一个，地址中不能包含通配符、片段或用户信息。"
      )
      return
    }
    setValidationError("")
    onSave({
      ...(!application ? { clientId: field("clientId") } : {}),
      displayName: field("displayName"),
      organizationId:
        field("organizationId") === "*" ? "" : field("organizationId"),
      redirectUris,
      postLogoutRedirectUris,
      accountReturnUris,
      preauthorized,
      refresh,
    })
  }
  const feedback = validationError || error

  return (
    <Dialog
      open
      onOpenChange={(show) => {
        if (!show && !pending) onClose()
      }}
    >
      <DialogContent className={dialogClass}>
        <DialogHeader>
          <DialogTitle>
            {application ? "编辑 OIDC 应用" : "添加 OIDC 应用"}
          </DialogTitle>
        </DialogHeader>
        <form onSubmit={submit} className="grid gap-4">
          <FieldGroup className="gap-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <Field>
                <FieldLabel htmlFor="oidc-name">应用名称</FieldLabel>
                <Input
                  id="oidc-name"
                  name="displayName"
                  defaultValue={application?.displayName}
                  maxLength={128}
                  required
                />
              </Field>
              {application ? (
                <CopyField label="客户端 ID" value={application.clientId} />
              ) : (
                <Field>
                  <FieldLabel htmlFor="oidc-client">客户端 ID</FieldLabel>
                  <Input
                    id="oidc-client"
                    name="clientId"
                    placeholder="my-app"
                    pattern="[A-Za-z0-9][A-Za-z0-9._\-]{0,127}"
                    maxLength={128}
                    required
                  />
                </Field>
              )}
            </div>
            <Field>
              <FieldLabel htmlFor="oidc-organization">
                允许登录的组织
              </FieldLabel>
              <select
                id="oidc-organization"
                name="organizationId"
                className="h-8 w-full rounded-lg border border-input bg-background px-2.5 text-sm focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
                defaultValue={
                  application ? (application.organizationId ?? "*") : ""
                }
                required
              >
                <option value="" disabled>
                  选择组织
                </option>
                {organizations.map((organization) => (
                  <option key={organization.id} value={organization.id}>
                    {organization.name}
                  </option>
                ))}
                <option value="*">所有组织</option>
              </select>
            </Field>
            <Field>
              <FieldLabel htmlFor="oidc-redirects">登录回调地址</FieldLabel>
              <Textarea
                id="oidc-redirects"
                name="redirectUris"
                rows={2}
                placeholder="https://app.example.com/auth/callback"
                defaultValue={application?.redirectUris.join("\n")}
                required
              />
            </Field>
            <Field>
              <FieldLabel htmlFor="oidc-logout">
                退出后跳转地址（可选）
              </FieldLabel>
              <Textarea
                id="oidc-logout"
                name="postLogoutRedirectUris"
                rows={2}
                placeholder="https://app.example.com/"
                defaultValue={application?.postLogoutRedirectUris?.join("\n")}
              />
            </Field>
            <Field>
              <FieldLabel htmlFor="oidc-account-return">
                账号绑定后返回地址（可选）
              </FieldLabel>
              <Textarea
                id="oidc-account-return"
                name="accountReturnUris"
                rows={2}
                defaultValue={application?.accountReturnUris?.join("\n")}
              />
            </Field>
            <Field orientation="horizontal">
              <Checkbox
                id="oidc-preauthorized"
                checked={preauthorized}
                onCheckedChange={setPreauthorized}
              />
              <FieldLabel htmlFor="oidc-preauthorized">
                跳过用户授权确认
              </FieldLabel>
            </Field>
            {preauthorized && (
              <Alert>
                <AlertDescription>
                  此应用可在用户完成认证后接收请求的身份信息，无需再次确认授权。应用明确要求确认时仍需用户确认。
                </AlertDescription>
              </Alert>
            )}
            <Field orientation="horizontal">
              <Checkbox
                id="oidc-refresh"
                checked={refresh}
                onCheckedChange={setRefresh}
              />
              <FieldLabel htmlFor="oidc-refresh">允许 Refresh Token</FieldLabel>
            </Field>
          </FieldGroup>
          <div className="form-feedback" role="status" aria-live="polite">
            {feedback && (
              <Alert variant="destructive">
                <AlertDescription>{feedback}</AlertDescription>
              </Alert>
            )}
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
            <Button type="submit" disabled={pending}>
              {pending ? "正在保存…" : application ? "保存" : "创建应用"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
