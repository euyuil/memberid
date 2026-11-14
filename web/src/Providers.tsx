import { useState, type FormEvent } from "react"
import { Plus } from "lucide-react"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
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

type Kind = "dingtalk" | "feishu"
type Provider = {
  id: string
  type: Kind
  displayName: string
  tenantId: string
  clientId: string
  enabled: boolean
  authorizationStatus: string
  revision: number
  createdAt: string
}

export type ProviderDirectory = {
  items: Provider[]
  dingTalkCallback: string
  feishuCallback: string
}

const names = { dingtalk: "钉钉", feishu: "飞书" }

export function Providers({
  directory,
  enabled,
  base,
  csrf,
  system,
  save,
  onComplete,
}: {
  directory: ProviderDirectory
  enabled: boolean
  base: string
  csrf: string
  system: boolean
  save: (path: string, init: RequestInit) => Promise<unknown>
  onComplete: () => void
}) {
  const [editing, setEditing] = useState<Provider | "new">()
  return (
    <section className="directory" aria-label="身份提供商列表">
      <div className="section-heading">
        <span className="muted">{directory.items.length} 个提供商</span>
        <Button disabled={!enabled} onClick={() => setEditing("new")}>
          <Plus data-icon="inline-start" />
          添加提供商
        </Button>
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>显示名称</TableHead>
            <TableHead>类型</TableHead>
            <TableHead>应用 ID</TableHead>
            <TableHead>状态</TableHead>
            <TableHead>创建时间</TableHead>
            <TableHead>操作</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {directory.items.map((item) => (
            <TableRow key={item.id}>
              <TableCell className="font-medium">{item.displayName}</TableCell>
              <TableCell>{names[item.type]}</TableCell>
              <TableCell>
                <code>{item.clientId}</code>
              </TableCell>
              <TableCell>
                <Badge
                  variant={
                    item.enabled && item.authorizationStatus === "active"
                      ? "secondary"
                      : "outline"
                  }
                >
                  {!item.enabled
                    ? "已停用"
                    : item.authorizationStatus === "revoked"
                      ? "已撤权"
                      : "已启用"}
                </Badge>
              </TableCell>
              <TableCell>
                {new Date(item.createdAt).toLocaleString("zh-CN")}
              </TableCell>
              <TableCell>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={!enabled}
                  aria-label={`编辑 ${item.displayName}`}
                  onClick={() => setEditing(item)}
                >
                  编辑
                </Button>
              </TableCell>
            </TableRow>
          ))}
          {directory.items.length === 0 && (
            <TableRow>
              <TableCell colSpan={6} className="muted">
                本组织尚未配置提供商。
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
      {editing && (
        <ProviderDialog
          directory={directory}
          item={editing === "new" ? undefined : editing}
          system={system}
          base={base}
          csrf={csrf}
          save={save}
          onClose={() => setEditing(undefined)}
          onComplete={() => {
            setEditing(undefined)
            onComplete()
          }}
        />
      )}
    </section>
  )
}

function ProviderDialog({
  directory,
  item,
  system,
  base,
  csrf,
  save,
  onClose,
  onComplete,
}: {
  directory: ProviderDirectory
  item?: Provider
  system: boolean
  base: string
  csrf: string
  save: (path: string, init: RequestInit) => Promise<unknown>
  onClose: () => void
  onComplete: () => void
}) {
  const [kind, setKind] = useState<Kind>(
    item?.type ?? (system ? "dingtalk" : "feishu")
  )
  const [pending, setPending] = useState(false)
  const [error, setError] = useState("")
  const callback =
    kind === "feishu" ? directory.feishuCallback : directory.dingTalkCallback
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (pending) return
    const fields = new FormData(event.currentTarget)
    setPending(true)
    setError("")
    try {
      await save(
        `${base}/providers/${kind}${item ? `/${encodeURIComponent(item.id)}` : ""}`,
        {
          method: item ? "PUT" : "POST",
          headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
          body: JSON.stringify({
            displayName: String(fields.get("displayName")).trim(),
            tenantId: item?.tenantId ?? String(fields.get("tenantId")).trim(),
            clientId: item?.clientId ?? String(fields.get("clientId")).trim(),
            clientSecret: fields.get("clientSecret"),
            enabled: fields.has("enabled"),
            expectedRevision: item?.revision ?? 0,
          }),
        }
      )
      onComplete()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setPending(false)
    }
  }
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open && !pending) onClose()
      }}
    >
      <DialogContent className="flex max-h-[calc(100dvh-2rem)] flex-col sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>
            {item ? "编辑身份提供商" : "添加身份提供商"}
          </DialogTitle>
          <DialogDescription>
            将以下回调地址登记到对应应用的 OAuth 设置。
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="flex min-h-0 flex-col">
          <div className="min-h-0 overflow-y-auto px-1 py-1">
            <FieldGroup className="gap-3">
              <Field>
                <FieldLabel htmlFor="provider-type">类型</FieldLabel>
                <select
                  id="provider-type"
                  value={kind}
                  disabled={pending || !!item || system}
                  className="h-9 rounded-md border border-input bg-background px-2 text-sm"
                  onChange={(event) => setKind(event.target.value as Kind)}
                >
                  {!system && <option value="feishu">飞书</option>}
                  <option value="dingtalk">钉钉</option>
                </select>
              </Field>
              <Field>
                <FieldLabel htmlFor="provider-name">登录页显示名称</FieldLabel>
                <Input
                  id="provider-name"
                  name="displayName"
                  defaultValue={item?.displayName}
                  maxLength={128}
                  required
                  readOnly={pending}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="provider-tenant">
                  {kind === "feishu"
                    ? "飞书租户标识（Tenant Key）"
                    : "钉钉组织标识（Corp ID）"}
                </FieldLabel>
                <Input
                  id="provider-tenant"
                  name="tenantId"
                  defaultValue={item?.tenantId}
                  maxLength={256}
                  required
                  readOnly={pending || !!item}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="provider-app">应用 ID</FieldLabel>
                <Input
                  id="provider-app"
                  name="clientId"
                  defaultValue={item?.clientId}
                  maxLength={256}
                  required
                  readOnly={pending || !!item}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="provider-secret">应用密钥</FieldLabel>
                <Input
                  id="provider-secret"
                  name="clientSecret"
                  type="password"
                  autoComplete="new-password"
                  placeholder={item ? "留空则保留现有密钥" : undefined}
                  maxLength={4096}
                  required={!item}
                  readOnly={pending}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="provider-callback">
                  OAuth 回调地址
                </FieldLabel>
                <Input id="provider-callback" value={callback} readOnly />
              </Field>
              <label className="flex items-center gap-2 text-sm">
                <input
                  name="enabled"
                  type="checkbox"
                  defaultChecked={item?.enabled ?? true}
                  disabled={pending}
                />
                允许使用此应用登录
              </label>
            </FieldGroup>
            <div className="form-feedback" role="status" aria-live="polite">
              {error && (
                <Alert variant="destructive">
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}
            </div>
          </div>
          <DialogFooter className="shrink-0">
            <Button
              variant="outline"
              type="button"
              disabled={pending}
              onClick={onClose}
            >
              取消
            </Button>
            <Button type="submit" disabled={pending}>
              {pending ? "正在保存…" : "保存"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
