import { useState, type FormEvent } from "react"
import { SAMLIdentityProvider } from "@/SAMLIdentityProvider"
import { Plus } from "lucide-react"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogDescription,
  AlertDialogFooter,
} from "@/components/ui/alert-dialog"
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  DirectoryResults,
  DirectoryState,
  RecordIdentifier,
} from "@/components/directory"
import { Link } from "@/navigation"
import { routeURL } from "@/routes"
import {
  registrationInput,
  signingCertificates,
  type SAMLDirectory,
  type SAMLServiceProvider,
} from "@/saml-service-providers"

type Save = (path: string, init: RequestInit) => Promise<unknown>
const name = (item: SAMLServiceProvider) => item.displayName || item.id
const status = (item: SAMLServiceProvider) =>
  item.retired ? "已退役" : item.enabled ? "已启用" : "已停用"

export function SAMLServiceProviders({
  directory,
  selected,
  organizationId,
  after,
  csrf,
  save,
  onComplete,
}: {
  directory: SAMLDirectory
  selected?: SAMLServiceProvider
  organizationId: string
  after: string
  csrf: string
  save: Save
  onComplete: () => void
}) {
  const [integration, setIntegration] = useState(false)
  const [editing, setEditing] = useState<SAMLServiceProvider | "new">()
  const [viewing, setViewing] = useState(selected)
  const [retiring, setRetiring] = useState<SAMLServiceProvider>()
  const base = `/api/organizations/${encodeURIComponent(organizationId)}/saml-service-providers`
  const finish = () => {
    setEditing(undefined)
    setViewing(undefined)
    setRetiring(undefined)
    onComplete()
  }
  return (
    <section aria-label="SAML 应用列表">
      {integration && (
        <SAMLIdentityProvider
          organizationId={organizationId}
          request={save}
          onClose={() => setIntegration(false)}
        />
      )}
      <div className="flex justify-end gap-2 pb-4">
        <Button variant="outline" onClick={() => setIntegration(true)}>
          接入信息
        </Button>
        <Button onClick={() => setEditing("new")}>
          <Plus data-icon="inline-start" />
          添加 SAML 应用
        </Button>
      </div>
      <div className="overflow-hidden rounded-md border">
        <DirectoryResults
          count={directory.items.length}
          empty={
            <DirectoryState
              kind="empty"
              title={after ? "此页没有 SAML 应用" : "尚未配置 SAML 应用"}
            />
          }
        >
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>应用名称</TableHead>
                <TableHead>ACS 地址</TableHead>
                <TableHead>状态</TableHead>
                <TableHead>请求签名</TableHead>
                <TableHead className="w-0 text-right">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {directory.items.map((item) => (
                <TableRow key={item.id}>
                  <TableCell>
                    <button
                      type="button"
                      className="block max-w-64 truncate text-left font-medium hover:underline"
                      title={name(item)}
                      onClick={() => setViewing(item)}
                    >
                      {name(item)}
                    </button>
                  </TableCell>
                  <TableCell>
                    <span
                      className="block max-w-64 truncate"
                      title={item.acsUrl}
                    >
                      {item.acsUrl}
                    </span>
                  </TableCell>
                  <TableCell>
                    <Badge variant={item.enabled ? "secondary" : "outline"}>
                      {status(item)}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {item.allowUnsignedRequests ? "允许未签名" : "必须签名"}
                  </TableCell>
                  <TableCell className="w-0 text-right">
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={item.retired}
                      aria-label={`编辑 ${name(item)}`}
                      onClick={() => setEditing(item)}
                    >
                      编辑
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </DirectoryResults>
      </div>
      <div className="flex items-center justify-between gap-3 py-4">
        <span className="text-sm text-muted-foreground">
          本页 {directory.items.length} 个应用
        </span>
        <div className="flex gap-2">
          {after && (
            <Button
              variant="outline"
              render={
                <Link
                  href={routeURL({
                    view: "saml-service-providers",
                    org: organizationId,
                  })}
                />
              }
              nativeButton={false}
            >
              返回首页
            </Button>
          )}
          {directory.nextAfter && (
            <Button
              variant="outline"
              render={
                <Link
                  href={routeURL({
                    view: "saml-service-providers",
                    org: organizationId,
                    after: directory.nextAfter,
                  })}
                />
              }
              nativeButton={false}
            >
              下一页
            </Button>
          )}
        </div>
      </div>
      {viewing && (
        <Dialog
          open
          onOpenChange={(open) => {
            if (!open) setViewing(undefined)
          }}
        >
          <DialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-xl">
            <DialogHeader>
              <DialogTitle>{name(viewing)}</DialogTitle>
            </DialogHeader>
            <dl>
              <dt>状态</dt>
              <dd>{status(viewing)}</dd>
              <dt>应用 ID</dt>
              <dd>
                <RecordIdentifier value={viewing.id} label="应用 ID" />
              </dd>
              <dt>Entity ID</dt>
              <dd>
                <RecordIdentifier value={viewing.entityId} label="Entity ID" />
              </dd>
              <dt>ACS 地址</dt>
              <dd>
                <RecordIdentifier value={viewing.acsUrl} label="ACS 地址" />
              </dd>
              <dt>协议绑定</dt>
              <dd>HTTP-Redirect 请求 / HTTP-POST 响应</dd>
              <dt>NameID 格式</dt>
              <dd>{viewing.nameIdFormat}</dd>
              <dt>用户授权确认</dt>
              <dd>{viewing.preauthorized ? "跳过" : "每次确认"}</dd>
              <dt>允许发送的属性</dt>
              <dd>{viewing.attributes?.join("、") || "无"}</dd>
              <dt>请求签名</dt>
              <dd>
                {viewing.allowUnsignedRequests ? "允许未签名请求" : "必须签名"}
              </dd>
              <dt>配置版本</dt>
              <dd>{viewing.revision}</dd>
            </dl>
            <Field>
              <FieldLabel htmlFor="saml-certificates-view">
                SP 签名公共证书
              </FieldLabel>
              <Textarea
                id="saml-certificates-view"
                className="field-sizing-fixed h-32"
                readOnly
                value={viewing.signingCertificates?.join("\n\n") ?? ""}
                rows={5}
              />
            </Field>
            {!viewing.retired && (
              <DialogFooter>
                <Button
                  variant="destructive"
                  onClick={() => {
                    setViewing(undefined)
                    setRetiring(viewing)
                  }}
                >
                  退役应用
                </Button>
                <Button
                  onClick={() => {
                    setViewing(undefined)
                    setEditing(viewing)
                  }}
                >
                  编辑
                </Button>
              </DialogFooter>
            )}
          </DialogContent>
        </Dialog>
      )}
      {editing && (
        <RegistrationDialog
          item={editing === "new" ? undefined : editing}
          base={base}
          csrf={csrf}
          save={save}
          onClose={() => setEditing(undefined)}
          onComplete={finish}
        />
      )}
      {retiring && (
        <RetireDialog
          item={retiring}
          base={base}
          csrf={csrf}
          save={save}
          onClose={() => setRetiring(undefined)}
          onComplete={finish}
        />
      )}
    </section>
  )
}

function RegistrationDialog({
  item,
  base,
  csrf,
  save,
  onClose,
  onComplete,
}: {
  item?: SAMLServiceProvider
  base: string
  csrf: string
  save: Save
  onClose: () => void
  onComplete: () => void
}) {
  const [pending, setPending] = useState(false)
  const [error, setError] = useState("")
  const [unsigned, setUnsigned] = useState(item?.allowUnsignedRequests ?? false)
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (pending) return
    const fields = new FormData(event.currentTarget)
    setError("")
    setPending(true)
    try {
      const certificates = signingCertificates(
        String(fields.get("certificates") ?? "")
      )
      if (!unsigned && !certificates.length)
        throw new Error("要求签名的应用至少需要一个 SP 公共证书。")
      const input = {
        ...(item ? { id: item.id } : {}),
        displayName: String(fields.get("displayName")).trim(),
        entityId: item?.entityId ?? String(fields.get("entityId")).trim(),
        acsUrl: String(fields.get("acsUrl")).trim(),
        nameIdFormat: item?.nameIdFormat ?? "persistent",
        enabled: fields.has("enabled"),
        allowUnsignedRequests: unsigned,
        signingCertificates: certificates,
        preauthorized: fields.has("preauthorized"),
        attributes: [
          ...(fields.has("displayNameAttribute") ? ["DisplayName"] : []),
          ...(fields.has("emailAttribute") ? ["Email"] : []),
          ...(fields.has("organizationAttribute") ? ["OrganizationID"] : []),
        ],
        revision: item?.revision ?? 0,
      }
      await save(base + (item ? `/${encodeURIComponent(item.id)}` : ""), {
        method: item ? "PUT" : "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
        body: JSON.stringify(input),
      })
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
      <DialogContent
        className="flex max-h-[calc(100dvh-2rem)] flex-col sm:max-w-xl"
        showCloseButton={!pending}
      >
        <DialogHeader>
          <DialogTitle>
            {item ? "编辑 SAML 应用" : "添加 SAML 应用"}
          </DialogTitle>
        </DialogHeader>
        <form onSubmit={submit} className="flex min-h-0 flex-col">
          <div className="min-h-0 overflow-y-auto px-1 py-1">
            <FieldGroup className="gap-3">
              <Field>
                <FieldLabel htmlFor="saml-name">应用名称</FieldLabel>
                <Input
                  id="saml-name"
                  name="displayName"
                  required
                  maxLength={128}
                  defaultValue={item ? name(item) : ""}
                  readOnly={pending}
                />
              </Field>
              {item && <RecordIdentifier value={item.id} label="应用 ID" />}
              <Field>
                <FieldLabel htmlFor="saml-entity">Entity ID</FieldLabel>
                <Input
                  id="saml-entity"
                  name="entityId"
                  required
                  maxLength={1024}
                  defaultValue={item?.entityId}
                  readOnly={pending || !!item}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="saml-acs">
                  ACS 地址（HTTPS / HTTP-POST）
                </FieldLabel>
                <Input
                  id="saml-acs"
                  name="acsUrl"
                  type="url"
                  required
                  maxLength={2048}
                  defaultValue={item?.acsUrl}
                  readOnly={pending}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="saml-certificates">
                  SP 签名公共证书（PEM，最多 4 个）
                </FieldLabel>
                <Textarea
                  id="saml-certificates"
                  className="field-sizing-fixed h-32"
                  name="certificates"
                  rows={5}
                  maxLength={28000}
                  defaultValue={item?.signingCertificates?.join("\n\n")}
                  readOnly={pending}
                />
              </Field>
              <Field orientation="horizontal" data-disabled={pending}>
                <Checkbox
                  id="saml-unsigned"
                  nativeButton
                  render={<button type="button" />}
                  checked={unsigned}
                  onCheckedChange={setUnsigned}
                  disabled={pending}
                />
                <FieldLabel htmlFor="saml-unsigned">
                  允许未签名的登录请求
                </FieldLabel>
              </Field>
              {unsigned && (
                <Alert>
                  <AlertDescription>
                    仅为无法签名的可信应用启用此例外。已签名但验签失败的请求仍会被拒绝。
                  </AlertDescription>
                </Alert>
              )}
              <Field orientation="horizontal" data-disabled={pending}>
                <Checkbox
                  id="saml-preauthorized"
                  name="preauthorized"
                  nativeButton
                  render={<button type="button" />}
                  defaultChecked={item?.preauthorized ?? false}
                  disabled={pending}
                />
                <FieldLabel htmlFor="saml-preauthorized">
                  跳过用户授权确认
                </FieldLabel>
              </Field>
              <Field orientation="horizontal" data-disabled={pending}>
                <Checkbox
                  id="saml-display-attribute"
                  name="displayNameAttribute"
                  nativeButton
                  render={<button type="button" />}
                  defaultChecked={
                    item?.attributes?.includes("DisplayName") ?? false
                  }
                  disabled={pending}
                />
                <FieldLabel htmlFor="saml-display-attribute">
                  向应用发送成员显示名称（DisplayName）
                </FieldLabel>
              </Field>
              <Field orientation="horizontal" data-disabled={pending}>
                <Checkbox
                  id="saml-email-attribute"
                  name="emailAttribute"
                  nativeButton
                  render={<button type="button" />}
                  defaultChecked={item?.attributes?.includes("Email") ?? false}
                  disabled={pending}
                />
                <FieldLabel htmlFor="saml-email-attribute">
                  向应用发送受管邮箱（Email）
                </FieldLabel>
              </Field>
              <Field orientation="horizontal" data-disabled={pending}>
                <Checkbox
                  id="saml-organization-attribute"
                  name="organizationAttribute"
                  nativeButton
                  render={<button type="button" />}
                  defaultChecked={item?.attributes?.includes("OrganizationID") ?? false}
                  disabled={pending}
                />
                <FieldLabel htmlFor="saml-organization-attribute">
                  向应用发送登录成员的组织 ID（OrganizationID）
                </FieldLabel>
              </Field>
              <Field orientation="horizontal" data-disabled={pending}>
                <Checkbox
                  id="saml-enabled"
                  name="enabled"
                  nativeButton
                  render={<button type="button" />}
                  defaultChecked={item?.enabled ?? true}
                  disabled={pending}
                />
                <FieldLabel htmlFor="saml-enabled">启用应用</FieldLabel>
              </Field>
            </FieldGroup>
            <Feedback error={error} />
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

function RetireDialog({
  item,
  base,
  csrf,
  save,
  onClose,
  onComplete,
}: {
  item: SAMLServiceProvider
  base: string
  csrf: string
  save: Save
  onClose: () => void
  onComplete: () => void
}) {
  const [pending, setPending] = useState(false)
  const [error, setError] = useState("")
  async function retire() {
    if (pending) return
    setPending(true)
    setError("")
    try {
      await save(`${base}/${encodeURIComponent(item.id)}/retire`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
        body: JSON.stringify({ revision: item.revision }),
      })
      onComplete()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setPending(false)
    }
  }
  async function disable() {
    if (pending) return
    setPending(true)
    setError("")
    try {
      await save(`${base}/${encodeURIComponent(item.id)}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
        body: JSON.stringify({ ...registrationInput(item), enabled: false }),
      })
      onComplete()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setPending(false)
    }
  }
  return (
    <AlertDialog
      open
      onOpenChange={(open) => {
        if (!open && !pending) onClose()
      }}
    >
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>退役 {name(item)}？</AlertDialogTitle>
          <AlertDialogDescription>
            退役后无法恢复，Entity ID 和已有 NameID
            映射将永久保留。若只需暂时停止登录，请选择停用。现有应用会话不会自动退出。
          </AlertDialogDescription>
        </AlertDialogHeader>
        <Feedback error={error} />
        <AlertDialogFooter>
          <Button variant="outline" disabled={pending} onClick={onClose}>
            取消
          </Button>
          <Button
            variant="secondary"
            disabled={pending || !item.enabled}
            onClick={disable}
          >
            仅停用
          </Button>
          <Button variant="destructive" disabled={pending} onClick={retire}>
            {pending ? "正在处理…" : "永久退役"}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}

function Feedback({ error }: { error: string }) {
  return (
    <div className="form-feedback" role="status" aria-live="polite">
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
    </div>
  )
}
