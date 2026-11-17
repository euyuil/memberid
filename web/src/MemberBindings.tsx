import { useState } from "react"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { RecordIdentifier, RecordTime } from "@/components/directory"

export type MemberBinding = {
  id: string
  factorType: string
  status: string
  createdAt: string
  revokedAt?: string
  providerId?: string
  providerName?: string
  clientId?: string
  tenantId?: string
  externalSubject?: string
  externalMemberId?: string
}
const labels: Record<string, string> = {
  phone: "手机号",
  password: "密码",
  feishu: "飞书",
  dingtalk: "钉钉",
}

export function MemberBindings({
  items,
  username,
}: {
  items: MemberBinding[]
  username?: string
}) {
  const [viewing, setViewing] = useState<MemberBinding>()
  return (
    <>
      {items.map((item) => (
        <div className="flex items-center justify-between gap-4" key={item.id}>
          <button
            className="min-w-0 truncate text-left hover:underline"
            onClick={() => setViewing(item)}
          >
            {labels[item.factorType] ?? item.factorType}
            {item.providerName
              ? ` · ${item.providerName}`
              : item.factorType === "password" && username
                ? ` · ${username}`
                : ""}
          </button>
          <Badge
            variant={item.status === "active" ? "secondary" : "destructive"}
          >
            {item.status === "active" ? "已绑定" : "已撤销"}
          </Badge>
        </div>
      ))}
      {viewing && (
        <Dialog
          open
          onOpenChange={(open) => {
            if (!open) setViewing(undefined)
          }}
        >
          <DialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-xl">
            <DialogHeader>
              <DialogTitle>登录方式详情</DialogTitle>
            </DialogHeader>
            <dl>
              <dt>类型</dt>
              <dd>{labels[viewing.factorType] ?? viewing.factorType}</dd>
              <dt>状态</dt>
              <dd>{viewing.status === "active" ? "已绑定" : "已撤销"}</dd>
              <dt>绑定时间</dt>
              <dd>
                <RecordTime value={viewing.createdAt} />
              </dd>
              {viewing.revokedAt && (
                <>
                  <dt>撤销时间</dt>
                  <dd>
                    <RecordTime value={viewing.revokedAt} />
                  </dd>
                </>
              )}
              {viewing.factorType === "password" && username && (
                <>
                  <dt>登录用户名</dt>
                  <dd>
                    <RecordIdentifier value={username} label="登录用户名" />
                  </dd>
                </>
              )}
              {viewing.providerName && (
                <>
                  <dt>提供商</dt>
                  <dd>{viewing.providerName}</dd>
                </>
              )}
              {viewing.providerId && (
                <>
                  <dt>提供商 ID</dt>
                  <dd>
                    <RecordIdentifier
                      value={viewing.providerId}
                      label="提供商 ID"
                    />
                  </dd>
                </>
              )}
              {viewing.clientId && (
                <>
                  <dt>应用 ID</dt>
                  <dd>
                    <RecordIdentifier
                      value={viewing.clientId}
                      label="应用 ID"
                    />
                  </dd>
                </>
              )}
              {viewing.tenantId && (
                <>
                  <dt>
                    {viewing.factorType === "feishu" ? "Tenant Key" : "Corp ID"}
                  </dt>
                  <dd>
                    <RecordIdentifier
                      value={viewing.tenantId}
                      label="企业标识"
                    />
                  </dd>
                </>
              )}
              {viewing.externalSubject && (
                <>
                  <dt>
                    {viewing.factorType === "feishu" ? "OpenID" : "UnionID"}
                  </dt>
                  <dd>
                    <RecordIdentifier
                      value={viewing.externalSubject}
                      label="外部身份标识"
                    />
                  </dd>
                </>
              )}
              {viewing.externalMemberId && (
                <>
                  <dt>员工 ID</dt>
                  <dd>
                    <RecordIdentifier
                      value={viewing.externalMemberId}
                      label="员工 ID"
                    />
                  </dd>
                </>
              )}
            </dl>
          </DialogContent>
        </Dialog>
      )}
    </>
  )
}

export function SelfAccountLink({
  csrf,
  request,
}: {
  csrf: string
  request: (path: string, init: RequestInit) => Promise<unknown>
}) {
  const [pending, setPending] = useState(false)
  const [error, setError] = useState("")
  async function start() {
    if (pending) return
    setPending(true)
    setError("")
    try {
      const result = (await request("/api/account-link", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
        body: "{}",
      })) as { authorizationUrl: string }
      window.location.assign(result.authorizationUrl)
    } catch (e) {
      setError((e as Error).message)
      setPending(false)
    }
  }
  return (
    <div>
      <Button variant="outline" disabled={pending} onClick={() => void start()}>
        {pending ? "正在重新验证身份…" : "绑定本人的登录方式"}
      </Button>
      <div className="form-feedback" role="status" aria-live="polite">
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
      </div>
    </div>
  )
}
