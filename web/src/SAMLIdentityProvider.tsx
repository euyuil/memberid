import { useEffect, useState } from "react"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { RecordIdentifier, RecordTime } from "@/components/directory"

type Certificate = {
  pem: string
  sha256: string
  notBefore: string
  notAfter: string
  status: "valid" | "expiring" | "expired" | "notYetValid"
}
type Integration = {
  entityId: string
  metadataUrl: string
  ssoUrl: string
  status: string
  checkedAt: string
  certificate?: Certificate
}
const certificateStatus = {
  valid: "有效",
  expiring: "30 天内到期",
  expired: "已过期",
  notYetValid: "尚未生效",
}

export function SAMLIdentityProvider({
  organizationId,
  request,
  onClose,
}: {
  organizationId: string
  request: (path: string, init: RequestInit) => Promise<unknown>
  onClose: () => void
}) {
  const [data, setData] = useState<Integration>()
  const [error, setError] = useState("")
  useEffect(() => {
    const controller = new AbortController()
    request(
      `/api/organizations/${encodeURIComponent(organizationId)}/saml-identity-provider`,
      { signal: controller.signal }
    )
      .then((value) => {
        if (!controller.signal.aborted) setData(value as Integration)
      })
      .catch((e: Error) => {
        if (!controller.signal.aborted) setError(e.message)
      })
    return () => controller.abort()
  }, [organizationId, request])
  function download(certificate: Certificate) {
    const url = URL.createObjectURL(
      new Blob([certificate.pem], { type: "application/x-pem-file" })
    )
    const link = document.createElement("a")
    link.href = url
    link.download = "memberid-saml-certificate.pem"
    link.click()
    URL.revokeObjectURL(url)
  }
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) onClose()
      }}
    >
      <DialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>SAML 接入信息</DialogTitle>
        </DialogHeader>
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        {!data && !error && <div role="status">正在读取元数据…</div>}
        {data && (
          <>
            {data.status !== "available" && (
              <Alert variant="destructive">
                <AlertDescription>
                  认证服务未返回有效的 SAML 元数据。请确认 SAML
                  已启用且服务可访问。
                </AlertDescription>
              </Alert>
            )}
            <dl>
              <dt>Entity ID</dt>
              <dd>
                <RecordIdentifier
                  value={data.entityId}
                  label="Entity ID"
                  multiline
                />
              </dd>
              <dt>SSO 地址</dt>
              <dd>
                <RecordIdentifier
                  value={data.ssoUrl}
                  label="SSO 地址"
                  multiline
                />
              </dd>
              <dt>元数据地址</dt>
              <dd>
                <RecordIdentifier
                  value={data.metadataUrl}
                  label="元数据地址"
                  multiline
                />
              </dd>
              <dt>检查时间</dt>
              <dd>
                <RecordTime value={data.checkedAt} />
              </dd>
              {data.certificate && (
                <>
                  <dt>签名证书</dt>
                  <dd>{certificateStatus[data.certificate.status]}</dd>
                  <dt>SHA-256</dt>
                  <dd>
                    <RecordIdentifier
                      value={data.certificate.sha256}
                      label="证书 SHA-256"
                      multiline
                    />
                  </dd>
                  <dt>生效时间</dt>
                  <dd>
                    <RecordTime value={data.certificate.notBefore} />
                  </dd>
                  <dt>到期时间</dt>
                  <dd>
                    <RecordTime value={data.certificate.notAfter} />
                  </dd>
                </>
              )}
            </dl>
            {data.certificate && (
              <Button
                variant="outline"
                onClick={() => download(data.certificate!)}
              >
                下载公钥证书
              </Button>
            )}
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}
