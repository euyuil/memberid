import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import {
  Card,
  CardHeader,
  CardTitle,
  CardContent,
  CardFooter,
} from "@/components/ui/card"
import { Alert, AlertDescription } from "@/components/ui/alert"
import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogDescription,
  AlertDialogFooter,
} from "@/components/ui/alert-dialog"
import {
  Table,
  TableHeader,
  TableHead,
  TableBody,
  TableCell,
  TableRow,
} from "@/components/ui/table"
import { DirectoryState, DirectoryResults } from "@/components/directory"
import { Link } from "@/navigation"
import { routeURL } from "@/routes"

export type ApplicationView = "oidc-applications" | "saml-service-providers"
export type ApplicationUse = (
  { clientId: string } | { applicationId: string }
) & {
  displayName: string
  ownerOrganizationId: string
  ownerName: string
  enabled: boolean
  use: "included" | "enabled" | "available" | "withdrawn"
}

function applicationID(app: ApplicationUse) {
  return "clientId" in app ? app.clientId : app.applicationId
}

export function ApplicationViews({
  view,
  org,
  used,
}: {
  org: string
  view: ApplicationView
  used: boolean
}) {
  return (
    <nav aria-label="应用视图" className="mb-4 flex gap-2">
      {[false, true].map((isUsed) => (
        <Button
          key={String(isUsed)}
          variant={isUsed === used ? "secondary" : "ghost"}
          nativeButton={false}
          render={
            <Link
              href={routeURL({
                view,
                org,
                used: isUsed,
              })}
              aria-current={isUsed === used ? "page" : undefined}
            />
          }
        >
          {isUsed ? "本组织使用" : "本组织管理"}
        </Button>
      ))}
    </nav>
  )
}

function applicationUseLabel(app: ApplicationUse) {
  if (!app.enabled) return "应用已全局停用"
  switch (app.use) {
    case "included":
      return "注册策略已允许"
    case "enabled":
      return "本组织已启用"
    case "withdrawn":
      return "本组织已停止使用"
    case "available":
      return "本组织尚未启用"
  }
}

export function ApplicationUses({
  view,
  org,
  items,
  preview,
  csrf,
  request,
  refresh,
}: {
  view: ApplicationView
  org: { id: string; name: string }
  items?: ApplicationUse[]
  preview?: ApplicationUse | null
  csrf: string
  request: <T>(path: string, init?: RequestInit) => Promise<T>
  refresh: () => void
}) {
  const [confirm, setConfirm] = useState(false)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState("")
  const withdrawing = preview?.use === "enabled"
  async function change(app: ApplicationUse) {
    setPending(true)
    setError("")
    try {
      await request(
        "/api/organizations/" +
          encodeURIComponent(org.id) +
          "/" +
          view +
          "/" +
          encodeURIComponent(applicationID(app)) +
          "/enablement",
        {
          method: "PUT",
          headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
          body: JSON.stringify({ enabled: !withdrawing }),
        }
      )
      setConfirm(false)
      refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : "操作失败，请刷新后重试。")
    } finally {
      setPending(false)
    }
  }
  if (items)
    return (
      <DirectoryResults
        count={items.length}
        empty={
          <DirectoryState
            kind="empty"
            title={
              view === "oidc-applications"
                ? "本组织尚未使用任何 OIDC 应用"
                : "本组织尚未使用任何 SAML 应用"
            }
          />
        }
      >
        <div className="overflow-hidden rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>应用名称</TableHead>
                <TableHead>发布组织</TableHead>
                <TableHead>使用状态</TableHead>
                <TableHead className="text-right">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((app) => (
                <TableRow key={applicationID(app)}>
                  <TableCell>{app.displayName}</TableCell>
                  <TableCell>{app.ownerName}</TableCell>
                  <TableCell>
                    <Badge variant="secondary">
                      {applicationUseLabel(app)}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="link"
                      nativeButton={false}
                      render={
                        <Link
                          href={routeURL({
                            view,
                            org: org.id,
                            join: applicationID(app),
                          })}
                        />
                      }
                    >
                      查看
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </DirectoryResults>
    )
  if (!preview)
    return (
      <DirectoryState
        kind="empty"
        title="此应用未对本组织开放，请联系发布组织确认共享设置。"
      />
    )
  return (
    <Card className="max-w-xl">
      <CardHeader>
        <CardTitle>{preview.displayName}</CardTitle>
      </CardHeader>
      <CardContent>
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-3">
          <dt>发布组织</dt>
          <dd>{preview.ownerName}</dd>
          <dt>当前使用组织</dt>
          <dd>
            {org.name}{" "}
            <span className="break-all text-muted-foreground">({org.id})</span>
          </dd>
          <dt>使用状态</dt>
          <dd>{applicationUseLabel(preview)}</dd>
        </dl>
      </CardContent>
      {(withdrawing || (preview.enabled && preview.use !== "included")) && (
        <CardFooter>
          <Button
            variant={withdrawing ? "outline" : "default"}
            onClick={() => {
              setConfirm(true)
              setError("")
            }}
          >
            {withdrawing ? "停止使用" : "为本组织启用"}
          </Button>
        </CardFooter>
      )}
      <AlertDialog
        open={confirm}
        onOpenChange={(v) => {
          if (!pending) setConfirm(v)
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {withdrawing ? "停止使用应用" : "为本组织启用应用"}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {withdrawing
                ? view === "saml-service-providers"
                  ? `「${org.name}」的成员将无法发起新的应用登录。应用内已有会话由应用管理。`
                  : `「${org.name}」的成员将无法登录或续期，其现有授权会被撤销。其他组织可继续使用。`
                : `允许「${org.name}」的成员登录「${preview.displayName}」。`}
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
              onClick={() => setConfirm(false)}
            >
              取消
            </Button>
            <Button
              variant={withdrawing ? "destructive" : "default"}
              disabled={pending}
              onClick={() => change(preview)}
            >
              {pending
                ? "正在处理…"
                : withdrawing
                  ? "确认停止使用"
                  : "确认启用"}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  )
}
