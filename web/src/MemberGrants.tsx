import { useEffect, useState } from "react"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { RecordTime } from "@/components/directory"

type Grant = {
  id: string
  clientId: string
  clientName: string
  scopes: string[]
  authenticatedAt: string
  expiresAt: string
  state: "active" | "expired" | "revoked"
}
type Page = { items: Grant[]; nextAfter?: string }
type Props = {
  organizationId: string
  memberId: string
  request: (path: string, init: RequestInit) => Promise<unknown>
}
const states = { active: "未到期", expired: "已过期", revoked: "已撤销" }

export function MemberGrants(props: Props) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <Button variant="outline" onClick={() => setOpen(true)}>
        查看应用授权
      </Button>
      {open && <GrantDialog {...props} onClose={() => setOpen(false)} />}
    </>
  )
}
function GrantDialog({
  organizationId,
  memberId,
  request,
  onClose,
}: Props & { onClose: () => void }) {
  const [after, setAfter] = useState("")
  const [page, setPage] = useState<Page>()
  const [error, setError] = useState("")
  useEffect(() => {
    const controller = new AbortController()
    const query = after ? `?after=${encodeURIComponent(after)}` : ""
    request(
      `/api/organizations/${encodeURIComponent(organizationId)}/members/${encodeURIComponent(memberId)}/grants${query}`,
      { signal: controller.signal }
    )
      .then((value) => {
        if (!controller.signal.aborted) setPage(value as Page)
      })
      .catch((e: Error) => {
        if (!controller.signal.aborted) setError(e.message)
      })
    return () => controller.abort()
  }, [organizationId, memberId, after, request])
  function move(cursor: string) {
    setPage(undefined)
    setError("")
    setAfter(cursor)
  }
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) onClose()
      }}
    >
      <DialogContent className="flex max-h-[calc(100dvh-2rem)] flex-col sm:max-w-4xl">
        <DialogHeader>
          <DialogTitle>OIDC 应用授权</DialogTitle>
        </DialogHeader>
        <Alert>
          <AlertDescription>
            记录状态不代表业务应用当前的登录会话或权限。
          </AlertDescription>
        </Alert>
        <div className="min-h-52 overflow-auto">
          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          {!page && !error && <div role="status">正在读取授权记录…</div>}
          {page && page.items.length === 0 && (
            <div role="status">暂无授权记录</div>
          )}
          {page && page.items.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>应用</TableHead>
                  <TableHead>授权范围</TableHead>
                  <TableHead>认证时间</TableHead>
                  <TableHead>到期时间</TableHead>
                  <TableHead>状态</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {page.items.map((item) => (
                  <TableRow key={item.id}>
                    <TableCell>
                      <div className="font-medium">{item.clientName}</div>
                      <div className="text-xs text-muted-foreground">
                        {item.clientId}
                      </div>
                    </TableCell>
                    <TableCell>
                      <span className="break-all whitespace-normal">
                        {item.scopes.join(" ")}
                      </span>
                    </TableCell>
                    <TableCell>
                      <RecordTime value={item.authenticatedAt} />
                    </TableCell>
                    <TableCell>
                      <RecordTime value={item.expiresAt} />
                    </TableCell>
                    <TableCell>{states[item.state]}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </div>
        <DialogFooter>
          <Button
            variant="outline"
            disabled={!after || !page}
            onClick={() => move("")}
          >
            返回首页
          </Button>
          <Button
            variant="outline"
            disabled={!page?.nextAfter}
            onClick={() => move(page!.nextAfter!)}
          >
            下一页
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
