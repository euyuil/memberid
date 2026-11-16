import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { currentLocation } from "@/navigation"

type Identity = {
  memberId: string
  organizationId: string
  organizationName: string
  displayName: string
  platform: boolean
}
type IdentityPage = { items: Identity[]; nextAfter?: string }

export function IdentitySwitch({
  memberId,
  csrf,
  request,
  onClose,
}: {
  memberId: string
  csrf: string
  request: <T>(path: string, init?: RequestInit) => Promise<T>
  onClose: () => void
}) {
  const [after, setAfter] = useState("")
  const [revision, setRevision] = useState(0)
  const [page, setPage] = useState<IdentityPage>()
  const [error, setError] = useState("")
  const [pending, setPending] = useState("")
  useEffect(() => {
    const abort = new AbortController()
    request<IdentityPage>(`/api/identities?${new URLSearchParams({ after })}`, {
      signal: abort.signal,
    })
      .then((value) => {
        if (!abort.signal.aborted) setPage(value)
      })
      .catch((error: Error) => {
        if (!abort.signal.aborted) setError(error.message)
      })
    return () => abort.abort()
  }, [after, revision, request])

  const choose = async (id: string) => {
    if (pending) return
    setPending(id)
    setError("")
    try {
      const result = await request<{ authorizationUrl: string }>(
        "/api/identity-switch",
        {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
          body: JSON.stringify({ memberId: id, returnTo: currentLocation() }),
        }
      )
      window.location.assign(result.authorizationUrl)
    } catch (error) {
      setError((error as Error).message)
      setPending("")
    }
  }
  return (
    <Dialog open onOpenChange={(open) => !open && !pending && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>切换身份</DialogTitle>
        </DialogHeader>
        <div className="flex max-h-[60vh] flex-col gap-2 overflow-y-auto">
          {!page && !error && <Skeleton className="h-24 w-full" />}
          {page?.items.map((identity) => (
            <Button
              key={identity.memberId}
              variant="outline"
              className="h-auto justify-start py-3"
              disabled={!!pending || identity.memberId === memberId}
              onClick={() => choose(identity.memberId)}
            >
              <span className="grid min-w-0 flex-1 gap-1 text-left">
                <span className="truncate">{identity.displayName}</span>
                <span className="truncate">{identity.organizationName}</span>
              </span>
              <Badge variant="secondary">
                {pending === identity.memberId
                  ? "正在切换…"
                  : identity.memberId === memberId
                    ? "当前身份"
                    : identity.platform
                      ? "平台管理员"
                      : "组织管理员"}
              </Badge>
            </Button>
          ))}
          {page?.items.length === 0 && <p>没有可切换的管理员身份。</p>}
          {(after || page?.nextAfter) && (
            <div className="flex justify-between gap-2">
              <Button
                variant="outline"
                disabled={!after || !!pending}
                onClick={() => {
                  setPage(undefined)
                  setError("")
                  setAfter("")
                }}
              >
                返回首页
              </Button>
              <Button
                variant="outline"
                disabled={!page?.nextAfter || !!pending}
                onClick={() => {
                  setAfter(page!.nextAfter!)
                  setPage(undefined)
                  setError("")
                }}
              >
                下一页
              </Button>
            </div>
          )}
        </div>
        <div className="min-h-12" aria-live="polite">
          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
        </div>
        {error && !page && (
          <Button
            variant="outline"
            onClick={() => {
              setError("")
              setRevision((value) => value + 1)
            }}
          >
            重试
          </Button>
        )}
      </DialogContent>
    </Dialog>
  )
}
