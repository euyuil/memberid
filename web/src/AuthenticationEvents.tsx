import { useEffect, useRef, useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog"
import {
  DirectoryState,
  RecordIdentifier,
  RecordTime,
} from "@/components/directory"
import { Link, navigate } from "@/navigation"
import {
  authenticationEventLocation,
  authenticationEventPath,
  correlationLocation,
  eventFilterKeys,
  eventTypes,
  eventOutcomes,
  eventMethods,
  localEventTime,
  type AuthenticationEvent,
  type AuthenticationEventPage,
} from "@/authentication-events"

export function AuthenticationEventFilters({
  org,
  query,
}: {
  org: string
  query: URLSearchParams
}) {
  const fields = {
    memberId: "成员 ID",
    clientId: "客户端 ID",
    grantId: "授权 ID",
    requestId: "请求 ID",
    interactionId: "交互 ID",
  }
  const advanced =
    Object.keys(fields).some((key) => query.has(key)) ||
    query.has("from") ||
    query.has("to")
  return (
    <form
      className="mb-4 flex flex-col gap-4"
      aria-label="筛选认证记录"
      onInput={(event) => {
        const end = event.currentTarget.elements.namedItem(
          "to"
        ) as HTMLInputElement
        end.setCustomValidity("")
      }}
      onSubmit={(event) => {
        event.preventDefault()
        const values = new FormData(event.currentTarget)
        const from = String(values.get("from") ?? "")
        const to = String(values.get("to") ?? "")
        const end = event.currentTarget.elements.namedItem(
          "to"
        ) as HTMLInputElement
        end.setCustomValidity(
          from && to && new Date(to) <= new Date(from)
            ? "结束时间需要晚于开始时间。"
            : ""
        )
        if (!event.currentTarget.reportValidity()) return
        const next = new URLSearchParams()
        for (const key of eventFilterKeys) {
          const value = String(values.get(key) ?? "").trim()
          if (value)
            next.set(
              key,
              key === "from" || key === "to"
                ? new Date(value).toISOString()
                : value
            )
        }
        navigate(authenticationEventLocation(org, next))
      }}
    >
      <FieldGroup className="flex-row flex-wrap items-end gap-3">
        {(
          [
            ["type", "事件类型", eventTypes],
            ["outcome", "结果", eventOutcomes],
            ["method", "认证方式", eventMethods],
          ] as const
        ).map(([key, label, choices]) => (
          <Field key={key} className="w-full sm:w-auto">
            <FieldLabel htmlFor={`event-${key}`}>{label}</FieldLabel>
            <Select
              name={key}
              defaultValue={query.get(key) ?? ""}
              items={[
                { value: "", label: "全部" },
                ...Object.entries(choices).map(([value, label]) => ({
                  value,
                  label,
                })),
              ]}
            >
              <SelectTrigger id={`event-${key}`} className="w-full sm:w-44">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value="">全部</SelectItem>
                  {Object.entries(choices).map(([value, text]) => (
                    <SelectItem key={value} value={value}>
                      {text}
                    </SelectItem>
                  ))}
                </SelectGroup>
              </SelectContent>
            </Select>
          </Field>
        ))}
        <Button type="submit">筛选</Button>
        <Button
          variant="outline"
          render={<Link href={authenticationEventPath(org)} />}
          nativeButton={false}
        >
          清除筛选
        </Button>
        <span className="self-center text-sm text-muted-foreground">
          记录可能不完整
        </span>
      </FieldGroup>
      <details open={advanced || undefined}>
        <summary className="w-fit cursor-pointer text-sm">更多筛选</summary>
        <FieldGroup className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {Object.entries(fields).map(([key, label]) => (
            <Field key={key}>
              <FieldLabel htmlFor={`event-${key}`}>{label}</FieldLabel>
              <Input
                id={`event-${key}`}
                name={key}
                defaultValue={query.get(key) ?? ""}
                maxLength={128}
              />
            </Field>
          ))}
          {(
            [
              ["from", "开始时间（本地，含）"],
              ["to", "结束时间（本地，不含）"],
            ] as const
          ).map(([key, label]) => (
            <Field key={key}>
              <FieldLabel htmlFor={`event-${key}`}>{label}</FieldLabel>
              <Input
                id={`event-${key}`}
                type="datetime-local"
                step="1"
                name={key}
                defaultValue={localEventTime(query.get(key) ?? "")}
              />
            </Field>
          ))}
        </FieldGroup>
      </details>
    </form>
  )
}

type LoadEvent = (
  path: string,
  options?: RequestInit
) => Promise<AuthenticationEvent>

function EventDetail({
  id,
  org,
  loadEvent,
  openEvent,
}: {
  id: string
  org: string
  loadEvent: LoadEvent
  openEvent: (id: string) => void
}) {
  const [event, setEvent] = useState<AuthenticationEvent>()
  const [error, setError] = useState("")
  const [revision, setRevision] = useState(0)
  useEffect(() => {
    const abort = new AbortController()
    void loadEvent(
      `/api${authenticationEventPath(org)}/${encodeURIComponent(id)}`,
      { signal: abort.signal }
    )
      .then((value) => {
        if (!abort.signal.aborted) setEvent(value)
      })
      .catch((reason: Error) => {
        if (!abort.signal.aborted) setError(reason.message)
      })
    return () => abort.abort()
  }, [id, org, loadEvent, revision])
  const references = {
    eventId: "事件 ID",
    organizationId: "组织 ID",
    memberId: "目标成员 ID",
    clientId: "客户端 ID",
    factorId: "认证因子 ID",
    bindingId: "绑定 ID",
    sessionId: "会话 ID",
    grantId: "授权 ID",
    providerId: "身份提供商 ID",
  } as const
  return (
    <>
      <DialogHeader>
        <DialogTitle>认证记录详情</DialogTitle>
        <DialogDescription>
          {event
            ? `${eventTypes[event.type] ?? event.type} · ${eventOutcomes[event.outcome] ?? event.outcome}`
            : "正在读取记录"}
        </DialogDescription>
      </DialogHeader>
      {error ? (
        <div role="alert">
          <p>{error}</p>
          <Button
            variant="outline"
            onClick={() => {
              setError("")
              setRevision((value) => value + 1)
            }}
          >
            重试
          </Button>
        </div>
      ) : !event ? (
        <p role="status">加载中…</p>
      ) : (
        <dl className="authentication-event-detail space-y-3">
          <div>
            <dt>发生时间</dt>
            <dd>
              <RecordTime value={event.occurredAt} />
            </dd>
          </div>
          <div>
            <dt>入库时间</dt>
            <dd>
              <RecordTime value={event.recordedAt} />
            </dd>
          </div>
          {event.actor && (
            <div>
              <dt>已验证发起者（{event.actor.kind}）</dt>
              <dd>
                <RecordIdentifier label="发起者 ID" value={event.actor.id} />
              </dd>
            </div>
          )}
          {Object.entries({
            method: "认证方式",
            reasonCode: "原因",
            purpose: "用途",
            trigger: "触发原因",
          } as const).map(([key, label]) => {
            const value =
              event[key as "method" | "reasonCode" | "purpose" | "trigger"]
            return value ? (
              <div key={key}>
                <dt>{label}</dt>
                <dd className="wrap-anywhere">
                  {key === "method" ? (eventMethods[value] ?? value) : value}
                </dd>
              </div>
            ) : null
          })}
          {Object.entries(references).map(([key, label]) => {
            const value = event[key as keyof typeof references]
            return value ? (
              <div key={key}>
                <dt>{label}</dt>
                <dd>
                  <RecordIdentifier label={label} value={value} />
                </dd>
              </div>
            ) : null
          })}
          {(
            [
              ["requestId", "请求 ID", "同一请求的记录"],
              ["interactionId", "交互 ID", "同一交互的记录"],
            ] as const
          ).map(([key, label, text]) =>
            event[key] ? (
              <div key={key}>
                <dt>{label}</dt>
                <dd>
                  <RecordIdentifier label={label} value={event[key]} />
                  <Link
                    className="underline"
                    href={correlationLocation(org, key, event[key])}
                    onClick={(click) => {
                      if (
                        click.button === 0 &&
                        !click.metaKey &&
                        !click.ctrlKey &&
                        !click.shiftKey &&
                        !click.altKey
                      )
                        openEvent("")
                    }}
                  >
                    {text}
                  </Link>
                </dd>
              </div>
            ) : null
          )}
          {event.causationId && (
            <div>
              <dt>触发事件</dt>
              <dd>
                <RecordIdentifier
                  label="触发事件 ID"
                  value={event.causationId}
                />
                <Button
                  variant="outline"
                  onClick={() => openEvent(event.causationId!)}
                >
                  查看触发事件
                </Button>
              </dd>
            </div>
          )}
        </dl>
      )}
    </>
  )
}

export function AuthenticationEvents({
  org,
  query,
  page,
  loadEvent,
}: {
  org: string
  query: URLSearchParams
  page: AuthenticationEventPage
  loadEvent: LoadEvent
}) {
  const [selected, setSelected] = useState("")
  const trigger = useRef<HTMLButtonElement | null>(null)
  const first = new URLSearchParams(query)
  first.delete("after")
  const next = new URLSearchParams(query)
  if (page.nextAfter) next.set("after", page.nextAfter)
  return (
    <section aria-label="认证记录列表">
      <div className="overflow-hidden rounded-md border">
        {page.items.length ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>发生时间</TableHead>
                <TableHead>事件</TableHead>
                <TableHead>结果</TableHead>
                <TableHead>认证方式</TableHead>
                {!org && <TableHead>组织</TableHead>}
                <TableHead>客户端</TableHead>
                <TableHead>
                  <span className="sr-only">详情</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {page.items.map((event) => (
                <TableRow key={event.eventId}>
                  <TableCell>
                    <RecordTime value={event.occurredAt} compact />
                  </TableCell>
                  <TableCell>{eventTypes[event.type] ?? event.type}</TableCell>
                  <TableCell>
                    {eventOutcomes[event.outcome] ?? event.outcome}
                  </TableCell>
                  <TableCell>
                    {event.method
                      ? (eventMethods[event.method] ?? event.method)
                      : "—"}
                  </TableCell>
                  {!org && (
                    <TableCell>
                      <span
                        className="block max-w-48 truncate"
                        title={
                          event.organizationId
                            ? page.organizationNames[event.organizationId]
                            : undefined
                        }
                      >
                        {event.organizationId
                          ? (page.organizationNames[event.organizationId] ??
                            "未知组织")
                          : "共享或未确定"}
                      </span>
                    </TableCell>
                  )}
                  <TableCell>
                    <span
                      className="block max-w-40 truncate"
                      title={event.clientId}
                    >
                      {event.clientId ?? "—"}
                    </span>
                  </TableCell>
                  <TableCell>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={(click) => {
                        trigger.current = click.currentTarget
                        setSelected(event.eventId)
                      }}
                    >
                      查看详情
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <DirectoryState
            kind={first.size ? "filtered" : "empty"}
            title="暂无匹配的认证记录"
          />
        )}
      </div>
      <div className="flex items-center justify-end gap-2 py-4">
        <div className="flex-1 text-sm text-muted-foreground">
          本页 {page.items.length} 条记录
        </div>
        <Button
          variant="outline"
          size="sm"
          disabled={!query.has("after")}
          render={<Link href={authenticationEventLocation(org, first)} />}
          nativeButton={false}
        >
          最新记录
        </Button>
        <Button
          variant="outline"
          size="sm"
          disabled={!page.nextAfter}
          render={<Link href={authenticationEventLocation(org, next)} />}
          nativeButton={false}
        >
          更早记录
        </Button>
      </div>
      <Dialog
        open={!!selected}
        onOpenChange={(open) => {
          if (!open) setSelected("")
        }}
      >
        <DialogContent
          finalFocus={trigger}
          className="max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-lg"
        >
          {selected && (
            <EventDetail
              key={selected}
              id={selected}
              org={org}
              loadEvent={loadEvent}
              openEvent={setSelected}
            />
          )}
        </DialogContent>
      </Dialog>
    </section>
  )
}
