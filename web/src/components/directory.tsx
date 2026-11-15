import { useState, type ReactNode } from "react"
import { Copy } from "lucide-react"
import accessDenied from "@/assets/directory-states/access-denied.webp"
import emptyDirectory from "@/assets/directory-states/empty.webp"
import loadFailed from "@/assets/directory-states/load-failed.webp"
import noMatches from "@/assets/directory-states/no-matches.webp"
import { Badge } from "@/components/ui/badge"
import {
  Empty,
  EmptyContent,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { Link, type NavigationState } from "@/navigation"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"

export function DirectoryToolbar({
  title,
  children,
}: {
  title: string
  children?: ReactNode
}) {
  return (
    <div className="directory-toolbar">
      <h2>{title}</h2>
      <div className="actions">{children}</div>
    </div>
  )
}

export function DirectoryFooter({
  count,
  message,
  children,
}: {
  count: number
  message?: string
  children?: ReactNode
}) {
  return (
    <div className="directory-footer">
      <span className="directory-count" role={message ? "status" : undefined}>
        {message ?? `本页 ${count} 条记录`}
      </span>
      <div className="pagination">{children}</div>
    </div>
  )
}

const directoryStateImages = {
  empty: emptyDirectory,
  filtered: noMatches,
  forbidden: accessDenied,
  error: loadFailed,
}

export function DirectoryState({
  kind,
  title,
  action,
}: {
  kind: keyof typeof directoryStateImages
  title: string
  action?: ReactNode
}) {
  return (
    <Empty className="min-h-72 py-8 sm:py-10">
      <EmptyHeader role={kind === "error" ? "alert" : "status"}>
        <EmptyMedia aria-hidden="true">
          <img
            alt=""
            src={directoryStateImages[kind]}
            width={432}
            height={288}
            className="h-auto w-44 sm:w-54"
          />
        </EmptyMedia>
        <EmptyTitle>{title}</EmptyTitle>
      </EmptyHeader>
      {action && <EmptyContent>{action}</EmptyContent>}
    </Empty>
  )
}

export function DirectoryResults({
  count,
  empty,
  children,
}: {
  count: number
  empty?: ReactNode
  children: ReactNode
}) {
  return count > 0 ? children : empty
}

export function RecordIdentity({
  name,
  icon,
  href,
  state,
  onClick,
}: {
  name: string
  icon?: ReactNode
  href?: string
  state?: NavigationState
  onClick?: () => void
}) {
  return (
    <div className="record-identity">
      {icon && (
        <span className="record-avatar" aria-hidden="true">
          {icon}
        </span>
      )}
      <div className="record-text">
        {href ? (
          <Link className="record-name" href={href} state={state} title={name}>
            {name}
          </Link>
        ) : onClick ? (
          <button
            type="button"
            className="record-name"
            title={name}
            onClick={onClick}
          >
            {name}
          </button>
        ) : (
          <span className="record-name" title={name}>
            {name}
          </span>
        )}
      </div>
    </div>
  )
}

export function RecordIdentifier({
  value,
  label,
}: {
  value: string
  label: string
}) {
  const [feedback, setFeedback] = useState("")
  const [copying, setCopying] = useState(false)
  return (
    <div className="record-identifier">
      <div className="identifier-value">
        <Input
          aria-label={label}
          value={value}
          readOnly
          onFocus={(event) => event.currentTarget.select()}
        />
        <Button
          type="button"
          variant="outline"
          size="icon"
          aria-label={`复制${label}`}
          disabled={copying}
          onClick={async () => {
            setCopying(true)
            try {
              await navigator.clipboard.writeText(value)
              setFeedback("已复制完整 ID。")
            } catch {
              setFeedback("无法自动复制，请选中上方 ID 手动复制。")
            } finally {
              setCopying(false)
            }
          }}
        >
          <Copy aria-hidden="true" />
        </Button>
      </div>
      <p className="identifier-feedback" role="status">
        {feedback}
      </p>
    </div>
  )
}

export function StatusBadge({
  tone,
  children,
}: {
  tone: "positive" | "negative" | "neutral"
  children: ReactNode
}) {
  return (
    <Badge variant="outline" className="status-badge" data-tone={tone}>
      <span className="status-dot" aria-hidden="true" />
      {children}
    </Badge>
  )
}

export function RecordTime({
  value,
  compact = false,
}: {
  value: string
  compact?: boolean
}) {
  const date = new Date(value)
  const full = date.toLocaleString("zh-CN", { hour12: false })
  return (
    <time className="record-time" dateTime={value} title={full}>
      {compact
        ? date.toLocaleString("zh-CN", {
            month: "2-digit",
            day: "2-digit",
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
            hour12: false,
          })
        : full}
    </time>
  )
}
