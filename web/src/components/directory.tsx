import { useState, type ReactNode } from "react"
import { Copy } from "lucide-react"
import { Badge } from "@/components/ui/badge"
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
  children,
}: {
  count: number
  children?: ReactNode
}) {
  return (
    <div className="directory-footer">
      <span className="directory-count">本页 {count} 条记录</span>
      <div className="pagination">{children}</div>
    </div>
  )
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

export function RecordTime({ value }: { value: string }) {
  const date = new Date(value)
  return (
    <time className="record-time" dateTime={value}>
      {date.toLocaleString("zh-CN", { hour12: false })}
    </time>
  )
}
