import type { ReactNode } from "react"
import { Badge } from "@/components/ui/badge"

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
  id,
  icon,
  href,
}: {
  name: string
  id?: string
  icon?: ReactNode
  href?: string
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
          <a className="record-name" href={href}>
            {name}
          </a>
        ) : (
          <span className="record-name">{name}</span>
        )}
        {id && (
          <code className="record-id" title={id}>
            {id}
          </code>
        )}
      </div>
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
      <span>{date.toLocaleDateString("zh-CN")}</span>
      <span>{date.toLocaleTimeString("zh-CN", { hour12: false })}</span>
    </time>
  )
}
