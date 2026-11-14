import { useState, type ReactNode } from "react"
import { Copy } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"

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
        {id && <RecordIdentifier value={id} label={name} />}
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
  const compact =
    value.length > 20 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value
  return (
    <Dialog onOpenChange={() => setFeedback("")}>
      <DialogTrigger
        className="record-id"
        title={value}
        aria-label={`查看 ${label} 的完整 ID`}
      >
        <code>{compact}</code>
        <Copy aria-hidden="true" />
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>完整 ID</DialogTitle>
          <DialogDescription>{label}</DialogDescription>
        </DialogHeader>
        <Input
          aria-label="完整 ID"
          value={value}
          readOnly
          onFocus={(event) => event.currentTarget.select()}
        />
        <p className="identifier-feedback" role="status">
          {feedback || "可复制完整 ID，或选中文本手动复制。"}
        </p>
        <DialogFooter>
          <Button
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
            <Copy data-icon="inline-start" />
            复制完整 ID
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
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
