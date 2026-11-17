import { useEffect, useState, type ReactNode } from "react"
import { Check, Copy } from "lucide-react"
import accessDenied from "@/assets/directory-states/access-denied.webp"
import emptyDirectory from "@/assets/directory-states/empty.webp"
import loadFailed from "@/assets/directory-states/load-failed.webp"
import noMatches from "@/assets/directory-states/no-matches.webp"
import {
  Empty,
  EmptyContent,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput,
} from "@/components/ui/input-group"

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

export function RecordIdentifier({
  value,
  label,
}: {
  value: string
  label: string
}) {
  const [copyResult, setCopyResult] = useState<{
    status: "idle" | "copying" | "copied" | "failed"
  }>({ status: "idle" })

  useEffect(() => {
    if (copyResult.status !== "copied") return
    const timeout = window.setTimeout(
      () => setCopyResult({ status: "idle" }),
      2000
    )
    return () => window.clearTimeout(timeout)
  }, [copyResult])

  return (
    <div className="min-w-0">
      <InputGroup>
        <InputGroupInput
          aria-label={label}
          className="h-full rounded-s-[calc(var(--radius)-1px)] bg-input/50 dark:bg-input/80"
          value={value}
          readOnly
          onFocus={(event) => event.currentTarget.select()}
        />
        <InputGroupAddon
          align="inline-end"
          className="h-full px-0.75 py-0 has-[>button]:mr-0"
        >
          <InputGroupButton
            size="icon-xs"
            aria-label={`复制${label}`}
            disabled={copyResult.status === "copying"}
            onClick={async () => {
              setCopyResult({ status: "copying" })
              try {
                await navigator.clipboard.writeText(value)
                setCopyResult({ status: "copied" })
              } catch {
                setCopyResult({ status: "failed" })
              }
            }}
          >
            {copyResult.status === "copied" ? (
              <Check
                aria-hidden="true"
                className="text-green-600 dark:text-green-400"
              />
            ) : (
              <Copy aria-hidden="true" />
            )}
          </InputGroupButton>
        </InputGroupAddon>
      </InputGroup>
      <p className="identifier-feedback" role="status">
        {copyResult.status === "failed" &&
          "无法自动复制，请选中上方内容手动复制。"}
        {copyResult.status === "copied" && (
          <span className="sr-only">已复制</span>
        )}
      </p>
    </div>
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
