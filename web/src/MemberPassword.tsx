import { useEffect, useRef, useState, type FormEvent } from "react"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import {
  passwordUsernameError,
  passwordUsernamePattern,
} from "@/member-password"

type GeneratedPassword = { username: string; password: string }

export function MemberPassword({
  configured,
  assignedUsername,
  generate,
  onComplete,
}: {
  assignedUsername?: string
  configured: boolean
  generate: (username?: string) => Promise<GeneratedPassword>
  onComplete: () => void
}) {
  const [open, setOpen] = useState(false)
  const [username, setUsername] = useState("")
  const [pending, setPending] = useState(false)
  const [error, setError] = useState("")
  const [result, setResult] = useState<GeneratedPassword>()
  const [copyFeedback, setCopyFeedback] = useState("")
  const done = useRef<HTMLButtonElement>(null)
  const cancel = useRef<HTMLButtonElement>(null)
  const usernameInput = useRef<HTMLInputElement>(null)
  const title = configured ? "重置登录密码" : "设置登录密码"

  useEffect(() => {
    if (result) done.current?.focus()
  }, [result])

  function close() {
    setOpen(false)
    setUsername("")
    setError("")
    setResult(undefined)
    setCopyFeedback("")
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (pending) return
    if (
      !configured &&
      !passwordUsernamePattern.test(assignedUsername ?? username)
    ) {
      setError(passwordUsernameError)
      return
    }
    setError("")
    setPending(true)
    try {
      setResult(
        await generate(configured ? undefined : (assignedUsername ?? username))
      )
    } catch (error) {
      setError((error as Error).message)
    } finally {
      setPending(false)
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(open) => {
        if (open) setOpen(true)
        else if (!pending && !result) close()
      }}
    >
      <DialogTrigger render={<Button variant="outline" />}>
        {title}
      </DialogTrigger>
      <DialogContent
        initialFocus={configured ? cancel : usernameInput}
        showCloseButton={!pending && !result}
      >
        <DialogHeader>
          <DialogTitle>{result ? "新密码已生成" : title}</DialogTitle>
          {(result || configured) && (
            <DialogDescription>
              {result
                ? "密码仅在此处显示一次。请先妥善保存。"
                : "旧密码将立即失效，已有的登录授权将被撤销。"}
            </DialogDescription>
          )}
        </DialogHeader>
        {result ? (
          <>
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="generated-username">用户名</FieldLabel>
                <Input
                  id="generated-username"
                  value={result.username}
                  readOnly
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="generated-password">新密码</FieldLabel>
                <Input
                  id="generated-password"
                  autoComplete="off"
                  value={result.password}
                  readOnly
                  onFocus={(event) => event.currentTarget.select()}
                />
              </Field>
            </FieldGroup>
            <div className="form-feedback" role="status">
              {copyFeedback}
            </div>
            <DialogFooter>
              <Button
                variant="outline"
                onClick={async () => {
                  try {
                    await navigator.clipboard.writeText(result.password)
                    setCopyFeedback("已复制密码。")
                  } catch {
                    setCopyFeedback("无法自动复制，请选中新密码手动复制。")
                  }
                }}
              >
                复制密码
              </Button>
              <Button
                ref={done}
                onClick={() => {
                  close()
                  onComplete()
                }}
              >
                完成
              </Button>
            </DialogFooter>
          </>
        ) : (
          <form onSubmit={submit}>
            {!configured && (
              <FieldGroup>
                <Field data-invalid={!!error}>
                  <FieldLabel htmlFor="password-username">用户名</FieldLabel>
                  <Input
                    ref={usernameInput}
                    id="password-username"
                    autoComplete="off"
                    autoCapitalize="none"
                    spellCheck={false}
                    value={assignedUsername ?? username}
                    readOnly={!!assignedUsername}
                    disabled={pending}
                    aria-invalid={!!error}
                    onChange={(event) => setUsername(event.target.value)}
                  />
                </Field>
              </FieldGroup>
            )}
            <div className="form-feedback" role="alert">
              {error}
            </div>
            <DialogFooter>
              <Button
                ref={cancel}
                type="button"
                variant="outline"
                disabled={pending}
                onClick={close}
              >
                取消
              </Button>
              <Button type="submit" disabled={pending}>
                {pending ? "正在生成…" : title}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}
