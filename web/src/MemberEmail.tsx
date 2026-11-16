import { useState, type FormEvent } from "react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import {
  Card,
  CardContent,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
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

export type ManagedEmail = {
  address: string
  source: "administrator"
  mailboxVerified: false
  revision: number
  updatedBy: string
  updatedAt: string | null
}

export function MemberEmail({
  email,
  save,
  onComplete,
}: {
  email: ManagedEmail
  save: (input: { address: string; revision: number }) => Promise<ManagedEmail>
  onComplete: () => void
}) {
  const [open, setOpen] = useState(false)
  const [address, setAddress] = useState("")
  const [revision, setRevision] = useState(0)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState("")

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (pending) return
    setPending(true)
    setError("")
    try {
      await save({ address, revision })
      setOpen(false)
      onComplete()
    } catch (error) {
      setError((error as Error).message)
    } finally {
      setPending(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle role="heading" aria-level={2}>
          受管邮箱
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-2">
        <span className="break-all">{email.address || "未设置"}</span>
        {email.address && (
          <div className="flex flex-wrap gap-2">
            <Badge variant="secondary">管理员维护</Badge>
            <Badge variant="outline">未验证邮箱所有权</Badge>
          </div>
        )}
      </CardContent>
      <CardFooter>
        <Dialog
          open={open}
          onOpenChange={(next) => {
            if (pending) return
            if (next) {
              setAddress(email.address)
              setRevision(email.revision)
              setError("")
            }
            setOpen(next)
          }}
        >
          <DialogTrigger render={<Button variant="outline" />}>
            {email.address ? "修改邮箱" : "设置邮箱"}
          </DialogTrigger>
          <DialogContent showCloseButton={!pending}>
            <form onSubmit={submit} className="flex flex-col gap-4">
              <DialogHeader>
                <DialogTitle>设置受管邮箱</DialogTitle>
                <DialogDescription>
                  修改或清除邮箱可能影响应用中的账号关联。请先确认目标邮箱及下游影响。
                </DialogDescription>
              </DialogHeader>
              <FieldGroup>
                <Field data-disabled={pending}>
                  <FieldLabel htmlFor="member-email">邮箱地址</FieldLabel>
                  <Input
                    id="member-email"
                    type="email"
                    autoComplete="off"
                    maxLength={254}
                    value={address}
                    disabled={pending}
                    onChange={(event) => setAddress(event.target.value)}
                  />
                </Field>
              </FieldGroup>
              <div className="form-feedback" role="alert">
                {error}
              </div>
              <DialogFooter>
                <Button
                  type="button"
                  variant="outline"
                  disabled={pending}
                  onClick={() => setOpen(false)}
                >
                  取消
                </Button>
                <Button
                  type="submit"
                  disabled={pending || address === email.address}
                >
                  {pending ? "保存中…" : address ? "保存" : "清除邮箱"}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </CardFooter>
    </Card>
  )
}
