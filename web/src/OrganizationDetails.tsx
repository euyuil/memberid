import { useState, type FormEvent } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { RecordIdentifier } from "@/components/directory"

export type Organization = {
  id: string
  name: string
  status: string
  slug?: string
}

export function OrganizationDetails({
  organization,
  canChangeStatus,
  canChangeSlug,
  onChangeSlug,
  save,
  onSaved,
  onStatusChange,
}: {
  organization: Organization
  canChangeSlug: boolean
  onChangeSlug: (slug: string) => void
  canChangeStatus: boolean
  save: (name: string) => Promise<Organization>
  onSaved: (organization: Organization) => void
  onStatusChange: () => void
}) {
  const [slug, setSlug] = useState(organization.slug ?? "")
  const [name, setName] = useState(organization.name)
  const [pending, setPending] = useState(false)
  const [invalid, setInvalid] = useState(false)
  const [error, setError] = useState("")
  const [saved, setSaved] = useState(false)
  const enabled = organization.status === "enabled"

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (pending || name === organization.name) return
    setError("")
    setSaved(false)
    if (!name.trim() || [...name].length > 128 || /\p{Cc}/u.test(name)) {
      setInvalid(true)
      setError("名称不能为空，最多 128 个字符，且不能包含控制字符。")
      return
    }
    setInvalid(false)
    setPending(true)
    try {
      const updated = await save(name)
      setName(updated.name)
      onSaved(updated)
      setSaved(true)
    } catch (error) {
      setError((error as Error).message)
    } finally {
      setPending(false)
    }
  }

  return (
    <Card className="max-w-2xl">
      <CardHeader>
        <CardTitle role="heading" aria-level={2}>
          组织资料
        </CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} noValidate aria-label="组织名称">
          <FieldGroup>
            <Field data-invalid={invalid} data-disabled={pending}>
              <FieldLabel htmlFor="organization-name">组织名称</FieldLabel>
              <div className="flex flex-wrap items-center gap-2">
                <Input
                  id="organization-name"
                  className="min-w-0 basis-full sm:w-auto sm:flex-1"
                  value={name}
                  disabled={pending}
                  aria-invalid={invalid}
                  aria-describedby="organization-name-feedback"
                  onChange={(event) => {
                    setName(event.target.value)
                    setInvalid(false)
                    setError("")
                    setSaved(false)
                  }}
                />
                <Button
                  type="submit"
                  className="ml-auto min-w-24"
                  disabled={pending || name === organization.name}
                >
                  {pending ? "正在保存…" : "保存"}
                </Button>
              </div>
            </Field>
          </FieldGroup>
          <div
            id="organization-name-feedback"
            className="min-h-16 py-3 text-sm text-muted-foreground"
            role={error ? "alert" : "status"}
          >
            {error ? (
              <span className="text-destructive">{error}</span>
            ) : saved ? (
              "已保存"
            ) : null}
          </div>
        </form>
        {canChangeSlug ? (
          <form
            className="mb-6"
            onSubmit={(event) => {
              event.preventDefault()
              onChangeSlug(slug.toLowerCase())
            }}
          >
            <Field>
              <FieldLabel htmlFor="organization-slug">组织登录名</FieldLabel>
              <div className="flex items-center gap-2">
                <Input
                  id="organization-slug"
                  value={slug}
                  required
                  pattern="[A-Za-z0-9]+(-[A-Za-z0-9]+)*"
                  maxLength={63}
                  onChange={(event) => setSlug(event.target.value)}
                />
                <Button
                  type="submit"
                  disabled={!slug || slug.toLowerCase() === organization.slug}
                >
                  {organization.slug ? "修改登录名" : "设置登录名"}
                </Button>
              </div>
            </Field>
          </form>
        ) : (
          <dl className="mb-6">
            <dt>组织登录名</dt>
            <dd>{organization.slug || "未设置"}</dd>
          </dl>
        )}
        <dl>
          <dt>组织 ID</dt>
          <dd>
            <RecordIdentifier value={organization.id} label="组织 ID" />
          </dd>
        </dl>
      </CardContent>
      <CardFooter className="flex-wrap justify-between gap-3">
        <div className="flex flex-wrap items-center gap-3">
          <span>组织状态</span>
          <Badge variant={enabled ? "secondary" : "destructive"}>
            {enabled ? "已启用" : "已停用"}
          </Badge>
        </div>
        {canChangeStatus && (
          <Button
            variant={enabled ? "destructive" : "outline"}
            disabled={pending}
            onClick={onStatusChange}
          >
            {enabled ? "停用组织" : "启用组织"}
          </Button>
        )}
      </CardFooter>
    </Card>
  )
}
