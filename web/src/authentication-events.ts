export type AuthenticationEvent = {
  eventId: string
  type: string
  outcome: string
  occurredAt: string
  recordedAt: string
  reasonCode?: string
  actor?: { kind: string; id: string }
  organizationId?: string
  memberId?: string
  clientId?: string
  factorId?: string
  bindingId?: string
  sessionId?: string
  grantId?: string
  providerId?: string
  requestId?: string
  interactionId?: string
  causationId?: string
  method?: string
  purpose?: string
  trigger?: string
}

export const eventTypes: Record<string, string> = {
  "sms.send": "短信发送",
  "authentication.verify": "认证验证",
  "oidc.grant.issue": "授权发放",
  "saml.request": "SAML 登录请求",
  "saml.assertion.issue": "SAML 断言签发",
  "saml.request.reuse": "SAML 请求重复使用",
  "oidc.authorizationCode.reuse": "授权码重复使用",
  "oidc.refreshToken.reuse": "刷新令牌重复使用",
  "session.revoke": "会话撤销",
  "grant.revoke": "授权撤销",
}
export const eventOutcomes: Record<string, string> = {
  succeeded: "成功",
  rejected: "拒绝",
  failed: "失败",
  detected: "已检测",
}
export const eventMethods: Record<string, string> = {
  sms: "短信",
  dingtalk: "钉钉",
  feishu: "飞书",
}
export const eventFilterKeys = [
  "type",
  "outcome",
  "method",
  "memberId",
  "clientId",
  "grantId",
  "requestId",
  "interactionId",
  "from",
  "to",
] as const

export function authenticationEventQuery(
  params: URLSearchParams
): URLSearchParams {
  const query = new URLSearchParams()
  for (const key of [...eventFilterKeys, "after"])
    if (params.get(key)) query.set(key, params.get(key)!)
  return query
}

export function authenticationEventPath(org: string): string {
  return `${org ? `/organizations/${encodeURIComponent(org)}` : ""}/authentication-events`
}

export function authenticationEventLocation(
  org: string,
  params = new URLSearchParams()
): string {
  const query = authenticationEventQuery(params)
  return authenticationEventPath(org) + (query.size ? `?${query}` : "")
}

// Correlation is a new query in the selected view, never a global traversal.
export function correlationLocation(
  org: string,
  key: "requestId" | "interactionId",
  value: string
): string {
  return authenticationEventLocation(org, new URLSearchParams({ [key]: value }))
}

export function localEventTime(value: string): string {
  const date = new Date(value)
  if (!value || Number.isNaN(date.getTime())) return ""
  const pad = (n: number) => String(n).padStart(2, "0")
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}

export type AuthenticationEventPage = {
  items: AuthenticationEvent[]
  nextAfter?: string
  organizationNames: Record<string, string>
}
