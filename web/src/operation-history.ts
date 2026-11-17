import { routeURL } from "./routes.ts"

export type ManagementEvent = {
  id: number
  actor: string
  organizationId: string
  memberId: string
  action: string
  changes: Record<string, unknown>
  previous?: Record<string, unknown>
  snapshot?: {
    actorName?: string
    organizationName?: string
    targetName?: string
  }
  createdAt: string
}

export function describeEvent(event: ManagementEvent) {
  const { action, changes, previous = {}, snapshot = {} } = event
  const operations: string[] = []
  const differences: string[] = []
  const field = (
    key: string,
    label: string,
    render: (value: unknown) => string | undefined
  ) => {
    const after = render(changes[key])
    if (after === undefined || changes[key] === previous[key]) return
    operations.push(label)
    const before = render(previous[key])
    differences.push(before === undefined ? after : `${before} → ${after}`)
  }
  const name = (value: unknown) =>
    typeof value === "string" ? value : undefined
  const enabled = (value: unknown) =>
    typeof value === "boolean" ? (value ? "启用" : "停用") : undefined
  let label = action
  switch (action) {
    case "organization.create":
      label = "创建组织"
      break
    case "member.create":
      label = "创建成员"
      break
    case "organization.update":
      label = "更新组织"
      field("name", "重命名", name)
      field(
        "status",
        changes.status === "enabled" ? "启用组织" : "停用组织",
        (value) =>
          value === "enabled"
            ? "启用"
            : value === "disabled"
              ? "停用"
              : undefined
      )
      break
    case "member.update":
      label = "更新成员"
      field("displayName", "重命名", name)
      field(
        "manualBlocked",
        changes.manualBlocked ? "封禁" : "解除封禁",
        (value) =>
          typeof value === "boolean" ? (value ? "封禁" : "未封禁") : undefined
      )
      break
    case "password.create":
      label = "创建密码凭据"
      break
    case "member.email.update":
      label = "更新受管邮箱"
      field("address", "修改邮箱", (value) =>
        typeof value === "string" ? value || "未设置" : undefined
      )
      break
    case "password.reset":
      label = "重置密码"
      break
    case "password.username.update":
      label = "修改登录用户名"
      break
    case "administrator.update":
      label = "管理员任免"
      field(
        "enabled",
        changes.enabled ? "授予管理员" : "撤销管理员",
        (value) =>
          typeof value === "boolean"
            ? value
              ? "管理员"
              : "普通成员"
            : undefined
      )
      break
    case "dingtalk.admission":
      label = "更新钉钉准入"
      field(
        "enabled",
        changes.enabled ? "设置钉钉准入" : "取消钉钉准入",
        (value) =>
          typeof value === "boolean" ? (value ? "已设置" : "未设置") : undefined
      )
      break
    case "binding.revoke":
      label = "撤销绑定"
      break
    case "oidc.application.create":
      label = "添加 OIDC 应用"
      break
    case "oidc.application.update":
      label = "编辑 OIDC 应用"
      break
    case "oidc.application.status.update":
      label = changes.enabled ? "启用 OIDC 应用" : "停用 OIDC 应用"
      field("enabled", label, enabled)
      break
    case "oidc.application.credential.rotate":
      label = "轮换 OIDC 应用密钥"
      break
    case "saml.nameId.provision":
      label = "预设 SAML NameID"
      break
    case "saml.serviceProvider.configure":
      label =
        changes.retired === true
          ? "退役 SAML 应用"
          : changes.revision === 1
            ? "添加 SAML 应用"
            : "配置 SAML 应用"
      if (changes.retired === true || changes.revision === 1) break
      field("displayName", "重命名 SAML 应用", name)
      field("acsUrl", "更新 ACS", name)
      field("nameIdFormat", "更新 NameID 格式", name)
      field(
        "enabled",
        changes.enabled ? "启用 SAML 应用" : "停用 SAML 应用",
        enabled
      )
      field("allowUnsignedRequests", "更新请求签名策略", (value) =>
        typeof value === "boolean"
          ? value
            ? "允许未签名"
            : "必须签名"
          : undefined
      )
      field("preauthorized", "更新授权确认策略", (value) =>
        typeof value === "boolean"
          ? value
            ? "跳过确认"
            : "用户确认"
          : undefined
      )
      for (const [key, text] of [
        ["signingCertificates", "更新 SP 签名证书"],
        ["attributes", "更新属性授权"],
      ]) {
        if (JSON.stringify(changes[key]) !== JSON.stringify(previous[key]))
          operations.push(text)
      }
      break
    case "provider.configure":
      label = changes.created === true ? "添加登录" : "配置登录"
      if (changes.created === true) {
        const state = enabled(changes.enabled)
        if (state) differences.push(state)
        break
      }
      field("displayName", "重命名", name)
      field("enabled", changes.enabled ? "启用登录" : "停用登录", enabled)
      field("authorizationStatus", "更新授权", (value) =>
        value === "active"
          ? "已授权"
          : value === "revoked"
            ? "已撤权"
            : undefined
      )
      if (changes.credentialsUpdated === true) {
        operations.push("更新凭据")
        differences.push("凭据已更新")
      }
      break
  }
  const provider = action === "provider.configure"
  const oidc = action.startsWith("oidc.application.")
  const saml = action === "saml.serviceProvider.configure"
  const providerId =
    provider && typeof changes.providerId === "string"
      ? changes.providerId
      : undefined
  const recordedName =
    action === "organization.create" || action === "organization.update"
      ? name(changes.name)
      : action === "member.create" ||
          action === "member.update" ||
          provider ||
          saml ||
          oidc
        ? name(changes.displayName)
        : undefined
  return {
    action: operations.join("、") || label,
    changes: differences,
    actorName:
      event.actor === "installation-operator"
        ? "安装运维"
        : event.actor === "installation-manager"
          ? "集成管理服务"
          : snapshot.actorName || "姓名未记录",
    organizationName: snapshot.organizationName || "组织名称未记录",
    targetName: snapshot.targetName || recordedName || "名称未记录",
    targetURL: oidc
      ? routeURL({ view: "oidc-applications" })
      : saml
        ? routeURL({
            org: event.organizationId,
            view: "saml-service-providers",
            serviceProvider: name(changes.id),
          })
        : provider
          ? providerId
            ? routeURL({
                org: event.organizationId,
                view: "providers",
                provider: providerId,
              })
            : undefined
          : routeURL({
              org: event.organizationId,
              view: event.memberId ? "members" : "organization",
              member: event.memberId,
            }),
    providerId,
  }
}
