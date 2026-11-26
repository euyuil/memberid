export function isExactApplicationURL(
  value: string,
  allowLoopbackHttp: boolean
) {
  const authority = /^https?:\/\/([^/?#]+)/.exec(value)?.[1]
  if (!authority || authority.includes("@") || /[\s*#\\]/.test(value))
    return false
  const url = URL.parse(value)
  if (!url || url.port === "0") return false
  return (
    url.protocol === "https:" ||
    (allowLoopbackHttp && /^127\.0\.0\.1(?::\d+)?$/.test(authority))
  )
}

export function evidencePolicyError(
  scope: string,
  audience: string,
  allowLoopbackHttp: boolean
) {
  if (!scope && !audience) return ""
  if (!scope || !audience) return "请同时填写身份凭据范围和接收方，或同时留空。"
  if (
    [
      "openid",
      "profile",
      "email",
      "phone",
      "address",
      "offline_access",
    ].includes(scope)
  )
    return "该名称已由标准范围使用，请填写其他自定义范围名。"
  if (!/^[a-z][a-z0-9:_-]{0,127}$/.test(scope))
    return "请使用自定义范围名：以小写字母开头，最多 128 个字符，可包含小写字母、数字、冒号、下划线和连字符。"
  if (
    !isExactApplicationURL(audience, allowLoopbackHttp) ||
    audience.includes("?")
  )
    return "请填写接收身份凭据的资源 URL，使用完整的 HTTPS 地址，不含查询参数、片段、用户信息或通配符。"
  return ""
}
