export type SAMLServiceProvider = {
  id: string
  displayName: string
  organizationId: string
  entityId: string
  acsUrl: string
  nameIdFormat: "persistent" | "unspecified"
  enabled: boolean
  allowUnsignedRequests: boolean
  signingCertificates: string[] | null
  preauthorized: boolean
  attributes: string[] | null
  revision: number
  retired: boolean
}

export type SAMLDirectory = {
  items: SAMLServiceProvider[]
  nextAfter?: string
}

// Reject extra material instead of silently discarding a private key or a
// damaged certificate block. The server validates the actual public keys.
export function signingCertificates(value: string): string[] {
  const certificates =
    value.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g
    ) ?? []
  const remainder = value
    .replace(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,
      ""
    )
    .trim()
  if (remainder || certificates.length > 4)
    throw new Error("请填写最多 4 个完整的 PEM 公共证书，不要填写私钥。")
  return certificates
}

export function registrationInput(item: SAMLServiceProvider) {
  const {
    id,
    displayName,
    entityId,
    acsUrl,
    nameIdFormat,
    enabled,
    allowUnsignedRequests,
    signingCertificates,
    preauthorized,
    attributes,
    revision,
  } = item
  return {
    id,
    displayName,
    entityId,
    acsUrl,
    nameIdFormat,
    enabled,
    allowUnsignedRequests,
    signingCertificates: signingCertificates ?? [],
    preauthorized,
    attributes: attributes ?? [],
    revision,
  }
}
