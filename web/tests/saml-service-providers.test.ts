import assert from "node:assert/strict"
import { test } from "node:test"
import {
  registrationInput,
  signingCertificates,
} from "../src/saml-service-providers.ts"
import type { SAMLServiceProvider } from "../src/saml-service-providers.ts"
import { routeURL, parseRoute } from "../src/routes.ts"
import { describeEvent } from "../src/operation-history.ts"

test("certificate input preserves complete blocks and rejects extra material", () => {
  const certificate =
    "-----BEGIN CERTIFICATE-----\nsynthetic-public-certificate\n-----END CERTIFICATE-----"
  assert.deepEqual(
    signingCertificates(`  ${certificate}\n\n${certificate}\n`),
    [certificate, certificate]
  )
  assert.deepEqual(signingCertificates(""), [])
  for (const invalid of [
    certificate + "PRIVATE KEY",
    certificate.replace("END CERTIFICATE", "END KEY"),
    Array(5).fill(certificate).join("\n"),
  ])
    assert.throws(() => signingCertificates(invalid))
})

test("registration edits preserve an explicit legacy NameID format", () => {
  const item: SAMLServiceProvider = {
    id: "legacy-sp",
    displayName: "Legacy app",
    organizationId: "org_example",
    entityId: "https://sp.example.test/metadata",
    acsUrl: "https://sp.example.test/acs",
    nameIdFormat: "unspecified",
    enabled: false,
    allowUnsignedRequests: true,
    signingCertificates: null,
    preauthorized: false,
    attributes: null,
    revision: 2,
    retired: false,
  }
  assert.equal(registrationInput(item).nameIdFormat, "unspecified")
})

test("SAML directory links retain scope, cursor and selected registration", () => {
  const url = routeURL({
    view: "saml-service-providers",
    org: "org_example",
    after: "first-sp",
    serviceProvider: "selected-sp",
  })
  const route = parseRoute(url)
  assert.equal(route?.view, "saml-service-providers")
  assert.equal(route?.org, "org_example")
  assert.equal(route?.query.get("after"), "first-sp")
  assert.equal(route?.query.get("serviceProviderId"), "selected-sp")
  assert.equal(parseRoute("/saml-service-providers")?.org, "")
  assert.equal(
    parseRoute("/organizations/org_example/saml-service-providers/arbitrary"),
    null
  )
})

test("SAML history describes retirement and routes to the registered application", () => {
  const result = describeEvent({
    id: 1,
    actor: "installation-manager",
    organizationId: "org_example",
    memberId: "",
    action: "saml.serviceProvider.configure",
    changes: { id: "example", retired: true, enabled: false, revision: 3 },
    previous: { enabled: true, revision: 2 },
    snapshot: { targetName: "Example application" },
    createdAt: "2026-11-15T00:00:00Z",
  })
  assert.equal(result.action, "退役 SAML 应用")
  assert.equal(result.targetName, "Example application")
  assert.equal(
    result.targetURL,
    "/organizations/org_example/saml-service-providers?serviceProviderId=example"
  )
})
