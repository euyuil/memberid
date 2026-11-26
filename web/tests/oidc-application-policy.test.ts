import assert from "node:assert/strict"
import { test } from "node:test"
import { evidencePolicyError } from "../src/oidc-application-policy.ts"

test("Member evidence requires a custom scope and exact resource audience together", () => {
  const scope = "member:evidence"
  const resource = "https://api.example.test/reports"
  assert.equal(evidencePolicyError("", "", false), "")
  assert.equal(evidencePolicyError(scope, resource, false), "")
  for (const [name, audience] of [
    [scope, ""],
    ["", resource],
    ["profile", resource],
    ["Member Evidence", resource],
    [scope, resource + "?"],
    [scope, resource + "?tenant=one"],
    [scope, resource + "#fragment"],
    [scope, "https://user@api.example.test"],
    [scope, "https://*.example.test"],
    [scope, "https:///reports"],
    [scope, "http://api.example.test"],
  ]) {
    assert.ok(evidencePolicyError(name, audience, false))
  }
})

test("HTTP evidence audiences require the configured loopback exception", () => {
  const loopback = "http://127.0.0.1:8080/resource"
  assert.ok(evidencePolicyError("example", loopback, false))
  assert.equal(evidencePolicyError("example", loopback, true), "")
  assert.ok(evidencePolicyError("example", "http://localhost/resource", true))
})
