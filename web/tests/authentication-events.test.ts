import assert from "node:assert/strict"
import { test } from "node:test"
import {
  authenticationEventQuery,
  authenticationEventLocation,
  correlationLocation,
  localEventTime,
} from "../src/authentication-events.ts"

test("event queries preserve supported filters without allowing query-selected scope", () => {
  const params = new URLSearchParams(
    "type=sms.send&outcome=failed&method=sms&requestId=a%3Ab&interactionId=t&memberId=mbr_example&clientId=client&grantId=grant&from=2026-01-01T00%3A00%3A00Z&to=2026-01-02T00%3A00%3A00Z&after=cursor&organizationId=foreign&limit=100000"
  )
  const query = authenticationEventQuery(params)
  assert.equal(query.size, 11)
  assert.equal(query.get("requestId"), "a:b")
  assert.equal(query.has("organizationId"), false)
  assert.equal(query.has("limit"), false)
  const url = new URL(
    authenticationEventLocation("org_local", params),
    "https://admin.example.invalid"
  )
  assert.equal(url.pathname, "/organizations/org_local/authentication-events")
  assert.equal(url.searchParams.get("after"), "cursor")
})

test("correlation starts within the same view and clears unrelated filters and pagination", () => {
  assert.equal(
    correlationLocation("org_local", "requestId", "shared:request"),
    "/organizations/org_local/authentication-events?requestId=shared%3Arequest"
  )
  assert.equal(
    correlationLocation("", "interactionId", "flow"),
    "/authentication-events?interactionId=flow"
  )
})

test("local filter time preserves the instant with an explicit conversion back to UTC", () => {
  const instant = "2026-11-15T12:34:56Z"
  assert.equal(
    new Date(localEventTime(instant)).toISOString(),
    "2026-11-15T12:34:56.000Z"
  )
  assert.equal(localEventTime("invalid"), "")
  assert.equal(localEventTime(""), "")
})
