import assert from "node:assert/strict"
import { test } from "node:test"
import { memberListLocation, parseRoute, routeURL } from "../src/routes.ts"

test("page paths identify resources independently of query parameters", () => {
  for (const [path, view, org, member] of [
    ["/organizations", "organization", "", ""],
    ["/members", "members", "", ""],
    ["/providers", "providers", "", ""],
    ["/events", "events", "", ""],
    ["/organizations/org_example", "organization", "org_example", ""],
    ["/organizations/org_example/members", "members", "org_example", ""],
    [
      "/organizations/org_example/members/mbr_example",
      "members",
      "org_example",
      "mbr_example",
    ],
    ["/organizations/org_example/providers", "providers", "org_example", ""],
    ["/organizations/org_system/events", "events", "org_system", ""],
  ]) {
    const route = parseRoute(
      `${path}?org=org_other&view=events&member=mbr_other`
    )
    assert.ok(route)
    assert.deepEqual([route.view, route.org, route.member], [view, org, member])
    assert.equal(routeURL(route), path)
  }
  assert.equal(parseRoute("/")?.root, true)
})

test("only supported pages are routes", () => {
  for (const path of [
    "/unknown",
    "/members/mbr_example",
    "/organizations/org_example/unknown",
    "/organizations/org_example/events/id",
    "/organizations/org_example/providers/id",
    "/organizations/",
    "//members",
    "/organizations/org_example/members/id/extra",
    "/api/members",
    "/auth/login",
    "/assets/app.js",
    "/organizations/%2Fexample",
  ])
    assert.equal(parseRoute(path), null, path)
})

test("list filters are encoded, while details have one canonical resource address", () => {
  const list = {
    view: "members" as const,
    q: "姓名 & a?b",
    status: "active",
    administrator: "yes",
    after: "mbr_cursor",
  }
  const route = parseRoute(routeURL(list))!
  assert.equal(route.query.get("q"), list.q)
  assert.equal(route.query.get("after"), list.after)
  assert.equal(parseRoute("/members?q=a?b")?.query.get("q"), "a?b")
  assert.equal(
    routeURL({ ...list, org: "org_example", member: "mbr_example" }),
    "/organizations/org_example/members/mbr_example"
  )
  const events = routeURL({
    ...list,
    view: "events",
    org: "org_example",
    target: "mbr_example",
    before: "42",
  })
  assert.equal(
    events,
    "/organizations/org_example/events?memberId=mbr_example&before=42"
  )
})

test("return navigation accepts member lists with filters, not arbitrary destinations", () => {
  for (const list of [
    "/members?q=Alice&after=mbr_cursor",
    "/organizations/org_example/members?status=blocked",
  ])
    assert.equal(memberListLocation(list), list)
  for (const value of [
    null,
    42,
    "/organizations",
    "/organizations/org_example/members/mbr_example",
    "https://example.invalid/members",
    "//example.invalid/members",
  ])
    assert.equal(memberListLocation(value), undefined)
})
