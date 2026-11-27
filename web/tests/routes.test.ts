import assert from "node:assert/strict"
import { test } from "node:test"
import {
  isOrganizationDetail,
  memberListLocation,
  parseRoute,
  routeURL,
} from "../src/routes.ts"

test("page paths identify resources independently of query parameters", () => {
  for (const [path, view, org, member] of [
    ["/organizations", "organization", "", ""],
    ["/members", "members", "", ""],
    ["/providers", "providers", "", ""],
    ["/oidc-applications", "oidc-applications", "", ""],
    ["/events", "events", "", ""],
    ["/authentication-events", "authentication-events", "", ""],
    [
      "/organizations/org_example/authentication-events",
      "authentication-events",
      "org_example",
      "",
    ],
    ["/organizations/org_example", "organization", "org_example", ""],
    ["/organizations/org_example/members", "members", "org_example", ""],
    [
      "/organizations/org_example/members/mbr_example",
      "members",
      "org_example",
      "mbr_example",
    ],
    ["/organizations/org_example/providers", "providers", "org_example", ""],
    [
      "/organizations/org_example/oidc-applications",
      "oidc-applications",
      "org_example",
      "",
    ],
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

test("OIDC application navigation retains the selected management scope", () => {
  const url = routeURL({ view: "oidc-applications", org: "org_example" })
  assert.equal(url, "/organizations/org_example/oidc-applications")
  const route = parseRoute(url)!
  assert.equal(route.view, "oidc-applications")
  assert.equal(route.org, "org_example")
  assert.equal(routeURL(route), url)
  assert.equal(routeURL({ view: "oidc-applications" }), "/oidc-applications")
  assert.equal(
    parseRoute("/oidc-applications?organizationId=org_example")?.org,
    ""
  )
})

test("a shared application link acquires only the signed-in organization scope", () => {
  const join = "app_example"
  const link = routeURL({ view: "oidc-applications", join })
  assert.equal(link, "/oidc-applications?join=app_example")
  const target = parseRoute(link)!
  assert.equal(target.org, "")
  assert.equal(target.query.get("join"), join)
  assert.equal(
    routeURL({ view: "oidc-applications", org: "org_example", used: true }),
    "/organizations/org_example/oidc-applications?tab=used"
  )
})

test("organization detail controls follow the page when navigating within a scope", () => {
  const org = "org_system"
  const detailURL = routeURL({ org })
  const appsURL = routeURL({ org, view: "oidc-applications" })
  for (const [url, expected] of [
    ["/organizations", false],
    [detailURL, true],
    [appsURL, false],
    [detailURL, true],
  ] as const) {
    const route = parseRoute(url)
    assert.ok(route)
    assert.equal(isOrganizationDetail(route), expected, url)
  }
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
