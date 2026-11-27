export type View =
  | "organization"
  | "members"
  | "providers"
  | "oidc-applications"
  | "saml-service-providers"
  | "events"
  | "authentication-events"

export type Route = {
  view?: View
  org?: string
  member?: string
  q?: string
  status?: string
  administrator?: string
  after?: string
  before?: string
  oidcUse?: boolean
  join?: string
  provider?: string
  serviceProvider?: string
  target?: string
}

export function routeURL(route: Route): string {
  const { view = "organization", org, member } = route
  let path = org ? `/organizations/${encodeURIComponent(org)}` : ""
  if (view === "organization") path ||= "/organizations"
  else path += `/${view}`
  if (view === "members" && org && member)
    path += `/${encodeURIComponent(member)}`

  const query = new URLSearchParams()
  if (view === "members" && !member) {
    for (const key of ["q", "status", "administrator", "after"] as const)
      if (route[key]) query.set(key, route[key])
  } else if (view === "oidc-applications") {
    if (route.join) query.set("join", route.join)
    else if (org && route.oidcUse) query.set("tab", "used")
  } else if (view === "providers" && org) {
    if (route.provider) query.set("providerId", route.provider)
  } else if (view === "saml-service-providers") {
    if (route.after) query.set("after", route.after)
    if (org && route.serviceProvider)
      query.set("serviceProviderId", route.serviceProvider)
  } else if (view === "events") {
    if (route.target) query.set("memberId", route.target)
    if (route.before) query.set("before", route.before)
  } else if (!org && route.after) query.set("after", route.after)
  return path + (query.size ? `?${query}` : "")
}

export function parseRoute(location: string) {
  const separator = location.indexOf("?")
  const path = separator < 0 ? location : location.slice(0, separator)
  const search = separator < 0 ? "" : location.slice(separator + 1)
  const query = new URLSearchParams(search)
  if (path === "/")
    return {
      root: true,
      view: "organization" as View,
      org: "",
      member: "",
      query,
    }
  const match =
    /^(?:\/(organizations|members|providers|oidc-applications|saml-service-providers|events|authentication-events)|\/organizations\/([A-Za-z0-9_-]+)(?:\/(members|providers|oidc-applications|saml-service-providers|events|authentication-events)(?:\/([A-Za-z0-9_-]+))?)?)$/.exec(
      path
    )
  if (!match || (match[4] && match[3] !== "members")) return null
  const view = (match[3] ||
    (match[1] === "organizations" ? "organization" : match[1]) ||
    "organization") as View
  return {
    root: false,
    view,
    org: match[2] ?? "",
    member: match[4] ?? "",
    query,
  }
}

export function isOrganizationDetail(route: Route): boolean {
  return (route.view ?? "organization") === "organization" && !!route.org
}

export function memberListLocation(value: unknown): string | undefined {
  if (typeof value !== "string") return
  const route = parseRoute(value)
  if (route?.view === "members" && !route.member) return value
}
