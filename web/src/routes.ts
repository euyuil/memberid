export type View = "organization" | "members" | "providers" | "events"

export type Route = {
  view?: View
  org?: string
  member?: string
  q?: string
  status?: string
  administrator?: string
  after?: string
  before?: string
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
    /^(?:\/(organizations|members|providers|events)|\/organizations\/([A-Za-z0-9_-]+)(?:\/(members|providers|events)(?:\/([A-Za-z0-9_-]+))?)?)$/.exec(
      path
    )
  if (!match || (match[4] && match[3] !== "members")) return null
  return {
    root: false,
    view: (match[3] ||
      (match[1] === "organizations" ? "organization" : match[1]) ||
      "organization") as View,
    org: match[2] ?? "",
    member: match[4] ?? "",
    query,
  }
}

export function memberListLocation(value: unknown): string | undefined {
  if (typeof value !== "string") return
  const route = parseRoute(value)
  if (route?.view === "members" && !route.member) return value
}
