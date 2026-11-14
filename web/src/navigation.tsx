import type { ComponentProps } from "react"
import { routeURL, type Route } from "./routes"

export type NavigationState = { memberList?: string }

export function currentLocation() {
  return window.location.pathname + window.location.search
}

export function navigate(
  destination: Route | string,
  options: { replace?: boolean; state?: NavigationState } = {}
) {
  const href =
    typeof destination === "string" ? destination : routeURL(destination)
  if (href === currentLocation() && !options.replace) return
  window.history[options.replace ? "replaceState" : "pushState"](
    options.state ?? null,
    "",
    href
  )
  window.dispatchEvent(new PopStateEvent("popstate"))
}

export function Link({
  href,
  state,
  onClick,
  ...props
}: ComponentProps<"a"> & { href: string; state?: NavigationState }) {
  return (
    <a
      {...props}
      href={href}
      onClick={(event) => {
        onClick?.(event)
        if (
          event.defaultPrevented ||
          event.button !== 0 ||
          event.metaKey ||
          event.ctrlKey ||
          event.shiftKey ||
          event.altKey ||
          (props.target && props.target !== "_self") ||
          props.download != null
        )
          return
        event.preventDefault()
        navigate(href, { state })
      }}
    />
  )
}
