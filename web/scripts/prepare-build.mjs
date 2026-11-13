import { mkdir, rm } from "node:fs/promises"

// Only Vite's generated assets are replaced; the tracked embed placeholder stays.
const output = new URL("../../internal/console/static/", import.meta.url)
await mkdir(output, { recursive: true })
await rm(new URL("assets/", output), { recursive: true, force: true })
await rm(new URL("index.html", output), { force: true })
await rm(new URL("vite.svg", output), { force: true })
