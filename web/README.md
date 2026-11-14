# MemberID console frontend

React and TypeScript with shadcn/ui Base Nova components, built using Vite and Tailwind CSS. This is the personal administration console, served by `memberid serve-console` using its own OIDC-backed session and same-origin API.

From the repository root, use Node.js 26.13.1 LTS and npm 11.20.0:

```sh
npm --prefix web ci
npm --prefix web run lint
npm --prefix web test
npm --prefix web run build
```

The build writes ignored assets to `internal/console/static/`, which the Go executable embeds. Rebuild Go and restart the console to inspect a changed production bundle. Vite's development server alone has no management API or login session; use the documented [disposable browser fixture](../docs/console.md#validation) for end-to-end inspection. The nested `go.mod` only prevents `go test ./...` from traversing npm packages containing unrelated Go examples; the frontend has no Go implementation or runtime dependency.

`components.json` records the registry/style configuration. Add components using the locked shadcn CLI from this directory (`npm exec shadcn -- add COMPONENT`), inspect the resulting code, and update the dependency/license inventory for any new material. Keep browser-visible fields and action areas stable during validation and requests. Use the repository [contributor guide](../CONTRIBUTING.md) and [console setup](../docs/console.md) for the complete build and authentication model.
