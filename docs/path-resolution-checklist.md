# Path resolution on `npx trigger.dev deploy` — the checklist I work through

This is the diagnostic order I will run against your repo once the config lands.
Nothing here is a claim about your setup yet — it is the list of things that
produce "could not resolve", "module not found" or a silent empty bundle when
esbuild meets `tsconfig` path aliases, roughly in order of how often each one is
the actual culprit.

---

### 1. Which `tsconfig.json` is esbuild actually reading?

esbuild picks up the `tsconfig.json` nearest to each **source file**, not the one
nearest your shell. In a monorepo where the aliases are declared only in the root
config and the task files live in `packages/jobs/` with their own thinner
`tsconfig.json`, the leaf config wins and the aliases simply are not in scope.

Check: does the config nearest the task files declare `baseUrl` and `paths`
itself?

### 2. `baseUrl` inherited through `extends` points at the wrong directory

The trap that catches most monorepos. Every relative path in a tsconfig is
resolved **relative to the file it is written in** — so if `baseUrl: "."` lives
in a shared `@acme/tsconfig/base.json`, it resolves to
`node_modules/@acme/tsconfig/`, and the `paths` hanging off it point into that
package rather than into your source tree.

Symptom: the aliases resolve fine in your editor (the language service is more
forgiving about how it walks the project) and fail in the bundler.

Fixes, best first:
- declare `baseUrl` + `paths` in the leaf config that the task files sit under
- or on TypeScript 5.5+, use the `${configDir}` template variable in the shared
  base so it expands relative to the *inheriting* config:
  `"baseUrl": "${configDir}"`, `"paths": { "@/*": ["${configDir}/src/*"] }`

### 3. The alias resolves, but the target is `external`

Anything listed in `build.external` (or auto-externalised as a native/CJS
package) is **not** bundled, so the import specifier survives verbatim into the
deployed output — and Node at runtime has never heard of tsconfig `paths`. It
fails at import time in the container with `ERR_MODULE_NOT_FOUND`, which reads
like a deploy problem but is a config problem.

Rule: aliases may only ever point at code that gets bundled. External entries
must be real, installable package names.

### 4. Extensionless relative imports in an ESM output

With `"type": "module"`, Node requires explicit extensions. esbuild adds them
while bundling, so `import { x } from './lib/x'` is fine *if* that file is
bundled — and blows up the moment it isn't. The durable fix is to write the
extension in the source:

- `allowImportingTsExtensions` lets you write `./lib/x.ts`
- `rewriteRelativeImportExtensions` (TypeScript 5.7+) rewrites `.ts` → `.js` on
  emit, so the same source works under a bundler, under `tsc`, and under Node's
  own type stripping

That is exactly how this repo is written — every relative import carries its
extension, which is why `npm test` runs with no build step at all.

### 5. Case sensitivity

`import '@/lib/Storage'` against a file called `storage.ts` works on macOS and
Windows and fails in the Linux build container. Classic "it deploys from my
machine but not from a fresh clone". Worth a pass with a case-sensitive check
even when everything else looks right.

### 6. Task discovery vs. import graph

`dirs` in `trigger.config.ts` controls which files are scanned for exported
tasks. A file outside those directories is only included if something inside
them imports it. A task that "disappeared" from the deploy usually moved, or is
reached only through an alias that failed silently at step 1 or 2.

### 7. Symlinked workspaces

pnpm and npm workspaces symlink packages into `node_modules`. Resolution that
walks through the symlink to the real path can land on a different
`tsconfig.json` than the one you expect — which loops back to check 1 from a
different direction.

---

### What I need to run this

- `trigger.config.ts`
- every `tsconfig.json` in the `extends` chain, leaf to root
- `package.json` (root + per-package), plus `pnpm-workspace.yaml` / `turbo.json`
- the **full** `npx trigger.dev deploy` output, warnings included — the warnings
  usually name the file whose config lost the alias, and that is the fastest
  path to the answer
- one or two task files showing the aliased imports
- the directory tree, real depth and real folder names

The deliverable at the end is a `deploy.sh` that runs clean from a fresh clone,
plus a short note on which of the above was the cause, so it does not come back.
