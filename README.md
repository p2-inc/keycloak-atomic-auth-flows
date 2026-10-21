# keycloak-atomic-auth-flows

Config as code solution to safely update Keycloak authentication flows.

Authentication flows are the highest-stakes configuration in a realm, and the admin
console and REST API only let you change them one execution at a time, each change
committing against a flow that is already bound and serving logins. This extension
registers an admin realm REST resource (`authentication-flow`) that imports a complete
set of authenticator configs, authentication flows and their bindings (browser, identity
provider first/post login, and per-client browser/direct grant overrides) in a single
atomic, transactional request: either the whole set is applied, or nothing is.

It has two modes for dealing with flows that already exist, selected per server or per
request (see [Import modes](#import-modes)):

- **versioned** (default) — every import creates a new, hash-prefixed set of flows and
  moves the bindings onto it. Previous versions stay in the realm for rollback.
- **replace** — flows keep the aliases from the payload and an existing flow is
  overwritten in place. Re-posting the same payload is a no-op, so the realm never
  drifts from what a config-as-code tool expects to find.

## Quick start

Try the extension end-to-end without installing a JDK, Maven, or Keycloak — just
Docker and Ruby. From the repo root:

```bash
# Build the extension and start Keycloak (dev mode) with it loaded, plus a
# minimal `demo` realm. Admin console: http://localhost:8080 (admin / admin)
docker compose up --build

# In another shell, import the demo authentication flows via the new endpoint:
ruby examples/scripts/update_auth_flows.rb
```

Then open the admin console → realm **demo** → *Authentication* to see the
imported flows and their bindings. The [`examples/`](examples/) directory is a
full config-as-code walkthrough — a per-realm flow **builder**, the generated
import payload, its human-readable rendering, a **validator**, and the update
script above. See [examples/README.md](examples/README.md).

## Usage

Once the JAR is deployed to a Keycloak server, the endpoint is available under the
realm admin API:

```
POST /admin/realms/{realm}/authentication-flow/import[?mode=versioned|replace][&force=true][&dryRun=true]
Content-Type: application/json
```

The caller must have the `manage-realm` permission. See `src/test/resources/json/`
for raw example payloads, or [`examples/`](examples/) for a config-as-code
toolchain that generates and applies them.

| Query parameter | Description |
| --- | --- |
| `mode` | `versioned` or `replace`. Overrides the server-wide default for this request. See [Import modes](#import-modes). |
| `force` | Versioned mode only. When omitted, an import whose flows already exist (same payload hash) is rejected with `409 Conflict`. `force=true` instead re-applies the flow bindings over the already-imported flows. Any other value is treated as `false`. Ignored in replace mode. |
| `dryRun` | `dryRun=true` validates and executes the whole import, then rolls it back. See [Dry run](#dry-run). |

## Import modes

### Versioned (default)

The server hashes the flows and configs in the payload and prefixes every flow and
config alias with that hash. An import never edits a flow that exists; it creates a
new, independently bindable set of flows and then moves the bindings onto it. The flow
that was serving traffic a moment ago is untouched and still in the realm, which gives
you:

- **Rollback by re-binding.** A previous version is still present under its own hash
  prefix with its executions and configs intact. Re-post that previous payload with
  `force=true` and its bindings are re-applied in one transaction.
- **Canary before promote.** Bind a new version as a per-client browser or direct grant
  override first, then import the same payload with the realm binding to promote it.
- **Duplicate detection.** Re-posting an identical payload returns `409 Conflict`
  instead of creating a second copy.

The trade-off is that old versions accumulate in the realm until someone removes them,
and the hash-prefixed aliases do not match what a tool such as Terraform or
keycloak-config-cli expects to find by name. That is what replace mode is for.

### Replace

Flows keep the plain aliases from the payload. For every flow in the payload:

- a flow that does not exist is created;
- a flow that exists keeps its **id** and gets its executions and subflows rebuilt
  from the payload. Bindings that point at that flow, including ones not mentioned in
  the payload (other realm bindings, other clients' overrides, other identity
  providers), keep resolving;
- subflows that hung off a replaced flow but are no longer in the payload are
  deleted, unless a flow outside the payload still uses them;
- authenticator configs are upserted by alias and never deleted, since other flows
  may share them.

Flows and configs in the realm that the payload does not mention are left alone.
Built-in flows are never touched: a payload that names one is rejected with `400`
and nothing is written.

Before writing, the import compares every flow and config in the payload with what the
realm has now: a flow's description, type, and executions (authenticator, requirement,
priority, subflow and config alias), and a config's values. Only flows and configs that
are missing or differ are written; the rest keep their ids. Re-posting an identical
payload is therefore a true no-op: nothing is rewritten and every flow and execution id
stays the same. The bindings are still (idempotently) re-applied. The response header
`X-Import-Result` says which happened: `applied` if anything was written, otherwise
`unchanged`. Because the comparison is against the realm itself, and nothing is stored
about previous imports, a flow edited in the admin console or through the admin API is
detected and rewritten by the next import of the payload.

As in versioned mode, everything happens in one transaction, and any error rolls back
the whole request with `400`, including the bindings.

#### Validation

Before anything is written, replace mode checks that the payload is complete and
consistent:

- every flow has a known `providerId` (`basic-flow`, `form-flow` or `client-flow`);
- every execution names an authenticator that is deployed on the server, looked up in the
  SPI its parent flow type uses (`Authenticator`, `FormAction` or `ClientAuthenticator`),
  and a valid requirement;
- every subflow and config an execution references is in the payload;
- the flows form a tree: a top-level flow is never used as a subflow, each subflow has
  exactly one parent, and every subflow is reachable from a top-level flow (so no
  orphans and no reference cycles).

It then checks the payload against what the realm already has:

- a built-in flow cannot be replaced;
- an existing flow cannot change between top-level and subflow;
- a flow that a flow outside the payload uses as a subflow cannot be replaced.

A subflow that is no longer in the payload is deleted only if no flow outside the
payload still uses it.

#### Logins in progress

Replacing a flow recreates all of its executions with new ids. A browser login that was
part way through the old flow (for example, it showed the username/password form) can't
continue: when the user submits, Keycloak no longer finds the execution the login was on
and restarts the flow from the beginning. This is deliberate. If you replace a flow to
require a second factor, a login that started before the change can't finish without it.

An identical re-post (`X-Import-Result: unchanged`) rewrites nothing, and a flow in the
payload that matches the realm keeps its executions even when other flows change, so
neither disturbs logins in progress on that flow. `ReplaceModeInFlightLoginTest` covers both cases.

### Dry run

Add `dryRun=true` to run the whole import, including validation and bindings, inside the
transaction and then roll it back. The response is what the real import would return:
the same status and errors, the same body, and in replace mode the same `X-Import-Result`
(`applied` means "would apply"). It also carries `X-Dry-Run: true`. This works in both
modes and is meant for CI checks on a pull request before you apply the change.

### Choosing the mode

| Scope | How | Example |
| --- | --- | --- |
| server-wide default | provider config, read at startup | `KC_SPI_ADMIN_REALM_RESTAPI_EXTENSION_AUTHENTICATION_FLOW_MODE=replace` or `--spi-admin-realm-restapi-extension-authentication-flow-mode=replace` |
| per request | `mode` query parameter | `POST .../authentication-flow/import?mode=replace` |

The query parameter wins over the server default, and the server default is
`versioned` when nothing is configured. An unknown value is rejected (`400` for the
query parameter, startup failure for the server config).

### Request attributes

The JSON body is an `AuthenticationFlowPayload` with the following fields. The
flow/config aliases referenced in the binding fields are matched against the flows and
configs defined in the same payload, so a binding always points at a flow imported in
the same request. In versioned mode the server prefixes those aliases with the payload
hash; in replace mode they are used as-is.

| Attribute | Required | Scope | Description |
| --- | --- | --- | --- |
| `authenticationFlows` | yes | realm | The list of authentication flows to create (Keycloak `AuthenticationFlowRepresentation`, including their executions). |
| `authenticatorConfig` | yes | realm | The list of authenticator configs to create (Keycloak `AuthenticatorConfigRepresentation`), referenced by alias from the flow executions. |
| `browserFlowBinding` | no | realm | Alias of the flow to set as the realm's **browser** flow. |
| `idpFlowBindings` | no | identity provider | List binding flows to identity providers (see below). |
| `clientFlowBinding` | no | client | Binds flow overrides to a single client (see below). |

`idpFlowBindings[]` — each entry binds flows to one identity provider:

| Attribute | Scope | Description |
| --- | --- | --- |
| `alias` | identity provider | Alias of the target identity provider. |
| `firstLoginFlowBinding` | identity provider | Alias of the flow to set as the IdP's **first broker login** flow. |
| `postLoginFlowBinding` | identity provider | Alias of the flow to set as the IdP's **post broker login** flow. |

`clientFlowBinding` — flow binding overrides for a single client:

| Attribute | Scope | Description |
| --- | --- | --- |
| `clientId` | client | Client ID of the target client. |
| `browserFlowBinding` | client | Alias of the flow to set as the client's **browser** flow override. |
| `directFlowBinding` | client | Alias of the flow to set as the client's **direct grant** flow override. |

## Export

```
GET /admin/realms/{realm}/authentication-flow/export[?alias=<top-level flow>&alias=...]
```

Returns top-level flows, every subflow they reach, and the authenticator configs those
flows reference. The body is an `AuthenticationFlowPayload`, so you can commit it to a
repository and post it back to `import` as-is. Ids are dropped and bindings are not
exported. With no `alias`, it exports every top-level flow that is not built in. A built-in
flow can be exported by naming it, for example as a starting point for a copy. An unknown
alias returns `404`, and a subflow alias returns `400` (export its top-level flow
instead). The caller needs `view-realm`.

## Build

Requires **JDK 21** and **Maven**.

```bash
mvn clean package
```

This produces `target/keycloak-atomic-auth-flows.jar`. Deploy it to Keycloak by
copying it into the server's `providers/` directory and running `kc.sh build` (or
mounting it into `/opt/keycloak/providers/` for the container image).

## Tests

The integration tests run against a real Keycloak instance using
[Testcontainers](https://testcontainers.com/), so a running **Docker** daemon is
required. The test (`AuthenticationFlowsResourceApiTest`) starts a Keycloak container
with the freshly built extension loaded and drives the import endpoint over HTTP.

```bash
mvn test
```

To run a single test class:

```bash
mvn -Dtest=AuthenticationFlowsResourceApiTest test
```

## License

[Apache License, Version 2.0,](https://www.apache.org/licenses/LICENSE-2.0.txt).

All documentation, source code and other files in this repository are Copyright 2026 Phase Two, Inc.
