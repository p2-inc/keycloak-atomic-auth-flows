# keycloak-atomic-auth-flows

Config as code solution to safely update Keycloak authentication flows.

This extension registers an admin realm REST resource (`authentication-flow`) that
imports a complete set of authenticator configs, authentication flows and their
bindings (browser, identity provider first/post login, and per-client browser/direct
grant overrides) in a single atomic, transactional request. The payload is hashed and
the flow aliases are prefixed with that hash, so re-importing an identical
configuration is detected and rejected (HTTP `409`) instead of silently duplicating
flows — making the import safe to run repeatedly from a CI/CD pipeline.

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
POST /admin/realms/{realm}/authentication-flow/import[?force=true]
Content-Type: application/json
```

The caller must have the `manage-realm` permission. See `src/test/resources/json/`
for raw example payloads, or [`examples/`](examples/) for a config-as-code
toolchain that generates and applies them.

The `force` query parameter is optional. When omitted, an import whose flows already
exist (same config hash) is rejected with `409 Conflict`. Passing `force=true` instead
re-applies the flow bindings over the already-imported flows. Any other value (or its
absence) is treated as `false`.

### Request attributes

The JSON body is an `AuthenticationFlowPayload` with the following fields. The
flow/config aliases referenced in the binding fields are matched against the flows and
configs defined in the same payload — the server automatically prefixes them with the
payload hash, so a binding always points at a flow imported in the same request.

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
