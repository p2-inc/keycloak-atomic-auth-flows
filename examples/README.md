# Examples — config-as-code for authentication flows

This directory is a worked example of driving the `authentication-flow/import`
endpoint (provided by this extension) from a small config-as-code toolchain. It
mirrors the layout of a real deployment: a per-realm builder that describes the
flows in Ruby, a generated import payload, a generated human-readable rendering,
a validator, and a script that posts the payload to Keycloak.

```
examples/
├── demo-realm/                  # one realm's flow config
│   ├── auth_flows_builder.rb    # SOURCE OF TRUTH — hand-edited
│   ├── auth_flows_tree.json     # generated — the import payload
│   └── auth_flows_tree.txt       # generated — human-readable rendering
├── docker/
│   └── demo-realm.json          # minimal realm imported by docker-compose
└── scripts/
    ├── auth_flow_dsl.rb          # the DSL the builder is written against
    ├── auth_flows_types.rb       # value objects → import-payload JSON
    ├── build_auth_flows.rb       # builder: renders the .json and .txt
    ├── auth_flow_validator.rb    # static checks over the generated .json
    ├── update_auth_flows.rb      # posts the .json to the import endpoint
    ├── core.rb / constants.rb    # HTTP + config plumbing
```

## The workflow

The model is: **you edit the builder, everything else is generated or derived.**

1. **Describe** the flows in `demo-realm/auth_flows_builder.rb`. It's a small
   Ruby program written against the DSL in `scripts/auth_flow_dsl.rb`
   (`flow`, `subflow`, `authenticator`, `config`, `idp_binding`,
   `auth_flows_tree`, plus shortcuts for the stock Keycloak authenticators). It
   returns an `auth_flows_tree(...)`.

2. **Build** the artifacts:

   ```bash
   ruby examples/scripts/build_auth_flows.rb
   ```

   This renders, next to the builder:
   - `auth_flows_tree.json` — the exact payload the import endpoint consumes.
   - `auth_flows_tree.txt` — a tree rendering of the same flows, showing
     entrypoints, requirements and subflow nesting. Nothing reads it back; it
     exists to make review and diffs legible. Commit both.

3. **Validate** the generated payload before shipping it:

   ```bash
   ruby examples/scripts/auth_flow_validator.rb
   ```

   The endpoint accepts a structurally-valid payload without checking that every
   referenced subflow/config/IdP resolves, so the validator catches dangling
   references, orphaned flows, inconsistent executions, and authenticator ids
   that exceed Keycloak's 36-char column — mistakes that would otherwise only
   surface at runtime.

4. **Apply** the flows to a running Keycloak:

   ```bash
   ruby examples/scripts/update_auth_flows.rb
   ```

   This POSTs `auth_flows_tree.json` to
   `/admin/realms/demo/authentication-flow/import`. The endpoint imports all
   flows, configs and bindings in one transaction and prefixes every flow alias
   with a hash of the flows+configs. Re-posting the identical tree returns
   **409** (already imported) instead of duplicating anything, so this is safe
   to run repeatedly. Pass `--force` to re-apply the bindings over an
   already-imported tree.

## Running it against the bundled Keycloak

From the repo root, start a Keycloak that has the extension loaded and a minimal
`demo` realm imported:

```bash
docker compose up --build      # http://localhost:8080  (admin / admin)
```

Then apply the demo flows:

```bash
ruby examples/scripts/update_auth_flows.rb
```

Open the admin console → realm **demo** → *Authentication*, and you'll see the
imported `demo-browser` and `demo-first-broker-login` flows (alias-prefixed with
the import hash), with `demo-browser` bound as the realm browser flow and
`demo-first-broker-login` bound to the `demo-oidc` identity provider.

### Configuration

The scripts default to the bundled Keycloak; override via environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `KC_HOST` | `http://localhost:8080` | Keycloak base URL |
| `KC_REALM` | `demo` | realm to import flows into |
| `KC_AUTH_REALM` | `master` | realm the admin authenticates against |
| `KC_CLIENT_ID` | `admin-cli` | client used for the token exchange |
| `KC_ADMIN` / `KC_ADMIN_PASSWORD` | `admin` / `admin` | admin credentials |

## Adapting it to your own realm

Copy `demo-realm/` to `examples/<your-realm>/`, edit its `auth_flows_builder.rb`,
and pass the directory to each script:

```bash
ruby examples/scripts/build_auth_flows.rb   examples/your-realm
ruby examples/scripts/auth_flow_validator.rb examples/your-realm
KC_REALM=your-realm ruby examples/scripts/update_auth_flows.rb examples/your-realm
```

Flows are **append-only** in spirit: because the endpoint keys imported flows by
a hash of their contents, "changing" a flow means importing a new version
(new content → new hash → new aliases) and re-binding to it, rather than
mutating flows already in Keycloak.
