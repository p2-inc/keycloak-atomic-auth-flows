# =============================================================================
# Demo realm auth flows.
#
# This file is the human-authored source of truth for the demo realm's
# authentication flows. It's a small Ruby program evaluated by
# ../scripts/build_auth_flows.rb against the DSL in ../scripts/auth_flow_dsl.rb,
# and it must return an `auth_flows_tree(...)`.
#
# Running the builder renders two files next to this one:
#   auth_flows_tree.json  — the import payload (posted to the extension endpoint)
#   auth_flows_tree.txt    — a human-readable rendering of the tree
#
# Everything here uses stock Keycloak authenticators, so the imported flows work
# against a vanilla Keycloak with only this extension installed. The two flows
# below rebuild Keycloak's own "browser" and "first broker login" flows so the
# shapes are familiar — but as new, independently-bindable copies.
# =============================================================================

# -----------------------------------------------------------------------------
# Authenticator configs
# -----------------------------------------------------------------------------

REVIEW_PROFILE_CONFIG = "demo-review-profile"

configs = [
    # Only prompt the IdP user to review their profile when a mapped field is
    # missing (rather than on every first login).
    config(REVIEW_PROFILE_CONFIG, { "update.profile.on.first.login" => "missing" })
]

# -----------------------------------------------------------------------------
# Browser login flow (bound as the realm browser flow)
#
#   demo-browser
#   ├── auth-cookie                       [ALTERNATIVE]  reuse existing session
#   ├── identity-provider-redirector      [ALTERNATIVE]  follow kc_idp_hint
#   └── demo-browser-forms                [ALTERNATIVE]  (subflow)
#       ├── auth-username-password-form   [REQUIRED]
#       └── demo-browser-conditional-otp  [CONDITIONAL]  (subflow)
#           ├── conditional-user-configured [REQUIRED]   only if OTP set up
#           └── auth-otp-form               [REQUIRED]
# -----------------------------------------------------------------------------

browser_conditional_otp = flow("demo-browser-conditional-otp",
    description: "Ask for an OTP only when the user has one configured",
    executions: [
        conditional_user_configured(priority: 10),
        otp_form(priority: 20)
    ]
)

browser_forms = flow("demo-browser-forms",
    description: "Username + password, then conditional OTP",
    executions: [
        username_password_form(priority: 10),
        subflow("demo-browser-conditional-otp", requirement: "CONDITIONAL", priority: 20)
    ]
)

browser = flow("demo-browser",
    description: "Demo browser based authentication",
    top_level: true,
    executions: [
        auth_cookie(priority: 10),
        idp_redirector(priority: 25),
        subflow("demo-browser-forms", requirement: "ALTERNATIVE", priority: 30)
    ]
)

# -----------------------------------------------------------------------------
# First broker login flow (bound to the demo-oidc identity provider)
#
#   demo-first-broker-login
#   ├── idp-review-profile                    [REQUIRED]  (config)
#   └── demo-first-broker-login-user-or-link  [REQUIRED]  (subflow)
#       ├── idp-create-user-if-unique         [ALTERNATIVE]  new user
#       └── demo-first-broker-login-link       [ALTERNATIVE]  (subflow) existing
#           ├── idp-confirm-link              [REQUIRED]
#           └── idp-email-verification        [REQUIRED]
# -----------------------------------------------------------------------------

first_broker_link = flow("demo-first-broker-login-link",
    description: "Link a brokered identity to an existing account",
    executions: [
        idp_confirm_link(priority: 10),
        idp_email_verification(priority: 20)
    ]
)

first_broker_user_or_link = flow("demo-first-broker-login-user-or-link",
    description: "Create a new user for a first-time brokered login, or link to an existing one",
    executions: [
        idp_create_user_if_unique(priority: 10),
        subflow("demo-first-broker-login-link", requirement: "ALTERNATIVE", priority: 20)
    ]
)

first_broker_login = flow("demo-first-broker-login",
    description: "Demo first broker login for the demo-oidc identity provider",
    top_level: true,
    executions: [
        idp_review_profile(priority: 10, config: REVIEW_PROFILE_CONFIG),
        subflow("demo-first-broker-login-user-or-link", requirement: "REQUIRED", priority: 20)
    ]
)

# -----------------------------------------------------------------------------
# Tree
# -----------------------------------------------------------------------------

auth_flows_tree(
    flows: [
        browser, browser_forms, browser_conditional_otp,
        first_broker_login, first_broker_user_or_link, first_broker_link
    ],
    configs: configs,
    flow_binding: "demo-browser",
    idp_bindings: [
        idp_binding("demo-oidc", first_login: "demo-first-broker-login")
    ]
)
