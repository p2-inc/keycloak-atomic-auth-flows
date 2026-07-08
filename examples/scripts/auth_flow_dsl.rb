# A small Ruby DSL for describing Keycloak authentication flows.
#
# A realm's `auth_flows_builder.rb` is `eval`'d in a context that has these
# helpers in scope (see build_auth_flows.rb) and is expected to return an
# `AuthFlowsTree`. The builder then renders that tree to:
#   * auth_flows_tree.json  — the import payload posted to the extension endpoint
#   * auth_flows_tree.txt    — a human-readable rendering of the same tree
#
# The primitives (`authenticator`, `subflow`, `flow`, `config`, `idp_binding`,
# `auth_flows_tree`) are all you strictly need. The named shortcuts below just
# make a builder read closer to how the Keycloak admin console presents the
# built-in flows. Everything here uses stock Keycloak authenticator provider
# ids, so the resulting tree imports against a vanilla Keycloak with only this
# extension installed — no custom SPIs required.
require 'json'
require File.join(File.expand_path(File.dirname(__FILE__)), "auth_flows_types.rb")

include AuthFlowsTypes

# =============================================================================
# Primitives
# =============================================================================

# A leaf execution that runs a single authenticator.
def authenticator(provider_id, requirement:, priority:, config: nil, user_setup_allowed: false)
    AuthenticationExecution.new(
        authenticator_flow: false,
        authenticator: provider_id,
        authenticator_config: config,
        requirement: requirement,
        priority: priority,
        user_setup_allowed: user_setup_allowed
    )
end

# An execution that nests a subflow, referenced by the subflow's alias.
def subflow(flow_alias, requirement:, priority:, user_setup_allowed: false)
    AuthenticationExecution.new(
        authenticator_flow: true,
        flow_alias: flow_alias,
        requirement: requirement,
        priority: priority,
        user_setup_allowed: user_setup_allowed
    )
end

# A flow (top-level or sub). `basic-flow` is the ordinary Keycloak flow type.
def flow(alias_name, description: nil, top_level: false, executions: [])
    AuthenticationFlow.new(
        alias_name: alias_name,
        description: description,
        provider_id: 'basic-flow',
        top_level: top_level,
        built_in: false,
        authentication_executions: executions
    )
end

# A named authenticator config. `settings` is a flat string-keyed hash.
def config(alias_name, settings = nil)
    AuthenticatorConfig.new(alias_name: alias_name, config: settings)
end

# Binds flows to one identity provider by alias.
def idp_binding(alias_name, first_login: nil, post_login: nil)
    IdpFlowBinding.new(
        alias_name: alias_name,
        first_login_flow_binding: first_login,
        post_login_flow_binding: post_login
    )
end

# Assembles the tree the builder must return. `flows` may contain nested arrays
# (flow builders often return several flows at once) — they're flattened.
def auth_flows_tree(flows: [], configs: [], flow_binding: nil, idp_bindings: [])
    AuthFlowsTree.new(
        authentication_flows: flows.flatten,
        authenticator_configs: configs.flatten,
        flow_binding: flow_binding,
        idp_flow_bindings: idp_bindings
    )
end

# =============================================================================
# Stock Keycloak authenticator shortcuts
# =============================================================================

# Reuse an existing SSO cookie session ("Cookie" in the console).
def auth_cookie(priority: 10, requirement: "ALTERNATIVE")
    authenticator("auth-cookie", requirement: requirement, priority: priority)
end

# Forward to an identity provider when kc_idp_hint is present ("Identity
# Provider Redirector").
def idp_redirector(priority: 25, requirement: "ALTERNATIVE")
    authenticator("identity-provider-redirector", requirement: requirement, priority: priority)
end

# Combined username + password form ("Username Password Form").
def username_password_form(priority: 10, requirement: "REQUIRED")
    authenticator("auth-username-password-form", requirement: requirement, priority: priority)
end

# Only run the enclosing branch if the user has the credential configured
# ("Condition - user configured"). Pairs with a CONDITIONAL subflow.
def conditional_user_configured(priority: 10, requirement: "REQUIRED")
    authenticator("conditional-user-configured", requirement: requirement, priority: priority)
end

# One-time-password form ("OTP Form").
def otp_form(priority: 20, requirement: "REQUIRED")
    authenticator("auth-otp-form", requirement: requirement, priority: priority)
end

# --- Identity-provider (first broker login) authenticators ------------------

# Prompt the user to review the profile mapped from the IdP ("Review Profile").
def idp_review_profile(priority: 10, requirement: "REQUIRED", config: nil)
    authenticator("idp-review-profile", requirement: requirement, priority: priority, config: config)
end

# Create a local user if the brokered identity is new ("Create User If Unique").
def idp_create_user_if_unique(priority: 10, requirement: "ALTERNATIVE", config: nil)
    authenticator("idp-create-user-if-unique", requirement: requirement, priority: priority, config: config)
end

# Confirm linking the brokered identity to an existing account ("Confirm link
# existing account").
def idp_confirm_link(priority: 10, requirement: "REQUIRED")
    authenticator("idp-confirm-link", requirement: requirement, priority: priority)
end

# Verify ownership of the existing account by email ("Verify existing account
# by Email").
def idp_email_verification(priority: 20, requirement: "REQUIRED")
    authenticator("idp-email-verification", requirement: requirement, priority: priority)
end
