# Typed value objects for an auth-flow tree.
#
# These mirror the JSON payload consumed by the `authentication-flow/import`
# endpoint (see the repo README). `#to_h` on each type emits exactly the field
# names the endpoint expects, so the builder can serialize a tree straight to a
# valid import payload with no further massaging.
require 'json'

module AuthFlowsTypes
    # A single execution inside a flow.
    #
    # Set +authenticator_flow+ to false and provide +authenticator+ for a leaf
    # authenticator, or true and provide +flow_alias+ to nest a subflow.
    #
    # Note the payload carries both +authenticatorFlow+ and the (historically
    # misspelled) +autheticatorFlow+ key — Keycloak's representation has always
    # serialized both, so we reproduce them for compatibility.
    AuthenticationExecution = Struct.new(
        :authenticator_flow,
        :requirement,
        :priority,
        :user_setup_allowed,
        :authenticator,
        :authenticator_config,
        :flow_alias,
        keyword_init: true
    ) do
        def to_h
            result = {
                'authenticatorFlow' => authenticator_flow,
                'requirement' => requirement,
                'priority' => priority,
                'autheticatorFlow' => authenticator_flow,
                'userSetupAllowed' => user_setup_allowed || false
            }
            result['flowAlias'] = flow_alias if flow_alias
            result['authenticator'] = authenticator if authenticator
            result['authenticatorConfig'] = authenticator_config if authenticator_config
            result
        end

        def to_json(*args)
            to_h.to_json(*args)
        end
    end

    # An authentication flow: a named, ordered list of executions. Top-level
    # flows can be bound as a realm/IdP/client entrypoint; subflows are
    # referenced by a parent execution's +flow_alias+.
    AuthenticationFlow = Struct.new(
        :alias_name,
        :description,
        :provider_id,
        :top_level,
        :built_in,
        :authentication_executions,
        keyword_init: true
    ) do
        def to_h
            result = {
                'alias' => alias_name,
                'providerId' => provider_id || 'basic-flow',
                'topLevel' => top_level || false,
                'builtIn' => built_in || false,
                'authenticationExecutions' => (authentication_executions || []).map(&:to_h)
            }
            result['description'] = description if description
            result
        end

        def to_json(*args)
            to_h.to_json(*args)
        end
    end

    # A named authenticator config, referenced by alias from an execution's
    # +authenticator_config+.
    AuthenticatorConfig = Struct.new(
        :alias_name,
        :config,
        keyword_init: true
    ) do
        def to_h
            result = { 'alias' => alias_name }
            result['config'] = config if config && !config.empty?
            result
        end

        def to_json(*args)
            to_h.to_json(*args)
        end
    end

    # Binds flows to one identity provider (first-broker-login / post-login).
    IdpFlowBinding = Struct.new(
        :alias_name,
        :first_login_flow_binding,
        :post_login_flow_binding,
        keyword_init: true
    ) do
        def to_h
            result = { 'alias' => alias_name }
            result['firstLoginFlowBinding'] = first_login_flow_binding if first_login_flow_binding
            result['postLoginFlowBinding'] = post_login_flow_binding if post_login_flow_binding
            result
        end

        def to_json(*args)
            to_h.to_json(*args)
        end
    end

    # The root container. +#to_h+ produces the full import payload:
    # authenticationFlows + authenticatorConfig, plus the optional
    # browserFlowBinding / idpFlowBindings entrypoints.
    AuthFlowsTree = Struct.new(
        :authentication_flows,
        :authenticator_configs,
        :flow_binding,
        :idp_flow_bindings,
        keyword_init: true
    ) do
        def to_h
            result = {
                'authenticationFlows' => (authentication_flows || []).map(&:to_h),
                'authenticatorConfig' => (authenticator_configs || []).map(&:to_h)
            }
            result['browserFlowBinding'] = flow_binding if flow_binding
            result['idpFlowBindings'] = idp_flow_bindings.map(&:to_h) if idp_flow_bindings && !idp_flow_bindings.empty?
            result
        end

        def to_json(*args)
            to_h.to_json(*args)
        end

        def to_pretty_json
            JSON.pretty_generate(to_h)
        end
    end
end
