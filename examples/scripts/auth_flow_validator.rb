#!/usr/bin/env ruby
#
# Flow validator.
#
# Static checks over a realm's generated auth_flows_tree.json, run before it is
# posted to Keycloak. Keycloak's import endpoint accepts a structurally-valid
# payload without cross-checking that every referenced flow/config/IdP actually
# resolves, so a dangling reference or an over-long authenticator id only
# surfaces at runtime (or as an opaque database error). These checks catch the
# common mistakes up front.
#
# Usage:
#   ruby auth_flow_validator.rb [realm-dir]      # defaults to ../demo-realm
#   exits non-zero if any error is found
require 'json'
require 'set'
require File.join(File.expand_path(File.dirname(__FILE__)), "constants.rb")

class AuthFlowValidator
    # Keycloak stores the authenticator provider id in
    # AUTHENTICATION_EXECUTION.AUTHENTICATOR, a VARCHAR(36). A longer id imports
    # fine but blows up at flow-execution time with a Postgres "value too long
    # for type character varying(36)" error, so we catch it here.
    AUTHENTICATOR_ID_MAX_LENGTH = 36

    # Built-in flow aliases that need not be defined in the tree.
    BUILTIN_FLOW_ALIASES = ['browser', ''].freeze

    def initialize(realm_dir)
        @realm_dir = realm_dir
        @realm = File.basename(realm_dir)
    end

    def validate
        errors = []
        tree_file = File.join(@realm_dir, "auth_flows_tree.json")

        unless File.exist?(tree_file)
            puts "  ✗ No auth_flows_tree.json found in #{@realm_dir}"
            return ["Missing auth_flows_tree.json in #{@realm_dir}"]
        end

        begin
            tree = JSON.parse(File.read(tree_file))
        rescue JSON::ParserError => e
            puts "  ✗ Invalid JSON in auth_flows_tree.json: #{e.message}"
            return ["Invalid JSON in auth_flows_tree.json: #{e.message}"]
        end

        flows   = tree['authenticationFlows'] || []
        configs = tree['authenticatorConfig'] || []
        puts "  ✓ Loaded #{flows.length} flows and #{configs.length} configs from #{File.basename(tree_file)}"

        errors.concat(validate_flow_references(flows, tree['browserFlowBinding']))
        errors.concat(validate_config_references(flows, configs))
        errors.concat(validate_idp_flow_bindings(flows, tree['idpFlowBindings']))
        errors.concat(validate_orphaned_flows(tree, flows))
        errors.concat(validate_execution_consistency(flows))
        errors.concat(validate_authenticator_id_length(flows))

        errors
    end

    # A set of every alias that a binding or subflow reference may legitimately
    # point at: the flows defined here plus Keycloak's built-ins.
    def available_flows(flows)
        set = Set.new(BUILTIN_FLOW_ALIASES)
        flows.each { |f| set.add(f['alias']) }
        set
    end

    def validate_flow_references(flows, browser_binding)
        errors = []
        puts "    → Validating flow references..."
        available = available_flows(flows)

        flows.each do |flow|
            (flow['authenticationExecutions'] || []).each do |exec|
                next unless exec['authenticatorFlow'] && exec['flowAlias']
                referenced = exec['flowAlias']
                unless available.include?(referenced)
                    errors << "Flow '#{flow['alias']}' references missing subflow '#{referenced}'"
                end
            end
        end

        if browser_binding && !available.include?(browser_binding)
            errors << "browserFlowBinding references missing flow '#{browser_binding}'"
        end

        report(errors, "flow references")
    end

    def validate_config_references(flows, configs)
        errors = []
        puts "    → Validating config references..."
        available = Set.new(configs.map { |c| c['alias'] })

        flows.each do |flow|
            (flow['authenticationExecutions'] || []).each do |exec|
                referenced = exec['authenticatorConfig']
                next unless referenced
                unless available.include?(referenced)
                    errors << "Flow '#{flow['alias']}' references missing config '#{referenced}'"
                end
            end
        end

        report(errors, "config references")
    end

    def validate_idp_flow_bindings(flows, idp_bindings)
        errors = []
        return errors unless idp_bindings
        puts "    → Validating identity provider flow bindings..."
        available = available_flows(flows)

        idp_bindings.each do |binding|
            alias_name = binding['alias']
            ['firstLoginFlowBinding', 'postLoginFlowBinding'].each do |field|
                flow_alias = binding[field]
                next unless flow_alias
                unless available.include?(flow_alias)
                    errors << "Identity provider '#{alias_name}' #{field} references missing flow '#{flow_alias}'"
                end
            end
        end

        report(errors, "identity provider flow bindings")
    end

    # Flags top-level flows that nothing references — neither a binding nor
    # another flow's subflow execution. Usually a leftover or a typo'd binding.
    def validate_orphaned_flows(tree, flows)
        errors = []
        puts "    → Validating for orphaned flows..."

        all_flows = Set.new(flows.map { |f| f['alias'] })
        referenced = Set.new

        referenced.add(tree['browserFlowBinding']) if tree['browserFlowBinding']
        (tree['idpFlowBindings'] || []).each do |binding|
            referenced.add(binding['firstLoginFlowBinding']) if binding['firstLoginFlowBinding']
            referenced.add(binding['postLoginFlowBinding']) if binding['postLoginFlowBinding']
        end
        flows.each do |flow|
            (flow['authenticationExecutions'] || []).each do |exec|
                referenced.add(exec['flowAlias']) if exec['authenticatorFlow'] && exec['flowAlias']
            end
        end

        (all_flows - referenced).each do |orphan|
            errors << "Flow '#{orphan}' is orphaned (not referenced by any binding or subflow execution)"
        end

        report(errors, "orphaned flows")
    end

    # An execution is either a subflow (authenticatorFlow true → flowAlias, no
    # authenticator) or a leaf (authenticatorFlow false → authenticator, no
    # flowAlias). Anything else is a mistake the endpoint won't catch.
    def validate_execution_consistency(flows)
        errors = []
        puts "    → Validating execution authenticatorFlow consistency..."

        flows.each do |flow|
            (flow['authenticationExecutions'] || []).each_with_index do |exec, i|
                is_flow = exec['authenticatorFlow']
                has_flow_alias = !exec['flowAlias'].nil?
                has_authenticator = !exec['authenticator'].nil?

                if is_flow == true
                    errors << "Flow '#{flow['alias']}' execution[#{i}]: authenticatorFlow is true but missing flowAlias" unless has_flow_alias
                    errors << "Flow '#{flow['alias']}' execution[#{i}]: authenticatorFlow is true but also has authenticator '#{exec['authenticator']}'" if has_authenticator
                elsif is_flow == false
                    errors << "Flow '#{flow['alias']}' execution[#{i}]: authenticatorFlow is false but missing authenticator" unless has_authenticator
                    errors << "Flow '#{flow['alias']}' execution[#{i}]: authenticatorFlow is false but also has flowAlias '#{exec['flowAlias']}'" if has_flow_alias
                end
            end
        end

        report(errors, "execution consistency")
    end

    def validate_authenticator_id_length(flows)
        errors = []
        puts "    → Validating authenticator provider id lengths (<= #{AUTHENTICATOR_ID_MAX_LENGTH})..."

        flows.each do |flow|
            (flow['authenticationExecutions'] || []).each_with_index do |exec, i|
                id = exec['authenticator']
                next if id.nil?
                if id.length > AUTHENTICATOR_ID_MAX_LENGTH
                    errors << "Flow '#{flow['alias']}' execution[#{i}]: authenticator id '#{id}' is #{id.length} chars, exceeds Keycloak's #{AUTHENTICATOR_ID_MAX_LENGTH}-char column"
                end
            end
        end

        report(errors, "authenticator id lengths")
    end

    def report(errors, what)
        if errors.empty?
            puts "    ✓ #{what}: OK"
        else
            errors.each { |e| puts "      ✗ #{e}" }
            puts "    ✗ #{what}: #{errors.length} error(s)"
        end
        errors
    end
end

if __FILE__ == $0
    realm_dir = ARGV[0] || DEFAULT_REALM_DIR
    puts "Validating auth flows in #{realm_dir}"
    errors = AuthFlowValidator.new(realm_dir).validate
    puts
    if errors.empty?
        puts "✓ Validation passed"
        exit 0
    else
        puts "✗ Validation failed with #{errors.length} error(s)"
        exit 1
    end
end
