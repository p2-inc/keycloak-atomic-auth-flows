#!/usr/bin/env ruby
#
# Update a realm's authentication flows through the atomic import endpoint.
#
# Posts a realm's generated auth_flows_tree.json to
#   POST /admin/realms/{realm}/authentication-flow/import[?force=true][&mode=replace][&dryRun=true]
# which imports every flow, config and binding in one transactional request.
#
# In the default *versioned* mode the endpoint hashes the flows + configs and
# prefixes each imported flow alias with that hash, so re-posting an identical
# tree is detected and rejected with HTTP 409 rather than silently duplicating
# flows, and every previous version stays in the realm for rollback. Pass
# --force to re-apply the bindings over an already imported tree instead of
# erroring on the 409.
#
# In *replace* mode (--mode replace) flows keep their plain aliases, an existing
# flow is overwritten in place, and re-posting an identical tree is a no-op.
# Use it when another config-as-code tool also manages the realm by flow name.
#
# --dry-run validates and runs the whole import, then rolls it back: a CI check
# that reports the same errors and result as the real import without writing.
#
# Usage:
#   ruby update_auth_flows.rb [realm-dir] [--force] [--mode versioned|replace] [--dry-run]
#     realm-dir  directory containing auth_flows_tree.json (default ../demo-realm)
#
# Connection + credentials come from the environment (see constants.rb); the
# defaults target the Keycloak started by this repo's docker-compose.
require 'json'
require File.join(File.expand_path(File.dirname(__FILE__)), "core.rb")

force = ARGV.delete("--force") ? true : false
dry_run = ARGV.delete("--dry-run") ? true : false
mode = nil
if (i = ARGV.index("--mode"))
    mode = ARGV[i + 1]
    ARGV.slice!(i, 2)
end
realm_dir = ARGV[0] || DEFAULT_REALM_DIR

tree_file = File.join(realm_dir, "auth_flows_tree.json")
unless File.exist?(tree_file)
    warn "✗ No auth_flows_tree.json found in #{realm_dir}"
    warn "  Run build_auth_flows.rb first to generate it."
    exit 1
end

tree = JSON.parse(File.read(tree_file))
params = []
params << "force=true" if force
params << "mode=#{mode}" if mode
params << "dryRun=true" if dry_run
url = URI("#{BASE_URL}/#{REALM}/authentication-flow/import#{params.empty? ? '' : '?' + params.join('&')}")

puts "Importing auth flows"
puts "  realm:  #{REALM}"
puts "  source: #{tree_file}"
puts "  target: #{url}"
puts "  force:  #{force}"
puts "  mode:   #{mode || 'server default'}"
puts "  dry run: #{dry_run}"

response = http_post(url, tree.to_json)
puts
puts "→ #{response.code} #{response.message}"
puts response.body unless response.body.nil? || response.body.empty?

case response.code.to_i
when 200
    result = response["X-Import-Result"]
    if response["X-Dry-Run"] == "true"
        puts "\n✓ Dry run passed#{result ? " (would be: #{result})" : ''}. Nothing was written."
    else
        puts "\n✓ Flows imported#{result ? " (#{result})" : ''}."
    end
    exit 0
when 409
    puts "\n• Flows with this exact configuration are already imported (409)."
    puts "  Re-run with --force to re-apply the bindings, or change the flows to import a new version."
    exit 0
else
    warn "\n✗ Import failed."
    exit 1
end
