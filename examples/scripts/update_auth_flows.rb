#!/usr/bin/env ruby
#
# Update a realm's authentication flows through the atomic import endpoint.
#
# Posts a realm's generated auth_flows_tree.json to
#   POST /admin/realms/{realm}/authentication-flow/import[?force=true]
# which imports every flow, config and binding in one transactional request.
#
# The endpoint hashes the flows + configs and prefixes each imported flow alias
# with that hash, so re-posting an identical tree is detected and rejected with
# HTTP 409 rather than silently duplicating flows — which makes this safe to run
# repeatedly from CI. Pass --force to re-apply the bindings over an already
# imported tree instead of erroring on the 409.
#
# Usage:
#   ruby update_auth_flows.rb [realm-dir] [--force]
#     realm-dir  directory containing auth_flows_tree.json (default ../demo-realm)
#
# Connection + credentials come from the environment (see constants.rb); the
# defaults target the Keycloak started by this repo's docker-compose.
require 'json'
require File.join(File.expand_path(File.dirname(__FILE__)), "core.rb")

force = ARGV.delete("--force") ? true : false
realm_dir = ARGV[0] || DEFAULT_REALM_DIR

tree_file = File.join(realm_dir, "auth_flows_tree.json")
unless File.exist?(tree_file)
    warn "✗ No auth_flows_tree.json found in #{realm_dir}"
    warn "  Run build_auth_flows.rb first to generate it."
    exit 1
end

tree = JSON.parse(File.read(tree_file))
url = URI("#{BASE_URL}/#{REALM}/authentication-flow/import#{force ? '?force=true' : ''}")

puts "Importing auth flows"
puts "  realm:  #{REALM}"
puts "  source: #{tree_file}"
puts "  target: #{url}"
puts "  force:  #{force}"

response = http_post(url, tree.to_json)
puts
puts "→ #{response.code} #{response.message}"
puts response.body unless response.body.nil? || response.body.empty?

case response.code.to_i
when 200
    puts "\n✓ Flows imported."
    exit 0
when 409
    puts "\n• Flows with this exact configuration are already imported (409)."
    puts "  Re-run with --force to re-apply the bindings, or change the flows to import a new version."
    exit 0
else
    warn "\n✗ Import failed."
    exit 1
end
