# Minimal Keycloak admin HTTP helpers for the example scripts.
#
# Acquires an admin access token via a direct-access-grant (password) exchange
# against the configured auth realm's `admin-cli` client — the default way to
# authenticate as the bootstrap admin on a stock Keycloak — and exposes thin
# GET/POST wrappers that attach it. Override any connection detail through the
# environment variables documented in constants.rb.
require 'net/http'
require 'uri'
require 'json'
require File.join(File.expand_path(File.dirname(__FILE__)), "constants.rb")

def get_access_token
    token_url = URI("#{HOST}/realms/#{AUTH_REALM}/protocol/openid-connect/token")
    http = Net::HTTP.new(token_url.host, token_url.port)
    http.use_ssl = (token_url.scheme == "https")

    request = Net::HTTP::Post.new(token_url.request_uri)
    request.set_form_data({
        'client_id'  => CLIENT_ID,
        'grant_type' => 'password',
        'username'   => USERNAME,
        'password'   => PASSWORD
    })

    response = http.request(request)
    unless response.is_a?(Net::HTTPSuccess)
        raise "Failed to obtain access token from #{token_url}: #{response.code} #{response.message} - #{response.body}"
    end
    JSON.parse(response.body)['access_token']
end

# Acquired once per run. Set ACCESS_TOKEN in the environment to reuse a token.
ACCESS_TOKEN = ENV['ACCESS_TOKEN'] || get_access_token

def http_send(request, url)
    http = Net::HTTP.new(url.host, url.port)
    http.use_ssl = (url.scheme == "https")
    request["Authorization"] = "Bearer #{ACCESS_TOKEN}"
    http.request(request)
end

def http_get(url)
    http_send(Net::HTTP::Get.new(url.request_uri), url)
end

def http_post(url, data_json)
    request = Net::HTTP::Post.new(url.request_uri)
    request['Content-Type'] = 'application/json'
    request.body = data_json
    http_send(request, url)
end
