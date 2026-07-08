# Shared configuration for the example scripts.
#
# Everything is overridable by environment variable so the same scripts work
# against the bundled Docker Keycloak (the defaults) or any other server.

# --- Keycloak connection -----------------------------------------------------
HOST     = ENV["KC_HOST"] || "http://localhost:8080"
BASE_URL = "#{HOST}/admin/realms"

# Realm the flows are imported into.
REALM = ENV["KC_REALM"] || "demo"

# Where admin credentials authenticate. On a stock Keycloak the bootstrap admin
# lives in `master` and authenticates through the public `admin-cli` client
# using a direct-access-grant (password) exchange.
AUTH_REALM = ENV["KC_AUTH_REALM"]     || "master"
CLIENT_ID  = ENV["KC_CLIENT_ID"]      || "admin-cli"
USERNAME   = ENV["KC_ADMIN"]          || "admin"
PASSWORD   = ENV["KC_ADMIN_PASSWORD"] || "admin"

# --- Repo layout -------------------------------------------------------------
SCRIPTS_DIR  = File.expand_path(File.dirname(__FILE__))
EXAMPLES_DIR = File.expand_path(File.join(SCRIPTS_DIR, ".."))

# Default realm directory the tooling operates on. Every script also accepts a
# directory as its first argument so you can point them at another realm.
DEFAULT_REALM_DIR = File.join(EXAMPLES_DIR, "demo-realm")
