package io.phasetwo.keycloak;

import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import java.util.concurrent.TimeUnit;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.internal.ResteasyClientBuilderImpl;
import org.junit.jupiter.api.BeforeAll;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.RealmRepresentation;

/**
 * Base class for integration tests. Starts a single Keycloak container (reused across all test
 * classes) with this project's extension loaded from {@code target/classes}, and exposes an admin
 * {@link Keycloak} client plus helpers for talking to the running server.
 *
 * <p>Requires a Docker daemon. The Keycloak image version can be overridden with
 * {@code -Dkeycloak-version=<tag>}; keep it aligned with the {@code keycloak.version} the extension
 * is compiled against to avoid internal-API drift.
 */
public abstract class AbstractTestBase {

  public static final String KEYCLOAK_IMAGE =
      String.format(
          "quay.io/keycloak/keycloak:%s", System.getProperty("keycloak-version", "26.6.2"));
  public static final String REALM = "master";
  public static final String ADMIN_CLI = "admin-cli";

  public static final ObjectMapper objectMapper = new ObjectMapper();

  public static Keycloak keycloak;
  public static ResteasyClient resteasyClient;

  public static final KeycloakContainer container =
      new KeycloakContainer(KEYCLOAK_IMAGE)
          .withContextPath("/auth")
          .withReuse(true)
          // packages everything under target/classes (including META-INF/services) into a
          // provider jar so the AuthenticationFlowResourceProvider is registered at startup.
          .withProviderClassesFrom("target/classes");

  static {
    container.start();
  }

  @BeforeAll
  public static void beforeAll() {
    resteasyClient =
        new ResteasyClientBuilderImpl()
            .disableTrustManager()
            .readTimeout(60, TimeUnit.SECONDS)
            .connectTimeout(10, TimeUnit.SECONDS)
            .build();
    keycloak =
        getKeycloak(REALM, ADMIN_CLI, container.getAdminUsername(), container.getAdminPassword());
  }

  public static Keycloak getKeycloak(String realm, String clientId, String user, String pass) {
    return Keycloak.getInstance(getAuthUrl(), realm, user, pass, clientId);
  }

  /** Base auth server URL, e.g. {@code http://localhost:32768/auth}. */
  public static String getAuthUrl() {
    return container.getAuthServerUrl();
  }

  /** Admin REST base for a realm, e.g. {@code http://localhost:32768/auth/admin/realms/master}. */
  public static String getAdminRealmUrl(String realm) {
    return getAuthUrl() + "/admin/realms/" + realm;
  }

  /** Current admin bearer token, for use with rest-assured {@code given().auth().oauth2(...)}. */
  public static String getAdminAccessToken() {
    return keycloak.tokenManager().getAccessTokenString();
  }

  /** Creates an enabled realm with the given name and returns its representation. */
  public static RealmRepresentation createRealm(String name) {
    RealmRepresentation rep = new RealmRepresentation();
    rep.setRealm(name);
    rep.setEnabled(true);
    keycloak.realms().create(rep);
    return keycloak.realm(name).toRepresentation();
  }
}
