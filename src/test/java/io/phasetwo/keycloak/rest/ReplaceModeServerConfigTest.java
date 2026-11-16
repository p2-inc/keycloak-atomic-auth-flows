package io.phasetwo.keycloak.rest;

import static io.phasetwo.keycloak.rest.AuthenticationFlowResource.RESULT_HEADER;
import static io.phasetwo.keycloak.rest.AuthenticationFlowResource.RESULT_UNCHANGED;
import static io.phasetwo.keycloak.rest.ReplaceModeTestSupport.BROWSER;
import static io.phasetwo.keycloak.rest.ReplaceModeTestSupport.V1;
import static io.phasetwo.keycloak.rest.ReplaceModeTestSupport.load;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.phasetwo.keycloak.AbstractTestBase;
import io.restassured.response.Response;
import java.io.IOException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.RealmRepresentation;

/**
 * Proves the server-wide default can be switched to replace mode with the documented env var, and
 * that the {@code mode} query parameter still overrides it. Needs its own container because the
 * env var is read once at startup.
 */
class ReplaceModeServerConfigTest {

  static final String MODE_ENV = "KC_SPI_ADMIN_REALM_RESTAPI_EXTENSION_AUTHENTICATION_FLOW_MODE";
  static final String REALM_NAME = "replace-default";

  static final KeycloakContainer container =
      new KeycloakContainer(AbstractTestBase.KEYCLOAK_IMAGE)
          .withContextPath("/auth")
          .withProviderClassesFrom("target/classes")
          .withEnv(MODE_ENV, "replace");

  static Keycloak keycloak;
  static String importUrl;

  @BeforeAll
  static void start() {
    container.start();
    keycloak =
        Keycloak.getInstance(
            container.getAuthServerUrl(),
            "master",
            container.getAdminUsername(),
            container.getAdminPassword(),
            "admin-cli");
    RealmRepresentation rep = new RealmRepresentation();
    rep.setRealm(REALM_NAME);
    rep.setEnabled(true);
    keycloak.realms().create(rep);
    importUrl =
        container.getAuthServerUrl()
            + "/admin/realms/"
            + REALM_NAME
            + "/authentication-flow/import";
  }

  @AfterAll
  static void stop() {
    container.stop();
  }

  @Test
  void envVar_makesReplaceTheDefault_andQueryParamStillOverrides() throws IOException {
    Response first = ReplaceModeTestSupport.post(keycloak, importUrl, load(V1), null);
    assertEquals(200, first.statusCode(), first.asString());
    assertEquals(BROWSER, first.jsonPath().getString("browserFlowBinding"));
    assertEquals(BROWSER, keycloak.realm(REALM_NAME).toRepresentation().getBrowserFlow());

    Response second = ReplaceModeTestSupport.post(keycloak, importUrl, load(V1), null);
    assertEquals(200, second.statusCode(), second.asString());
    assertEquals(RESULT_UNCHANGED, second.header(RESULT_HEADER));

    Response versioned = ReplaceModeTestSupport.post(keycloak, importUrl, load(V1), "versioned");
    assertEquals(200, versioned.statusCode(), versioned.asString());
    assertNotEquals(BROWSER, versioned.jsonPath().getString("browserFlowBinding"));
  }
}
