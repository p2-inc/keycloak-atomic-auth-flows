package io.phasetwo.keycloak;

import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.internal.ResteasyClientBuilderImpl;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;
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
              "quay.io/phasetwo/keycloak-crdb:%s", System.getProperty("keycloak-version", "26.5.6"));
  public static final String REALM = "master";
  public static final String ADMIN_CLI = "admin-cli";

  public static final ObjectMapper objectMapper = new ObjectMapper();

  public static Keycloak keycloak;
  public static ResteasyClient resteasyClient;

  public static final KeycloakContainer container =
      new KeycloakContainer(KEYCLOAK_IMAGE)
          .withContextPath("/auth")
          .withReuse(true)
          .withExposedPorts(8787, 9000, 8080)
          .withAccessToHost(true)
          // packages everything under target/classes (including META-INF/services) into a
          // provider jar so the AuthenticationFlowResourceProvider is registered at startup.
          .withProviderClassesFrom("target/classes");
          // resolves any extra runtime libs the extension needs (listed in `deps`) from the
          // Maven reactor and drops them into the server's providers/ before `kc.sh build` runs.
//          .withProviderLibsFrom(getDeps());

  /**
   * Coordinates ({@code groupId:artifactId}) of runtime dependencies the extension needs inside the
   * server but that are not part of the base image. Each must be declared in {@code pom.xml} (so its
   * version is resolvable); resolution is non-transitive, so list every artifact explicitly.
   */
  static final String[] deps = {};

  public static List<File> getDeps() {
    List<File> dependencies = new ArrayList<>();
    for (String dep : deps) {
      dependencies.addAll(getDep(dep));
    }
    return dependencies;
  }

  static List<File> getDep(String pkg) {
    return Maven.resolver()
        .loadPomFromFile("./pom.xml")
        .resolve(pkg)
        .withoutTransitivity()
        .asList(File.class);
  }

  @BeforeAll
  public static void beforeAll() {
    container.start();
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
