package io.phasetwo.keycloak.rest;

import com.google.auto.service.AutoService;
import io.phasetwo.keycloak.model.ImportMode;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

@Slf4j
@AutoService(AdminRealmResourceProviderFactory.class)
public class AuthenticationFlowResourceProvider
    implements AdminRealmResourceProviderFactory, AdminRealmResourceProvider {

  public static final String PROVIDER_ID = "authentication-flow";

  /**
   * Server-wide config key selecting the default {@link ImportMode}. Set with
   * {@code --spi-admin-realm-restapi-extension-authentication-flow-mode=replace} or the env var
   * {@code KC_SPI_ADMIN_REALM_RESTAPI_EXTENSION_AUTHENTICATION_FLOW_MODE=replace}. A request can
   * override it with the {@code mode} query parameter.
   */
  public static final String CONFIG_MODE = "mode";

  private ImportMode defaultMode = ImportMode.VERSIONED;

  @Override
  public AdminRealmResourceProvider create(KeycloakSession session) {
    return this;
  }

  @Override
  public void init(Config.Scope config) {
    String configured = config.get(CONFIG_MODE);
    try {
      defaultMode = ImportMode.parse(configured, ImportMode.VERSIONED);
    } catch (IllegalArgumentException e) {
      throw new IllegalStateException(
          "Invalid value for spi-admin-realm-restapi-extension-authentication-flow-mode: "
              + e.getMessage(),
          e);
    }
    log.info("authentication-flow import default mode: {}", defaultMode);
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  public ImportMode getDefaultMode() {
    return defaultMode;
  }

  @Override
  public Object getResource(
      KeycloakSession session,
      RealmModel realm,
      AdminPermissionEvaluator auth,
      AdminEventBuilder adminEvent) {
    return new AuthenticationFlowResource(session, realm, auth, defaultMode);
  }
}
